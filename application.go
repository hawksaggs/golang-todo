package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	Error  string           `json:"error"`
	Errors []*ErrorResponse `json:"errors"`
	Status int              `json:"status"`
	Data   interface{}      `json:"data"`
}

type Todo struct {
	ID          uuid.UUID `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Complete    bool      `json:"complete"`
	UserId      uuid.UUID `json:"userId"`
}

type TodoCreate struct {
	Title       string `json:"title" validate:"required"`
	Description string `json:"description" validate:"required"`
}

type TodoUpdate struct {
	Title       string `json:"title" validate:"required"`
	Description string `json:"description" validate:"required"`
	Complete    bool   `json:"complete"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
}

type SignInPayload struct {
	Username string `json:"username"  validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type SignUpPayload struct {
	Username  string `json:"username" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
}

type Claims struct {
	User UserResponse `json:"user"`
	jwt.RegisteredClaims
}

var jwtSignKey = []byte("sdsdf@q212")

var todos []*Todo
var users []*User

var validate = validator.New()

type ErrorResponse struct {
	Field string `json:"field"`
	Tag   string `json:"tag"`
	Value string `json:"value,omitempty"`
}

func ValidateStruct[T any](payload T) []*ErrorResponse {
	var errors []*ErrorResponse
	err := validate.Struct(payload)
	if err != nil {
		for _, err := range err.(validator.ValidationErrors) {
			var element ErrorResponse
			element.Field = err.StructNamespace()
			element.Tag = err.Tag()
			element.Value = err.Param()
			errors = append(errors, &element)
		}
	}

	return errors
}

func ListTodos(c *fiber.Ctx) error {
	user := c.Locals("user").(UserResponse)
	var userTodos []*Todo
	for _, todo := range todos {
		if todo.UserId == user.ID {
			userTodos = append(userTodos, todo)
		}
	}

	return c.JSON(Response{Status: http.StatusOK, Data: userTodos})
}

func AddTodo(c *fiber.Ctx) error {
	var payload TodoCreate
	if err := c.BodyParser(&payload); err != nil {
		return c.JSON(Response{Status: http.StatusBadRequest, Error: err.Error()})
	}
	errs := ValidateStruct(payload)
	if errs != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: http.StatusBadRequest, Errors: errs})
	}
	user := c.Locals("user").(UserResponse)
	var todo Todo
	todo.ID = uuid.New()
	todo.Title = payload.Title
	todo.Description = payload.Description
	todo.Complete = false
	todo.UserId = user.ID

	todos = append(todos, &todo)

	return c.JSON(Response{Status: http.StatusOK, Data: todo})
}

func GetTodoById(c *fiber.Ctx) error {
	id := c.Params("id", "")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  "Please provide id",
		})
	}

	user := c.Locals("user").(UserResponse)
	for _, todo := range todos {
		fmt.Println(todo)
		if todo.ID.String() == id && todo.UserId == user.ID {
			return c.JSON(Response{Status: http.StatusOK, Data: todo})
		}
	}

	return c.Status(http.StatusNotFound).JSON(Response{
		Status: http.StatusNotFound,
		Error:  "Not Found",
	})
}

func PatchTodo(c *fiber.Ctx) error {
	id := c.Params("id", "")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  "Please provide id",
		})
	}
	var payload TodoUpdate
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		})
	}

	if errors := ValidateStruct(payload); errors != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Errors: errors,
		})
	}

	user := c.Locals("user").(UserResponse)
	for _, todo := range todos {
		if todo.ID.String() == id && todo.UserId == user.ID {
			todo.Title = payload.Title
			todo.Description = payload.Description
			todo.Complete = payload.Complete
			break
		}
	}

	return c.JSON(Response{Status: http.StatusOK, Data: payload})
}

func DeleteTodo(c *fiber.Ctx) error {
	id := c.Params("id", "")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  "Please provide id",
		})
	}

	user := c.Locals("user").(UserResponse)
	for index, todo := range todos {
		if todo.ID.String() == id && todo.UserId == user.ID {
			todos = append(todos[:index], todos[index+1:]...)
			return c.JSON(Response{Status: http.StatusOK})
		}
	}

	return c.Status(http.StatusNotFound).JSON(Response{
		Status: http.StatusNotFound,
		Error:  "Not Found",
	})
}

func SignIn(c *fiber.Ctx) error {
	var payload SignInPayload
	// Decode and bind body to payload
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		})
	}

	if errors := ValidateStruct(payload); errors != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Errors: errors,
		})
	}
	// Check for valid username and password
	var user *User
	for _, userData := range users {
		if userData.Email == payload.Username {
			user = userData
			break
		}
	}
	if user == nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  "User Not Found",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password)); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  "Password doesnot match",
		})
	}

	// Generate JWT token, if valid
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		User: UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSignKey)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		})
	}

	c.Cookie(&fiber.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return c.JSON(Response{Status: http.StatusOK, Data: tokenString})
}

func SignUp(c *fiber.Ctx) error {
	var payload SignUpPayload
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		})
	}

	if errors := ValidateStruct(payload); errors != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Errors: errors,
		})
	}

	// check for existing email
	for _, user := range users {
		if user.Email == payload.Username {
			return c.Status(http.StatusBadRequest).JSON(Response{
				Status: http.StatusBadRequest,
				Error:  "Email already exists",
			})
		}
	}

	password, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Status(http.StatusBadRequest).JSON(Response{
			Status: http.StatusBadRequest,
			Error:  err.Error(),
		})
	}

	user := &User{
		ID:        uuid.New(),
		Email:     payload.Username,
		Password:  string(password),
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
	}
	users = append(users, user)

	return c.JSON(Response{Status: http.StatusOK, Data: user})
}

func Logout(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})

	return c.JSON(Response{Status: http.StatusOK})
}

func ValidateToken(c *fiber.Ctx) error {
	skipPaths := []string{
		"/api/todo/signin",
		"/api/todo/signup",
	}
	for _, path := range skipPaths {
		if c.Path() == path {
			return c.Next()
		}
	}

	token := c.Cookies("token", "")
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(Response{
			Status: http.StatusUnauthorized,
			Error:  "Not Authorized",
		})
	}

	claims := &Claims{}
	parseToken, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtSignKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return c.Status(http.StatusUnauthorized).JSON(Response{})
		}

		return c.Status(http.StatusBadRequest).JSON(Response{})
	}

	if !parseToken.Valid {
		return c.Status(http.StatusUnauthorized).JSON(Response{})
	}

	var tokenUser *UserResponse
	for _, user := range users {
		if user.ID == claims.User.ID {
			tokenUser = &claims.User
		}
	}

	if tokenUser == nil {
		return c.Status(http.StatusUnauthorized).JSON(Response{})
	} else {
		c.Locals("user", claims.User)
	}

	return c.Next()
}

func main() {
	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(Response{Status: http.StatusOK})
	})

	app.Use(ValidateToken)

	todoApi := app.Group("/api/todo")
	todoApi.Get("/", ListTodos)
	todoApi.Post("/", AddTodo)
	todoApi.Get("/logout", Logout)
	todoApi.Get("/:id", GetTodoById)
	todoApi.Patch("/:id", PatchTodo)
	todoApi.Delete("/:id", DeleteTodo)

	todoApi.Post("/signin", SignIn)
	todoApi.Post("/signup", SignUp)

	app.Listen(":5000")
}
