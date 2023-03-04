package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	Error   error       `json:"error"`
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type Todo struct {
	ID          uuid.UUID `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Complete    bool      `json:"complete"`
	UserId      int       `json:"userId"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
}

type SignInPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type SignUpPayload struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
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

func ListTodos(c *fiber.Ctx) error {
	return c.JSON(Response{Status: 200, Data: todos})
}

func AddTodo(c *fiber.Ctx) error {
	var todo Todo
	err := json.Unmarshal(c.Body(), &todo)
	fmt.Println(todo)
	if err != nil {
		return c.JSON(Response{Status: 400, Error: err})
	}
	todo.ID = uuid.New()

	todos = append(todos, &todo)
	fmt.Println(todos)

	return c.JSON(Response{Status: 200, Data: todo})
}

func GetTodoById(c *fiber.Ctx) error {
	fmt.Println(c.Locals("user"))
	id := c.Params("id", "")
	fmt.Println(id)
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{
			Status: 400,
			Error:  errors.New("Please provide id"),
		})
	}

	for _, todo := range todos {
		fmt.Println(todo)
		if todo.ID.String() == id {
			return c.JSON(Response{Status: 200, Data: todo})
		}
	}

	return c.Status(http.StatusNotFound).JSON(Response{Status: 404, Message: "Not Found"})
}

func PatchTodo(c *fiber.Ctx) error {
	id := c.Params("id", "")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: "Please provide id"})
	}
	var payload Todo
	err := json.Unmarshal(c.Body(), &payload)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Error: err})
	}
	fmt.Println(payload)
	for _, todo := range todos {
		if todo.ID.String() == id {
			fmt.Println(todo)
			todo.Title = payload.Title
			todo.Description = payload.Description
			todo.Complete = payload.Complete
			break
		}
	}

	return c.JSON(Response{Status: 200, Data: payload})
}

func DeleteTodo(c *fiber.Ctx) error {
	id := c.Params("id", "")
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: "Please provide id"})
	}

	for index, todo := range todos {
		if todo.ID.String() == id {
			todos = append(todos[:index], todos[index+1:]...)
			return c.JSON(Response{Status: 200})
		}
	}

	return c.Status(http.StatusNotFound).JSON(Response{Status: 404, Message: "Not Found"})
}

func SignIn(c *fiber.Ctx) error {
	var payload SignInPayload
	// Decode and bind body to payload
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: err.Error()})
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
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: "User Not Found"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password)); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: "Password doesnot match"})
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
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: err.Error()})
	}

	c.Cookie(&fiber.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})

	return c.JSON(Response{Status: 200, Data: tokenString})
}

func SignUp(c *fiber.Ctx) error {
	var payload SignUpPayload
	if err := c.BodyParser(&payload); err != nil {
		c.Status(http.StatusBadRequest).JSON(Response{Status: http.StatusBadRequest, Error: err})
	}

	password, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		c.Status(http.StatusBadRequest).JSON(Response{Status: http.StatusBadRequest, Error: err})
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

	return c.JSON(Response{Status: 200, Message: "Logout Success"})
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
		return c.Status(http.StatusUnauthorized).JSON(Response{Status: http.StatusUnauthorized, Message: "Not Authorized"})
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

	c.Locals("user", claims.User)

	return c.Next()
}

func main() {
	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(Response{Status: 200, Message: "Golang Fiber"})
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

	app.Listen(":8080")
}
