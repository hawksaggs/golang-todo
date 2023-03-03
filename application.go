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
	UserId      User      `json:"user"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Password  string    `json:"password"`
	FirstName string    `json:"firstName"`
	LastName  string    `json:"lastName"`
}

type UserPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var jwtSignKey = []byte("sdsdf@q212")

var todos []*Todo

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
	id := c.Params("id", "")
	fmt.Println(id)
	if id == "" {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Error: errors.New("Please provide id")})
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
	var payload UserPayload
	// Decode and bind body to payload
	if err := c.BodyParser(&payload); err != nil {
		return c.Status(http.StatusBadRequest).JSON(Response{Status: 400, Message: err.Error()})
	}
	// Check for valid username and password
	// Generate JWT token, if valid
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: payload.Username,
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
	}
	for _, path := range skipPaths {
		fmt.Println(path)
		fmt.Println(c.Path())
		if c.Path() == path {
			return c.Next()
		}
	}

	token := c.Cookies("token", "")
	if token == "" {
		return c.Status(http.StatusUnauthorized).JSON(Response{Status: http.StatusUnauthorized, Message: "Not Authorized"})
	}

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

	app.Listen(":8080")
}
