package main

import (
	"github.com/auth0/go-jwt-middleware"
	"github.com/labstack/echo"
	"jokeapp/controller"
	"jokeapp/middleware"
	"net/http"
)

//https://dev.to/codehakase/building-a-web-app-with-go-gin-and-react-5ke
//https://medium.com/monstar-lab-bangladesh-engineering/jwt-auth-in-go-dde432440924
//https://medium.com/@adigunhammedolalekan/build-and-deploy-a-secure-rest-api-with-go-postgresql-jwt-and-gorm-6fadf3da505b

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

var jwtMiddleWare *jwtmiddleware.JWTMiddleware

func main() {
	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello, World!")
	})
	h := controller.Handler{}
	e.POST("/login", h.Login)
	e.POST("/refreshtoken", h.RefreshToken)
	e.GET("/private", h.Private, middleware.IsLoggedIn, middleware.IsAdmin)
	e.GET("/jokes", h.JokeHandler, middleware.IsLoggedIn)
	e.POST("/jokes/like/:jokeID", h.LikeJoke)
	e.Logger.Fatal(e.Start(":1323"))
}
