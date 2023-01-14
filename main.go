package main

import (
	"github.com/bayunashr/go-jwt/controllers"
	"github.com/bayunashr/go-jwt/initializers"
	"github.com/bayunashr/go-jwt/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnv()
	initializers.LoadDb()
	initializers.SyncDb()
}

func main() {
	app := gin.Default()
	app.POST("/signup", controllers.SignUp)
	app.POST("/login", controllers.LogIn)
	app.GET("/validate", middleware.ReqAuth, controllers.Validate)
	app.Run()
}
