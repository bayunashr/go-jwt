package middleware

import (
	"fmt"
	"os"
	"time"

	"github.com/bayunashr/go-jwt/initializers"
	"github.com/bayunashr/go-jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func ReqAuth(c *gin.Context) {
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatus(401)
	}

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(401)
		} else {
			var user models.User
			initializers.DB.First(&user, claims["sub"])
			if user.ID == 0 {
				c.AbortWithStatus(401)
			} else {
				c.Set("user", user)
			}
		}
	} else {
		c.AbortWithStatus(401)
	}

	c.Next()
}
