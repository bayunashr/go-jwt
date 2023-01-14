package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/bayunashr/go-jwt/initializers"
	"github.com/bayunashr/go-jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(400, gin.H{
			"error": "Fail to read body",
		})
	} else {
		hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

		if err != nil {
			c.JSON(400, gin.H{
				"error": "Fail to encrypt password",
			})
		} else {
			user := models.User{Email: body.Email, Password: string(hashed)}
			result := initializers.DB.Create(&user)
			if result.Error != nil {
				c.JSON(400, gin.H{
					"error": "Fail to create user",
				})
			} else {
				c.JSON(200, gin.H{
					"user": user,
				})
			}
		}
	}
}

func LogIn(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(400, gin.H{
			"error": "Fail to read body",
		})
	} else {
		var user models.User
		initializers.DB.Where("Email = ?", body.Email).First(&user)
		if user.ID == 0 {
			c.JSON(400, gin.H{
				"error": "email not found, please sign in",
			})
		} else {
			err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
			if err != nil {
				c.JSON(400, gin.H{
					"error": "wrong password",
				})
			} else {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"sub": user.ID,
					"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
				})
				tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
				if err != nil {
					c.JSON(400, gin.H{
						"error": "fail to create token",
					})
				} else {
					c.SetSameSite(http.SameSiteLaxMode)
					c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
					c.JSON(200, gin.H{
						"success": "youre logged in",
					})
				}
			}
		}
	}
}

func Validate(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "youre logged in",
	})
}
