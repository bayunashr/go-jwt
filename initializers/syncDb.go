package initializers

import "github.com/bayunashr/go-jwt/models"

func SyncDb() {
	DB.AutoMigrate(&models.User{})
}
