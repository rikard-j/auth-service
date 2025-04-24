package routes

import (
	"auth_go/db"
	"auth_go/utils"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Validate(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get auth code from cookie
		token, err := c.Cookie("token")
		if err != nil {
			log.Printf("No token found: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No token found"})
			return
		}

		// Validate token
		claims, err := utils.ValidateJWT(token)
		if err != nil {
			log.Printf("Invalid token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"user_id": claims.UserID})
	}
}
