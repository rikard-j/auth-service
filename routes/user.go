package routes

import (
	"auth_go/db"
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetUserByUUID fetches a user by their UUID
func GetUserByUUID(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get UUID from URL parameter
		uuid := c.Param("uuid")
		if uuid == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "UUID parameter is required"})
			return
		}

		// Fetch user from database
		user, err := db.Queries.GetUserByUUID(context.Background(), uuid)
		if err != nil {
			log.Printf("Error fetching user by UUID %s: %v", uuid, err)
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Return user data (excluding password for security)
		c.JSON(http.StatusOK, gin.H{
			"uuid":      user.Uuid,
			"email":     user.Email,
			"firstname": user.Firstname,
			"lastname":  user.Lastname,
		})
	}
}
