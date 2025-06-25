package routes

import (
	"auth_go/db"
	"auth_go/dbcommon"
	"auth_go/utils"
	"context"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func Register(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {

		if c.PostForm("email") == "" || c.PostForm("password") == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email and password are required"})
			return
		}

		ctx := context.Background()

		user, err := db.Queries.GetUserByEmail(ctx, c.PostForm("email"))
		if err == nil && user.Email != "" {
			log.Printf("Error getting user by email: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}

		encodedHash, err := utils.GenerateFromPassword(c.PostForm("password"))
		if err != nil {
			log.Printf("Error generating password hash: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
			return
		}
		db.Queries.CreateUser(ctx, dbcommon.CreateUserParams{
			Email:    c.PostForm("email"),
			Password: encodedHash,
		})
		c.JSON(http.StatusOK, gin.H{"Email": c.PostForm("email"), "Password": c.PostForm("password")})
	}
}

func RegisterPage(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {

		// Render login page with authorization parameters
		c.HTML(http.StatusOK, "register.html", gin.H{})
	}
}
