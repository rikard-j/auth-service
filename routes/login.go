package routes

import (
	"auth_go/db"
	"auth_go/dbcommon"
	"auth_go/utils"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type LoginInput struct {
	Username    string `form:"username" binding:"required"`
	Password    string `form:"password" binding:"required"`
	NamespaceID int64  `form:"namespace_id" binding:"required"`
}

func Login(db *db.Db) gin.HandlerFunc {
	return func(g *gin.Context) {
		var input LoginInput
		if err := g.ShouldBind(&input); err != nil {
			log.Printf("Error binding login input: %v", err)
			g.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Get user from database
		user, err := db.Queries.GetUserByEmail(context.Background(), input.Username)
		if err != nil {
			log.Printf("Error getting user by email: %v", err)
			g.IndentedJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		if match, _ := utils.ComparePasswordAndHash(input.Password, user.Password); match {
			// Get auth code from cookie
			authCode, err := g.Cookie("auth_code")
			if err != nil {
				log.Printf("Error getting auth code from cookie: %v", err)
				g.IndentedJSON(http.StatusBadRequest, gin.H{"error": "No authorization code found"})
				return
			}

			// Update session with user ID
			err = db.Queries.UpdateUserSession(context.Background(), dbcommon.UpdateUserSessionParams{
				UserID:   sql.NullInt64{Int64: user.ID, Valid: true},
				AuthCode: authCode,
			})
			if err != nil {
				log.Printf("Error updating user session: %v", err)
				g.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "Failed to update session"})
				return
			}

			// Get authorization request from database using auth code from cookie
			authSession, err := db.Queries.GetSessionByAuthCode(context.Background(), authCode)
			if err != nil {
				log.Printf("Error getting session by auth code: %v", err)
				g.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Invalid authorization code"})
				return
			}

			// Get client information to get namespace
			client, err := db.Queries.GetClientByID(context.Background(), authSession.ClientID)
			if err != nil {
				log.Printf("Error getting client by ID: %v", err)
				g.IndentedJSON(http.StatusBadRequest, gin.H{"error": "Invalid client"})
				return
			}

			// Redirect back to authorize endpoint with all OAuth parameters
			redirectURL := fmt.Sprintf("/authorize?response_type=code&namespace=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=%s&state=%s",
				client.Namespace,
				authSession.RedirectUri,
				authSession.PkceChallenge,
				authSession.PkceChallengeMethod,
				authSession.State,
			)
			g.Redirect(http.StatusFound, redirectURL)
			return
		}

		log.Printf("Invalid password for user: %s", input.Username)
		g.IndentedJSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func LoginPage(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get auth code from cookie
		authCode, err := c.Cookie("auth_code")
		if err != nil {
			log.Printf("Error getting auth code from cookie: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "No authorization code found"})
			return
		}

		// Get authorization request from database
		authSession, err := db.Queries.GetSessionByAuthCode(context.Background(), authCode)
		if err != nil {
			log.Printf("Error getting session by auth code: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid authorization code"})
			return
		}

		// Get client to get namespace
		client, err := db.Queries.GetClientByID(context.Background(), authSession.ClientID)
		if err != nil {
			log.Printf("Error getting client by ID: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid client"})
			return
		}

		// Render login page with authorization parameters
		c.HTML(http.StatusOK, "login.html", gin.H{
			"NamespaceName": client.Name,
			"NamespaceID":   client.ID,
		})
	}
}
