package routes

import (
	"auth_go/db"
	"auth_go/dbcommon"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthorizeParams struct {
	ResponseType        string `form:"response_type" binding:"required"`
	Namespace           string `form:"namespace" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	CodeChallenge       string `form:"code_challenge" binding:"required"`
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required"`
	State               string `form:"state" binding:"required"`
}

func generateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func Authorize(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {
		var params AuthorizeParams
		if err := c.ShouldBindQuery(&params); err != nil {
			log.Printf("Invalid parameters: %v", err)
			http.Error(c.Writer, "Invalid parameters", http.StatusBadRequest)
			return
		}

		// Validate response_type
		if params.ResponseType != "code" {
			log.Printf("Invalid response_type: %s", params.ResponseType)
			http.Error(c.Writer, "Invalid response_type", http.StatusBadRequest)
			return
		}

		// Get client by namespace
		ctx := context.Background()
		client, err := db.Queries.GetClientByNamespace(ctx, params.Namespace)
		if err != nil {
			log.Printf("Failed to get client by namespace %s: %v", params.Namespace, err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid namespace"})
			return
		}

		// Get session ID from cookie
		authCode, err := c.Cookie("auth_code")
		if err != nil {
			// Generate authorization code
			authCode, err := generateAuthCode()
			if err != nil {
				log.Printf("Failed to generate authorization code: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate authorization code"})
				return
			}

			// Store authorization request parameters in database
			createParams := dbcommon.CreateAuthorizeSessionParams{
				AuthCode:            authCode,
				ClientID:            client.ID,
				PkceChallenge:       params.CodeChallenge,
				PkceChallengeMethod: params.CodeChallengeMethod,
				State:               params.State,
				RedirectUri:         params.RedirectURI,
			}

			if err := db.Queries.CreateAuthorizeSession(ctx, createParams); err != nil {
				log.Printf("Failed to create authorization session: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create authorization session"})
				return
			}

			// Set auth code in cookie
			c.SetCookie(
				"auth_code", // name
				authCode,    // value
				3600,        // max age in seconds
				"/",         // path
				"",          // domain
				true,        // secure (HTTPS only)
				true,        // httpOnly
			)

			// Redirect to login page
			c.Redirect(http.StatusFound, "/login")
			return
		}

		// Clear auth code cookie after successful authorization
		c.SetCookie(
			"auth_code", // name
			"",          // value
			-1,          // max age (negative to expire immediately)
			"/",         // path
			"",          // domain
			true,        // secure (HTTPS only)
			true,        // httpOnly
		)

		// Redirect back to client with authorization code
		redirectURL := fmt.Sprintf("%s?code=%s&state=%s",
			params.RedirectURI,
			authCode,
			params.State)

		c.Redirect(http.StatusFound, redirectURL)
	}
}
