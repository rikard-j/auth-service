package routes

import (
	"auth_go/db"
	"auth_go/utils"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type TokenRequest struct {
	GrantType    string `json:"grant_type" binding:"required"`
	Code         string `json:"code" binding:"required"`
	Namespace    string `json:"namespace" binding:"required"`
	CodeVerifier string `json:"code_verifier" binding:"required"`
}

func Token(db *db.Db) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req TokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("Error binding token request: %v", err)
			http.Error(c.Writer, "Error binding request", http.StatusBadRequest)
			return
		}

		// 1. Validate grant type is "authorization_code"
		if req.GrantType != "authorization_code" {
			log.Printf("Invalid grant type: %s", req.GrantType)
			http.Error(c.Writer, "Invalid grant type", http.StatusBadRequest)
			return
		}

		// 2. Verify client exists
		_, err := db.Queries.GetClientByNamespace(context.Background(), req.Namespace)
		if err != nil {
			log.Printf("Error getting client by namespace %s: %v", req.Namespace, err)
			http.Error(c.Writer, "Invalid client", http.StatusBadRequest)
			return
		}

		// 3. Get the authorization session using the auth code
		authSession, err := db.Queries.GetSessionByAuthCode(context.Background(), req.Code)
		if err != nil {
			log.Printf("Error getting session by auth code: %v", err)
			http.Error(c.Writer, "Invalid authorization code", http.StatusBadRequest)
			return
		}

		// 4. Verify the session hasn't expired
		if time.Now().After(authSession.ExpiresAt) {
			log.Printf("Authorization code expired at %v", authSession.ExpiresAt)
			http.Error(c.Writer, "Authorization code expired", http.StatusBadRequest)
			return
		}

		// 5. Verify PKCE code verifier
		if !verifyPKCE(req.CodeVerifier, authSession.PkceChallenge, authSession.PkceChallengeMethod) {
			log.Printf("Invalid PKCE code verifier for session %s", authSession.AuthCode)
			http.Error(c.Writer, "Invalid code verifier", http.StatusBadRequest)
			return
		}

		// 6. Generate access token using the email from the session
		accessToken, err := utils.GenerateJWT(authSession.UserID.Int64)
		if err != nil {
			log.Printf("Error generating JWT for user %d: %v", authSession.UserID.Int64, err)
			http.Error(c.Writer, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// 7. Delete the authorization session
		if err := db.Queries.DeleteSession(context.Background(), authSession.AuthCode); err != nil {
			log.Printf("Error deleting session %s: %v", authSession.AuthCode, err)
			http.Error(c.Writer, "Failed to clean up session", http.StatusInternalServerError)
			return
		}

		// 8. Return the tokens
		c.SetCookie(
			"token",     // name
			accessToken, // value
			3600,        // max age in seconds
			"/",         // path
			"",          // domain
			true,        // secure (HTTPS only)
			true,        // httpOnly
		)
		c.JSON(http.StatusOK, gin.H{
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}
}

func verifyPKCE(verifier, challenge, method string) bool {
	var computedChallenge string

	switch method {
	case "plain":
		computedChallenge = verifier
	case "S256":
		h := sha256.New()
		h.Write([]byte(verifier))
		computedChallenge = base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	default:
		return false
	}

	return computedChallenge == challenge
}
