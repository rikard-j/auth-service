package main

import (
	"auth_go/config"
	"auth_go/db"
	"auth_go/dbcommon"
	"auth_go/middleware"
	"auth_go/routes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
)

func initDB() (*dbcommon.Queries, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	db, err := sql.Open("mysql", cfg.GetDSN())
	if err != nil {
		return nil, err
	}

	if err := db.PingContext(context.Background()); err != nil {
		return nil, err
	}

	return dbcommon.New(db), nil
}

func main() {
	queries, err := initDB()
	if err != nil {
		log.Fatal(err)
	}

	db := db.NewDb(queries)

	r := gin.New()

	// Add logging middleware with custom format
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Formatter: func(param gin.LogFormatterParams) string {
			// Extract just the path without query parameters
			path := param.Request.URL.Path
			return fmt.Sprintf("[GIN] %v | %3d | %13v | %15s | %-7s %s\n",
				param.TimeStamp.Format("2006/01/02 - 15:04:05"),
				param.StatusCode,
				param.Latency,
				param.ClientIP,
				param.Method,
				path,
			)
		},
	}))

	// Add CORS middleware
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "Namespace"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(middleware.RateLimitMiddleware)

	// Load HTML templates
	r.LoadHTMLGlob("templates/*")

	// OAuth2 PKCE endpoints
	r.GET("/authorize", routes.Authorize(db))
	r.GET("/login", routes.LoginPage(db))
	r.POST("/login", routes.Login(db))
	r.POST("/token", routes.Token(db))
	r.POST("/register", routes.Register(db))
	r.GET("/register", routes.RegisterPage(db))
	r.GET("/validate", routes.Validate(db))

	// User endpoints
	r.GET("/user/:uuid", routes.GetUserByUUID(db))

	// Serve static files
	r.Static("/static", "./static")

	r.Run()
}
