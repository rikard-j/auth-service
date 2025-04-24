package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

var (
	clients = make(map[string]*rate.Limiter)
	mu      sync.Mutex
)

func getClientLimiter(ip string) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	if limiter, exists := clients[ip]; exists {
		return limiter
	}

	// Allow 5 requests per second with bursts of 10
	limiter := rate.NewLimiter(5, 10)
	clients[ip] = limiter

	// Clean up old clients after a minute
	go func() {
		time.Sleep(time.Minute)
		mu.Lock()
		delete(clients, ip)
		mu.Unlock()
	}()

	return limiter
}

func RateLimitMiddleware(c *gin.Context) {
	ip := c.ClientIP()
	limiter := getClientLimiter(ip)

	if !limiter.Allow() {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error": "Too many requests",
		})
		return
	}

	c.Next()
}
