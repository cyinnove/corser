 package main

// import (
// 	"net/http"

// 	"github.com/gin-gonic/gin"
// )

// func main() {
// 	app := gin.Default()

// 	// Configure CORS middleware with a misconfigured policy
// 	app.Use(func(c *gin.Context) {
// 		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
// 		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
// 		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
// 		if c.Request.Method == "OPTIONS" {
// 			c.AbortWithStatus(http.StatusOK)
// 			return
// 		}
// 		c.Next()
// 	})

// 	// Define routes
// 	app.POST("/", func(c *gin.Context) {
// 		c.JSON(http.StatusOK, gin.H{
// 			"message": "Hello, world!",
// 		})
// 	})

// 	app.GET("/api/sensitive", func(c *gin.Context) {
// 		// Handle sensitive data
// 		c.JSON(http.StatusOK, gin.H{
// 			"message": "Sensitive data processed successfully",
// 		})
// 	})

// 	// Start the server
// 	app.Run(":3000")

// }
