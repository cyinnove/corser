package main

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func handleCORS_ReflectedOrigin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Allow requests from any origin
		origin := ctx.Request.Header.Get("Origin")
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", origin)

		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true") // Allow credentials

		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}
		ctx.Next()
	}
}

func main() {
	// Server 1
	app := gin.Default()
	app.Use(handleCORS_ReflectedOrigin())

	app.GET("/api/1", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})

	fmt.Println("Starting Server 1 on port 4000...")
	if err := app.Run(":4000"); err != nil {
		fmt.Println("Error starting Server 1:", err)
	}

	// Server 2
	app2 := gin.Default()
	app2.Use(func(ctx *gin.Context) {
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "null")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusNoContent)
			return
		}
		ctx.Next()
	})

	app2.GET("/api/2", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})

	fmt.Println("Starting Server 2 on port 5000...")
	if err := app2.Run(":5000"); err != nil {
		fmt.Println("Error starting Server 2:", err)
	}

	// Server 3
	app3 := gin.Default()
	app3.Use(handleCORS_ReflectedOrigin()) // Corrected function name

	app3.GET("/api/3", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})

	fmt.Println("Starting Server 3 on port 6000...")
	if err := app3.Run(":6000"); err != nil {
		fmt.Println("Error starting Server 3:", err)
	}
}
