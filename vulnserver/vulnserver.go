package main

import (
	"log"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
)

// Handlers for CORS configurations

func handleCORS_ReflectedOrigin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", ctx.Request.Header.Get("Origin"))
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		ctx.AbortWithStatus(http.StatusOK)

		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusCreated)
			return
		}
		ctx.Status(http.StatusOK)
		ctx.Next()
	}
}

func handleCORS_Null() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "null")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusOK)
			return
		}
		ctx.Next()
	}
}

func handleCORS_Rege0x2() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin := ctx.Request.Header.Get("Origin")

		if wanted, _ := regexp.MatchString(`(https?://)([^/@]+@)?(.*\.)?target\.com`, ""); !wanted {
			ctx.AbortWithStatus(http.StatusForbidden)
			return
		}

		ctx.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusOK)
			return
		}
		ctx.Next()
	}
}

// Main function

func main() {
	// First server instance
	app := gin.Default()
	app.Use(handleCORS_ReflectedOrigin())
	app.GET("/api/1", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})
	go func() {
		if err := app.Run(":1000"); err != nil {
			log.Fatal("Error starting server 1: ", err)
		}
	}()

	// Second server instance
	app2 := gin.Default()
	app2.Use(handleCORS_Null())
	app2.GET("/api/2", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})
	go func() {
		if err := app2.Run(":2000"); err != nil {
			log.Fatal("Error starting server 2: ", err)
		}
	}()

	// Third server instance
	app3 := gin.Default()
	app3.Use(handleCORS_Rege0x2())
	app3.GET("/api/3", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})
	go func() {
		if err := app3.Run(":3000"); err != nil {
			log.Fatal("Error starting server 3: ", err)
		}
	}()

	// Keep the main goroutine running
	select {}
}
