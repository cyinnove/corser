package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// all of these are vulnrable to CORS Misconfiguration

func handleCORS_Wildcard() gin.HandlerFunc {
	return func(ctx*gin.Context) {
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(http.StatusOK)
			return
		}
		ctx.Next()
	}
}

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

// CORS Middleware

func handleCORS_Rege0x1() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin :=  ctx.Request.Header.Get("Origin")

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

// CORS Middleware

func handleCORS_Rege0x2() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		origin :=  ctx.Request.Header.Get("Origin")

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

func handleCORS_WildcardDomain() gin.HandlerFunc {
	return func(ctx *gin.Context) {
        origin := ctx.Request.Header.Get("Origin")
        // Check if the origin matches the wildcard pattern
        if !strings.HasPrefix(origin, "https://") && !strings.HasSuffix(origin, ".target.com") {
            ctx.AbortWithStatus(http.StatusForbidden)
            fmt.Println(origin)
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


func handleCORS_Normal() gin.HandlerFunc {
	return func(ctx *gin.Context) {
        origin := ctx.Request.Header.Get("Origin")
        if origin != "https://*.target.com" {
            ctx.AbortWithStatus(http.StatusForbidden)
			return
        } 
		ctx.Writer.Header().Set("Content-Type", "application/json")
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

func main() {
	app := gin.Default()

	// Configure CORS middleware
	app.Use(handleCORS_ReflectedOrigin())


	app.GET("/api/1", func(ctx *gin.Context) {
		// Handle sensitive data
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})


	app2 := gin.Default()

	app2.Use(handleCORS_Null())
	app2.GET("/api/2", func(ctx *gin.Context) {
		// Handle sensitive data
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})

	app3 := gin.Default()

	app3.Use(handleCORS_Rege0x2())
	app3.GET("/api/3", func(ctx *gin.Context) {
		// Handle sensitive data
		ctx.JSON(http.StatusOK, gin.H{
			"message": "Sensitive data processed successfully",
		})
	})

	// Start the server
	app.Run(":1000")
	app2.Run("2000")
	app3.Run("3000")
}
