package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Starting server on :3000...")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		fmt.Printf("Error starting server: %s\n", err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*") // Misconfigured CORS: allows any domain
	w.Header().Set("Access-Control-Allow-Credentials", "true") // Credentials flag set with wildcard origin

	// Simulate a response that might contain sensitive data
	fmt.Fprintf(w, "This might be sensitive data.")
}


// package main

// import (
// 	"github.com/gin-gonic/gin"
// 	"github.com/gin-contrib/cors"
// 	"net/http"
// )

// type Result struct {
// 	URL          string   `json:"url"`
// 	Vulnerable   bool     `json:"vulnerable"`
// 	Payload      string   `json:"payload"`
// 	Details      []string `json:"details"`
// 	ReqData      *PreFlightData `json:"request_data"`
// 	ErrorMessage string   `json:"error_message"`
// }

// type PreFlightData struct {
// 	// define your preflight data structure here
// }

// func main() {
// 	r := gin.Default()

// 	r.Use(cors.Default())
// 	cspMiddleware := func(c *gin.Context) {
// 		// Initialize CSP directives with defaults that always apply
		

// 		// Example condition: if you determine that 'unsafe-eval' should be allowed
		
// 			cspDirectives := " script-src 'self' 'unsafe-eval';"
		

	
		

// 		// Set the Content-Security-Policy header
// 		c.Header("Content-Security-Policy", cspDirectives)

// 		c.Next()
// 	}

// 	r.Use(cspMiddleware)
// 	// Set up a route to serve the scanner results as JSON
// 	r.GET("/scanner", func(c *gin.Context) {
// 		// Here you would fetch your actual data, below is just an example
// 		results := []Result{
// 			{
// 				URL:          "https://example.com/api/2",
// 				Vulnerable:   true,
// 				Payload:      "Example Payload",
// 				Details:      []string{"Detail 1", "Detail 2"},
// 				ReqData:      nil, // Replace with actual data
// 				ErrorMessage: "Example error message",
// 			},
// 			{
// 				URL:          "https://example.org/api/3",
// 				Vulnerable:   true,
// 				Payload:      "Example Payload",
// 				Details:      []string{"Detail 1", "Detail 2"},
// 				ReqData:      nil, // Replace with actual data
// 				ErrorMessage: "Example error message",
// 			},
			
// 			// Add more Result objects to the slice as needed
// 		}

// 		c.JSON(http.StatusOK, results)
// 	})

// 	r.Run(":3000") // listen and serve on 0.0.0.0:8080
// }
