package runner

import (
	"corser/pkg/corser" // Ensure this import path matches your project structure
	"fmt"
	"sync"
)

// Runner coordinates scans, now also includes origin and headers for customization.
type Runner struct {
    URLs     []string
	Origin  string
	Method  string
	Cookies string
	Timeout int
    CLevel  int
	Header string
}



// NewRunner creates a new Runner instance capable of scanning multiple URLs with custom settings.
func NewRunner(urls []string, method, header, origin, cookies string, timeout, cLevel int) *Runner {
    return &Runner{
        URLs:     urls,
		Origin:  origin,
		Method: method,
		Cookies: cookies,
		Timeout: timeout,
        CLevel: cLevel,
		Header: header,
    }
}

// Start begins the scanning process for all provided URLs with the specified origin and headers.
func (r *Runner) Start() error {
	var wg sync.WaitGroup
	clevel := make(chan struct{}, r.CLevel) // Control the concurrency level

	for _, url := range r.URLs {
		clevel <- struct{}{} 
		wg.Add(1)
		
		go func(u string) {
			defer wg.Done()
			defer func() { <-clevel }() // Release the slot

			// Assuming NewScanner's correct parameters are url and origin for simplicity
			// Adjust parameters as per your actual NewScanner function
            scanner := corser.NewScanner(u, r.Method,  r.Header, r.Origin, r.Origin, r.Timeout)
			result := scanner.Scan()

			fmt.Printf("Scan result for: %s\n", result.URL)
			fmt.Printf("Vulnerable: %t\n", result.Vulnerable)

			// Displaying details about the scan results
			if result.Vulnerable && len(result.Details) > 0 {
				fmt.Println("Details:")
				for _, detail := range result.Details {
					fmt.Printf("- %s\n", detail)
				}
			}

			if result.ErrorMessage != "" {
				fmt.Printf("Error: %s\n", result.ErrorMessage)
			}

			fmt.Println("--------------------------------------------------")
		}(url) 
	}

	wg.Wait() 
	return nil 
}