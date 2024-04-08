package runner

import (
    "corser/pkg/corser" // Ensure this import path matches your project structure
    "fmt"
)

// Runner coordinates scans, now also includes origin and headers for customization.
type Runner struct {
    URLs    []string
    Origin  string
    Headers map[string]string
}

// NewRunner creates a new Runner instance capable of scanning multiple URLs with custom settings.
func NewRunner(urls []string, origin string, headers map[string]string) *Runner {
    return &Runner{
        URLs:    urls,
        Origin:  origin,
        Headers: headers,
    }
}

// Start begins the scanning process for all provided URLs with the specified origin and headers.
func (r *Runner) Start() error {
    for _, url := range r.URLs {
        // Pass the origin and headers to the scanner
        scanner := corser.NewScanner(url, r.Origin, r.Headers)
        result := scanner.Scan()

        fmt.Printf("Scan result for: %s\n", result.URL)
        fmt.Printf("Vulnerable: %t\n", result.Vulnerable)

        // Displaying details about the scan results.
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
    }
    return nil
}
