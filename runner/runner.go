package runner

import (
	"github.com/zomasec/corser/pkg/corser" // Ensure this import path matches your project structure
	"github.com/zomasec/logz"
	//"github.com/zomasec/corser/pkg/pocgen"
	"fmt"
	"sync"
)

var (
	logger = logz.DefaultLogs()
	
)

// Runner coordinates scans, now also includes origin and headers for customization.
type Options struct {
	URLs     []string
	Origin   string
	Method   string
	Cookies  string
	DeepScan bool
	Verbose  bool
	Timeout  int
	CLevel   int
	Header   string
}

// NewRunner creates a new Runner instance capable of scanning multiple URLs with custom settings.
func NewOptions(urls []string, method, header, origin, cookies string, isDeep, verbose bool, timeout, cLevel int) *Options {
	return &Options{
		URLs:     urls,
		Origin:   origin,
		Method:   method,
		Cookies:  cookies,
		Timeout:  timeout,
		CLevel:   cLevel,
		DeepScan: isDeep,
		Verbose: verbose,
		Header:   header,
	}
}

// Start begins the scanning process for all provided URLs with the specified origin and headers.
func (r *Options) Start() error {
	var wg sync.WaitGroup
	clevel := make(chan struct{}, r.CLevel) // Control the concurrency level

	logger.ErrorEnabled = r.Verbose
	logger.DebugEnabled = r.Verbose

	for _, url := range r.URLs {
		clevel <- struct{}{}
		wg.Add(1)

		go func(u string) {
			defer wg.Done()
			defer func() { <-clevel }() // Release the slot

			// Assuming NewScanner's correct parameters are url and origin for simplicity
			// Adjust parameters as per your actual NewScanner function
			scanner := corser.NewScanner(u, r.Method, r.Header, r.Origin, r.Origin, r.DeepScan, r.Timeout)
			result := scanner.Scan()

			// Displaying details about the scan results
			if result.Vulnerable && len(result.Details) > 0 {
				logz.NewLogger("vuln", logz.Blue, result.URL).Log()
				for _, detail := range result.Details {
					fmt.Printf("\t %s-%s %s%s%s\n", logz.Green, logz.NC ,logz.Purple ,detail, logz.NC)
				}
			}

			if result.ErrorMessage != "" {
				logger.ERROR("%s", result.ErrorMessage)
			}

		}(url)
	}
	

	wg.Wait()
	return nil
}
