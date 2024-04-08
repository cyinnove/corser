package main//corser

import (
	requester "corser/pkg/requester"
	"fmt"
	"io"
	"os"
	"sync"
)

type Scan struct {
	Requester          *requester.Request
	URLs             []string
	ConcurrencyLevel int
	Wildcard         bool
	Errors           chan error
}

type Result struct {
	OutputFile *os.File
	StdOut     *io.Writer
}

// NewScan creates a new Scan instance with the provided configuration.
func NewScan(urls []string, concurrencyLevel int, wildcard bool, requester *requester.Request) *Scan {
	return &Scan{
		URLs:             urls,
		ConcurrencyLevel: concurrencyLevel,
		Wildcard:         wildcard,
		Requester:          requester,
		Errors:           make(chan error, concurrencyLevel),
	}
}

// RunScan executes the scanning process in a concurrent manner based on the ConcurrencyLevel.
func (s *Scan) RunScan() {
	var wg sync.WaitGroup

	// Using a buffered channel as a semaphore to control concurrency level
	cLevel := make(chan struct{}, s.ConcurrencyLevel)

	// It's safe to call SetClient() as it doesn't rely on external state that can be nil.
	client := s.Requester.SetClient()

	for _, URL := range s.URLs {
		wg.Add(1)
		go func(URL string) {
			defer wg.Done()
			cLevel <- struct{}{} // Acquire semaphore
			defer func() { <-cLevel }() // Release semaphore

			// Propagate errors through the Errors channel
			s.Requester.ScanTester(client, URL, s.Wildcard)
			
		}(URL)
	}

	wg.Wait()
	close(s.Errors) // Close the channel to signal completion

	// Print errors, if any
	for err := range s.Errors {
		fmt.Println("Error:", err)
	}
}


func main() {
	
	URLs := []string{"http://127.0.0.1:3000/api/sensitive"}

	req := requester.NewRequester("GET", "", "zomasec.io", "",  7)
	
	scan := NewScan(URLs, 2, true, req)

	scan.RunScan()

}