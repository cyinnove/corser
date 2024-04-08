package runner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"corser/pkg/corser"
	"corser/pkg/requester"
)

type Runner struct {
	CORSER  *corser.Scan
	Request *requester.Request
}

// NewRunner initializes a Runner instance with default values.
func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) ensureScanInitialized() {
	if r.CORSER == nil {
		// Assume default values for now; you might need a better way to initialize these based on actual needs
		r.CORSER = corser.NewScan([]string{}, 1, false, r.Request) // Default values; adjust as necessary
	}
}

// RunScan configures and runs the scan based on the provided parameters.
func (r *Runner) RunScan(cLevel int, wildcard bool, method, header, origin, cookies string, timeout int) {
	r.Request = requester.NewRequester(method, header, origin, cookies, timeout)
	r.CORSER = corser.NewScan([]string{}, cLevel, wildcard, r.Request)

	go func() {
		r.CORSER.RunScan()

		for err := range r.CORSER.Errors {
			fmt.Println("Scan error:", err)
		}
	}()
}

// ReadURLsFromFile reads URLs from a given file and adds them to the scan's URL list.
func (r *Runner) ReadURLsFromFile(filename string) error {
	r.ensureScanInitialized() // Ensure CORSER is initialized

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			r.CORSER.URLs = append(r.CORSER.URLs, url)
		}
	}

	return scanner.Err()
}

// ReadURLsFromStdin reads URLs from standard input until EOF and adds them to the scan's URL list.
func (r *Runner) ReadURLsFromStdin() error {
	r.ensureScanInitialized() // Ensure CORSER is initialized

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			r.CORSER.URLs = append(r.CORSER.URLs, url)
		}
	}

	return scanner.Err()
}
