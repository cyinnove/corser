package runner

import (
	"bufio"
	"os"
	"strings"
	"time"

	"corser/pkg/corser"
	"corser/pkg/requester"
)

type Runner struct {
	CORSER  corser.Scan
	Request requester.Request
}

func NewRunner() *Runner {
    return &Runner{
        Request: requester.Request{},
        CORSER: corser.Scan{},
    }
}

func (r *Runner) RunScan(cLevel int, wildcard bool, method string, header string, cookies string, timeout int) {

	r.CORSER.ConcurrencyLevel = cLevel
	r.CORSER.Wildcard = wildcard
	r.Request.Method = method
	r.Request.Header = header
	r.Request.Cookies = cookies
	r.Request.Timeout = time.Duration(timeout)

	r.CORSER.RunScan()

}

func (r *Runner) ReadURLsFromFile(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return err
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			r.CORSER.URLs = append(r.CORSER.URLs, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (r *Runner) ReadURLsFromStdin() error {
	// Read URLs from standard input
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			r.CORSER.URLs = append(r.CORSER.URLs, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
