package corser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	requester "corser/pkg/requester"


)

type Scanner struct {
	Request     *requester.Request
	URLs        []string
	Concurrency int
	Wildcard    bool
	Errors      chan error
	//	Delay 		*time.Duration
	//Proxy		string
}

type Result struct {
	OutputFile *os.File
	StdOut     *io.Writer
}

func NewScanner(urls []string, concurrencyLevel int, wildcard bool, requester *requester.Request) *Scanner {
	return &Scanner{URLs: urls, Concurrency: concurrencyLevel, Wildcard: wildcard, Request: requester, Errors: make(chan error, concurrencyLevel)}
}


func (s *Scanner) RunScan() {
	var wg sync.WaitGroup

	cLevel := make(chan struct{}, s.Concurrency)
	client := s.Request.SetClient()

	for _, URL := range s.URLs {
		wg.Add(1)
		go func(URL string) {
			defer wg.Done()
			cLevel <- struct{}{}
			defer func() { <-cLevel }()
			s.Request.ScanTester(client, URL, s.Wildcard)
		}(URL)
	}

	wg.Wait()

	for e := range s.Errors {
		fmt.Println(e)
	}

}

func (s *Scanner) ReadURLsFromFile(filename string) error {

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
			s.URLs = append(s.URLs, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (s *Scanner) ReadFromStdin() error {
	// Read URLs from standard input
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			s.URLs = append(s.URLs, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
