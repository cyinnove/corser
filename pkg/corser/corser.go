package main//corser

import (
	requester "corser/pkg/requester"
	"fmt"
	"io"
	"os"
	"sync"
)

type Scan struct {
	Request          *requester.Request
	URLs             []string
	ConcurrencyLevel int
	Wildcard         bool
	Errors           chan error
	//	Delay 		*time.Duration
	//Proxy		string
}

type Result struct {
	OutputFile *os.File
	StdOut     *io.Writer
}

func NewScan(urls []string, concurrencyLevel int, wildcard bool, requester *requester.Request) *Scan {
	return &Scan{URLs: urls, ConcurrencyLevel: concurrencyLevel, Wildcard: wildcard, Request: requester, Errors: make(chan error, concurrencyLevel)}
}

func (s *Scan) RunScan() {
	var wg sync.WaitGroup

	cLevel := make(chan struct{}, s.ConcurrencyLevel)
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


func main() {
	
	URLs := []string{"https://0a3c00a4034d5eb080078b81008b0066.web-security-academy.net/accountDetails"}

	req := requester.NewRequester("GET", "", "", 7)
	
	scan := NewScan(URLs, 2, true, req)

	scan.RunScan()
//


}