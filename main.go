package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	tld "github.com/jpillora/go-tld"
)

type Scanner struct {
	Request     Requester
	URLs        []string
	Concurrency int
	Wildcard    bool
	Errors      chan error
	//	Delay 		*time.Duration
	//Proxy		string
}

type Requester struct {
	Request *http.Request
	Cookies string
	Header  string
	Method  string
	Origin  string
	Timeout time.Duration
}

type Result struct {
	OutputFile *os.File
	StdOut     *io.Writer
}

func NewScanner(urls []string, concurrencyLevel int, wildcard bool, requester *Requester) *Scanner {
	return &Scanner{URLs: urls, Concurrency: concurrencyLevel, Wildcard: wildcard, Request: *requester, Errors: make(chan error, concurrencyLevel)}
}

func NewRequester(method string, header string, cookies string, timeout int) *Requester {
	return &Requester{Method: method, Header: header, Cookies: cookies, Timeout: time.Duration(timeout) * time.Second}
}

// SetClient function is used to return http client that will be used in the requests
func (r *Requester) SetClient() *http.Client {
	transportConfig := &http.Transport{
		MaxIdleConns:    30,
		IdleConnTimeout: 750 * time.Millisecond,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	redirectConfig := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &http.Client{
		Transport:     transportConfig,
		CheckRedirect: redirectConfig,
		Timeout:       r.Timeout,
	}
}

func (r *Requester) AddCustomHeader() {
	var headerName string
	var headerValue string

	parse := strings.ReplaceAll(r.Header, "\\n", "\n")

	re := regexp.MustCompile(`(?i)(.*):\s(.*)`)

	matches := re.FindStringSubmatch(parse)

	for i, match := range matches {
		if i == 1 {
			headerName = match
		}
		if i == 2 {
			headerValue = match
		}
	}

	r.Request.Header.Add(headerValue, headerName)
}

func (r *Requester) AddMethod(URL string) {
	// If the default request method for this request is not the user input method then add it
	if r.Request.Method != r.Method {
		r.Request.Method = r.Method
	}

}

func (r *Requester) Requester(client *http.Client, URL string, origins []string) {

	for _, origin := range origins {
		r.AddMethod(URL)
		r.Request.Header.Set("Origin", origin)

		if r.Header != "" {
			r.AddCustomHeader()
		}

		resp, err := client.Do(r.Request)

		if resp.Body != nil {
			// Discard the body content of the response
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		if err != nil {
			fmt.Printf("error sending %s", URL)
		}

		ACAOHeader := resp.Header.Get("Access-Control-Allow-Origin")
		ACACHeader := resp.Header.Get("Access-Control-Allow-Credentials")

		if ACAOHeader == origin {
			fmt.Printf("[+] Misconfiguration found! => URL: %s", URL)

			if ACACHeader == "true" {
				fmt.Printf("[+] Access-Control-Allow-Credentials: %s", ACACHeader)
			}

		}
	}
}

func netParser(url string) ([]string, error) {
	var parsedURLs []string

	URL, err := tld.Parse(url)

	if err != nil {
		return []string{}, err
	}

	subdomain := URL.Subdomain
	domain := URL.Domain
	topLevelDomain := URL.TLD

	return append(parsedURLs, subdomain, domain, topLevelDomain), nil
}

func anyOrigin(wildcard bool) []string {
	origins := []string{
		"http://zomasec.io",
		"https://zomasec.io",
	}

	if wildcard == true {
		origins = append(origins, "*")
	}
	return origins
}

func prefix(parts []string) []string {
	origins := []string{"https://" + parts[1] + ".zomasec.io", "https://" + parts[1] + "." + parts[2] + ".zomasec.io"}
	return origins
}

func suffix(parts []string) []string {
	origins := []string{"https://" + "zomasec" + parts[1] + "." + parts[2], "https://" + "zomasec.io" + "." + parts[1] + "." + parts[2]}
	return origins
}

func notEscapeDot(parts []string) []string {
	origins := []string{"https://" + parts[0] + "S" + parts[1] + parts[2]}
	return origins
}

func null() []string {
	origins := []string{"null"}
	return origins
}

func thirdParties() []string {
	origins := []string{
		"http://github.com",
		"https://google.com",
		"https://portswigger.net",
		"http://www.webdevout.net",
		"https://repl.it",
	}
	return origins
}

func specialChars(things []string) []string {
	var origins []string
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	permute := []string{"https://" + things[0] + "." + things[1] + "." + things[2] + "%s" + ".zomasec.io"}
	for i, per := range permute {
		for _, char := range chars {
			permute[i] = fmt.Sprintf(per, char)
			origins = append(origins, permute[i])
		}
	}
	return origins
}

func (r *Requester) ScanTester(client *http.Client, URL string, wildcard bool) {

	parts, _ := netParser(URL)

	anyOrigin := anyOrigin(wildcard)
	r.Requester(client, URL, anyOrigin)

	prefix := prefix(parts)
	r.Requester(client, URL, prefix)

	suffix := suffix(parts)
	r.Requester(client, URL, suffix)

	escaped := notEscapeDot(parts)
	r.Requester(client, URL, escaped)

	null := null()
	r.Requester(client, URL, null)

	thirdParties := thirdParties()
	r.Requester(client, URL, thirdParties)

	specialChars := specialChars(parts)
	r.Requester(client, URL, specialChars)

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

func main() {

	cLevel := flag.Int("c", 30, "Concurrency level or the number of workers to use.")
	checkWildcard := flag.Bool("wc", false, "Enable to check the wildcard in Access-Control-Allow-Origin.")
	header := flag.String("H", "", "Custom header added to each request.")
	method := flag.String("m", "GET", "Specific method name requested with it in each request.")
	cookies := flag.String("cookies", "", "Add cookies to each request to access authenticated pages.")
	list := flag.String("l", "", "List of URLs to scan.")
	timeout := flag.Int("timeout", 5, "Timeout for each request")

	flag.Parse()
	var Scan *Scanner

	if *list != "" {
		if err := Scan.ReadURLsFromFile(*list); err != nil {
			log.Fatalf("[!] Error reading from a file %s , %v\n", *list, err)
		}

	} else {
		if err := Scan.ReadFromStdin(); err != nil {
			log.Fatalf("[!] Error reading from Stdin")
		}
	}

	scan := NewScanner(Scan.URLs, *cLevel, *checkWildcard, NewRequester(*method, *header, *cookies, *timeout))

	scan.RunScan()

}
