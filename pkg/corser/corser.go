package corser

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"
	"net"
	"corser/utils"
	"github.com/zomasec/tld"
	"github.com/zomasec/logz"
)

var logger = logz.DefaultLogs()

type Result struct {
	URL          string
	Vulnerable   bool
	Details      []string
	ErrorMessage string
}

type Scanner struct {
	URL     string
	Origin  string
	Method  string
	Cookies string
	Header  string 
	Timeout int
	Client *http.Client
	
}

func NewScanner(url, method, header, origin, cookies string, timeout int) *Scanner {
	
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: (&net.Dialer{
			Timeout:   5 * time.Second, // Timeout for establishing the connection
			KeepAlive: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second, // Timeout for TLS handshake
	}

	client := http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}
	
	return &Scanner{
		URL:     url,
		Origin:  origin,
		Method: method,
		Cookies: cookies,
		Timeout: timeout,
		Header: header,
		Client: &client,
	}
}

func (s *Scanner) Scan() *Result {

	result := &Result{URL: s.URL}

	s.RequestCheck(result)
	s.preflightRequest(result)
	
	deduplicateDetails(result)
	return result
}

func deduplicateDetails(result *Result) {
    detailsMap := make(map[string]bool)
    uniqueDetails := []string{}

    for _, detail := range result.Details {
        if _, exists := detailsMap[detail]; !exists {
            detailsMap[detail] = true
            uniqueDetails = append(uniqueDetails, detail)
        }
    }

    result.Details = uniqueDetails
}

func (s *Scanner) RequestCheck(result *Result) {
	var wg sync.WaitGroup
	var mutex sync.Mutex

	parts, err := netParser(s.URL)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Error parsing URL: %v", err)
		return
	}

	testOrigins := generateTestOrigins(parts)
	for _, testOrigin := range testOrigins {
		wg.Add(1)
		go func(origin string) {
			defer wg.Done()
			s.performRequest(origin, result, &mutex)
		}(testOrigin)
	}
	wg.Wait()
}

func (s *Scanner) performRequest(origin string, result *Result, mutex *sync.Mutex) {
	
	
	req, err := http.NewRequest(s.Method, s.URL, nil)
	if err != nil {
		mutex.Lock()
		result.ErrorMessage = fmt.Sprintf("Error creating request: %v", err)
		mutex.Unlock()
		return
	}

	req.Header.Add("Origin", origin)
	
	if s.Header != "" {
		key, value, err := utils.ParseHeader(s.Header)
		if err != nil {
			logger.ERROR("%s", err.Error())
		}
		req.Header.Add(key, value)

	}
	
	if s.Cookies != "" {
		req.Header.Add("Cookie", s.Cookies)
	}


	resp, err := s.Client.Do(req)
	if err != nil {
		mutex.Lock()
		result.ErrorMessage = fmt.Sprintf("Error performing request: %v", err)
		mutex.Unlock()
		return
	}
	defer resp.Body.Close()

	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	acao := resp.Header.Get("Access-Control-Allow-Origin")

	vulnerable, details := evaluateResponse(origin, acao, acac)
	if vulnerable {
		mutex.Lock()
		result.Vulnerable = true
		result.Details = append(result.Details, details...)
		mutex.Unlock()
	}
}

func evaluateResponse(origin, acao, acac string) (bool, []string) {
	details := make([]string, 0)	
	
	if vulnerable, detail := checkOriginReflected(origin, acao, acac); vulnerable {
		
		details = append(details, detail)
	}
	if vulnerable, detail := checkWildCard(acao); vulnerable {
		
		details = append(details, detail)
	} 
	if vulnerable, detail := checkNullOriginAllowed(acao); vulnerable {
		details = append(details, detail)
	}

	if len(details) > 0 {
		return true, details
	}
	return false, []string{}
}

func generateTestOrigins(parts []string) []string {
	var origins []string

	// Generate standard origins based on the domain parts.
	origins = append(origins, anyOrigin(false)...)
	origins = append(origins, prefix(parts)...)
	origins = append(origins, suffix(parts)...)
	origins = append(origins, notEscapeDot(parts)...)
	origins = append(origins, thirdParties()...)
	origins = append(origins, specialChars(parts)...)

	return origins
}

// checkOriginReflected checks for specific CORS misconfigurations involving the Access-Control-Allow-Origin (ACAO)
// and Access-Control-Allow-Credentials (ACAC) headers.
func checkOriginReflected(origin, acao, acac string) (bool, string) {
	// Check for ACAO reflecting the Origin or ACAC set to true.
	if acao == origin || acac == "true" {
		detail := fmt.Sprintf("Potentially vulnerable CORS configuration found. ACAO Header: %s, ACAC Header: %s", acao, acac)
		fmt.Println("vuln")
		return true, detail
	}

	// No misconfiguration detected.
	return false, ""
}

func checkWildCard(acao string) (bool, string) {
	if acao == "*" {
		details := fmt.Sprintf("Potentially vulnerable CORS configuration found. Wildcard ACAO header found. %s", acao)

		return true, details 
	}
	// No misconfiguration detected.
	return false, ""
}

// preflightRequestCheck performs a preflight request to see how it's handled.
func (s *Scanner) preflightRequest(result *Result) {
	req, err := http.NewRequest("OPTIONS", s.URL, nil)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	req.Header.Add("Origin", s.Origin)
	req.Header.Add("Access-Control-Request-Method", s.Method)
	
	resp, err := s.Client.Do(req)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	defer resp.Body.Close()

	// Check for ACAO, ACAC, and other relevant headers
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	// Enhanced CORS policy checks
	if acao == "*" && acac == "true" {
		result.Vulnerable = true
		result.Details = append(result.Details, "Misconfigured CORS: Wildcard ACAO with ACAC true.")
	} 

}

func netParser(url string) ([]string, error) {
	var parsedURLs []string

	URL, err := tld.Parse(url)
	if err != nil {
		return nil, err
	}

	subdomain := URL.Subdomain
	domain := URL.Domain
	topLevelDomain := URL.TLD

	parsedURLs = append(parsedURLs, subdomain, domain, topLevelDomain)
	return parsedURLs, nil
}

func anyOrigin(wildcard bool) []string {
	origins := []string{
		"http://zomasec.io",
		"https://zomasec.io",
	}

	if wildcard {
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

func checkNullOriginAllowed(acao string) (bool, string) {
	if acao == "null" {
		detail := "Null origin allowed in ACAO header, potentially exposing resources to any website if a browser allows null origins."
		return true, detail
	}
	return false, ""
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

func specialChars(parts []string) []string {
	var origins []string
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	for _, char := range chars {
		origin := fmt.Sprintf("https://%s.%s.%s%s.zomasec.io", parts[0], parts[1], parts[2], char)
		origins = append(origins, origin)
	}
	return origins
}


