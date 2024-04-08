package corser

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/zomasec/logz"
)

var (
	logger = logz.DefaultLogs()
)

// ScanResult holds the outcome of a scan.
type ScanResult struct {
	URL          string
	Vulnerable   bool
	Details      []string // Add details for more informative output.
	ErrorMessage string
}

// Scanner scans for CORS misconfigurations.
type Scanner struct {
	URL    string
	Origin string
	Headers map[string]string
}

// NewScanner creates a new Scanner instance with customizable origin and headers.
func NewScanner(url, origin string, headers map[string]string) *Scanner {
	return &Scanner{
		URL:     url,
		Origin:  origin,
		Headers: headers,
	}
}

// Scan performs the CORS misconfiguration scan.
func (s *Scanner) Scan() *ScanResult {
	result := &ScanResult{URL: s.URL}

	// Initial simple request to check for basic misconfigurations.
	s.simpleRequestCheck(result)

	// Preflight request to check how preflighted requests are handled.
	s.preflightRequestCheck(result)

	return result
}

// simpleRequestCheck checks for basic CORS misconfigurations.
func (s *Scanner) simpleRequestCheck(result *ScanResult) {
	req, err := http.NewRequest("GET", s.URL, nil)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	req.Header.Add("Origin", s.Origin)
	for key, value := range s.Headers {
		req.Header.Add(key, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	defer resp.Body.Close()

	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	acao := resp.Header.Get("Access-Control-Allow-Origin")

	// Check for ACAC and ACAO misconfiguration.
	if acao == s.Origin || acac == "true" {
		result.Vulnerable = true
		result.Details = append(result.Details, fmt.Sprintf("ACAO Header: %s, ACAC Header: %s", acao, acac))
	}

	if acao == "*" {
		result.Vulnerable = true
		result.Details = append(result.Details, "Wildcard ACAO header found.")
	}

	logger.DEBUG("Simple Request Check - ACAO: %s, ACAC: %s", acao, acac)
}

// preflightRequestCheck performs a preflight request to see how it's handled.
func (s *Scanner) preflightRequestCheck(result *ScanResult) {
	req, err := http.NewRequest("OPTIONS", s.URL, nil)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	req.Header.Add("Origin", s.Origin)
	req.Header.Add("Access-Control-Request-Method", "GET")
	for key, value := range s.Headers {
		req.Header.Add(key, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acah := resp.Header.Get("Access-Control-Allow-Headers")

	if acao == s.Origin && strings.Contains(acah, "X-Custom-Header") {
		result.Vulnerable = true
		result.Details = append(result.Details, "Preflight request improperly allows custom headers.")
	}

	logger.DEBUG("Preflight Request Check - ACAO: %s, ACAH: %s", acao, acah)
}
