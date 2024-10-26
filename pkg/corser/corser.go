package corser

import (
	"crypto/tls"
	"fmt"
	"github.com/cyinnove/corser/pkg/utils"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/zomasec/logz"
)

// var logger = logz.DefaultLogs()

// Result represents the result of a CORS vulnerability check.
type Result struct {
	URL          string `json:"url"`
	Vulnerable   bool
	Payload      string         `json:"payload"`
	Details      []string       `json:"details"`
	ReqData      *PreFlightData `json:"request_data"`
	ErrorMessage string
}

// Scanner represents a scanner that performs HTTP requests with various options.
type Scanner struct {
	URL      string       // The target URL to scan.
	Origin   string       // The value of the Origin header to be sent with the request.
	Method   string       // The HTTP method to be used for the request.
	Cookies  string       // The cookies to be sent with the request.
	Header   string       // The additional headers to be sent with the request.
	DeepScan bool         // Indicates whether to perform a deep scan or not.
	NoColor  bool         // Indicates whether to disable colored output or not.
	Payloads []string     // The payloads to be used for scanning.
	Timeout  int          // The timeout duration for the request.
	Host     *Host        // The host information for the target URL.
	Client   *http.Client // The HTTP client to be used for making requests.
	Result   *Result      // The result of the scan.
}

// PreFlightData represents the data required for pre-flight requests.
type PreFlightData struct {
	ACAO    string   // ACAO represents the Access-Control-Allow-Origin header value.
	ACAC    string   // ACAC represents the Access-Control-Allow-Credentials header value.
	Headers []string // Headers represents the list of allowed headers.
	Methods []string // Methods represents the list of allowed methods.
}

// Host represents a host with its various components.
type Host struct {
	Full      string // Full represents the full host string.
	Domain    string // Domain represents the domain name of the host.
	TLD       string // TLD represents the top-level domain of the host.
	Subdomain string // Subdomain represents the subdomain of the host.
}

// NewScanner creates a new instance of the Scanner struct.
// It initializes the HTTP client with the provided parameters and returns a pointer to the Scanner.
// The Scanner is used to perform CORS scanning on the specified URL.
func NewScanner(url, method, header, origin, cookies string, isDeep bool, timeout int) *Scanner {

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	redirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		CheckRedirect: redirect,
	}

	return &Scanner{
		URL:      url,
		Origin:   origin,
		Method:   method,
		Cookies:  cookies,
		Timeout:  timeout,
		Header:   header,
		DeepScan: isDeep,
		Client:   &client,
		Result: &Result{
			URL:     url,
			Details: make([]string, 0),
			ReqData: &PreFlightData{},
		},
	}
}

// Scan performs the scanning operation on the provided URL.
// It sends a preflight request and checks for any errors.
// If there is an error, it returns a Result object with the error message.
// Otherwise, it proceeds with the request check and deduplicates the details before returning the Result.
func (s *Scanner) Scan() *Result {

	s.preflightRequest()

	if s.Result.ErrorMessage != "" {
		return &Result{
			URL:          s.URL,
			Vulnerable:   false,
			Details:      []string{},
			ErrorMessage: fmt.Sprintf("URL not alive or an error in request : %s", s.Result.ErrorMessage),
		}
	}

	s.RequestCheck()

	deduplicateDetails(s.Result)
	return s.Result
}

// deduplicateDetails removes duplicate details from the given Result object.
// It modifies the Details field of the Result object in-place.
// The function uses a map to keep track of unique details and appends them to a new slice.
// Finally, it assigns the new slice of unique details back to the Details field of the Result object.
//
// Parameters:
// - result: A pointer to a Result object.
//
// Example usage:
//
//	result := &Result{
//	  Details: []string{"detail1", "detail2", "detail1", "detail3"},
//	}
//	deduplicateDetails(result)
//
//	// After deduplication, result.Details will be []string{"detail1", "detail2", "detail3"}
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

// RequestCheck performs a series of checks on the Scanner instance.
// It sets the Host field by parsing the URL, applies various checks such as anyOrigin,
// Prefix, Wildcard, Null, Suffix, and JoinTwoice. If DeepScan is enabled, it also performs
// additional checks like UserAtDomain and SpecialChars. Finally, it performs a series of
// asynchronous requests using the payloads specified in the Scanner instance.
func (s *Scanner) RequestCheck() {
	var wg sync.WaitGroup
	var mutex sync.Mutex

	s.Host, _ = NetParser(s.URL)
	s.anyOrigin()
	s.Prefix()
	s.Wildcard()
	s.Null()
	s.Suffix()
	s.JoinTwoice()

	if s.DeepScan {
		s.UserAtDomain()
		s.SpecialChars()
	}

	for _, payload := range s.Payloads {
		wg.Add(1)
		go func(origin string) {
			defer wg.Done()
			s.performRequest(origin, &mutex)
		}(payload)
	}
	wg.Wait()
}

// performRequest sends an HTTP request to the specified URL using the provided payload.
// It sets the necessary headers and handles any errors that occur during the request.
// If the response indicates a vulnerability, it updates the result accordingly.
//
// Parameters:
// - payload: The payload to be sent in the request.
// - mutex: A mutex used to synchronize access to the result and other shared data.
//
// Returns: None.
func (s *Scanner) performRequest(payload string, mutex *sync.Mutex) {

	req, err := http.NewRequest(s.Method, s.URL, nil)
	if err != nil {
		mutex.Lock()
		s.Result.ErrorMessage = fmt.Sprintf("Error creating request: %s", err.Error())
		mutex.Unlock()
		return
	}

	// add default headers
	req.Header.Set("User-Agent", uarand.GetRandom())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	req.Header.Set("Connection", "close")

	req.Header.Add("Origin", payload)

	if s.Header != "" {
		key, value, err := utils.ParseHeader(s.Header)
		if err != nil {
			s.Result.ErrorMessage = fmt.Sprintf("Error formating error: %s", err.Error())
			return
		}
		req.Header.Add(key, value)

	}
	req.Cookies()
	if s.Cookies != "" {
		req.Header.Add("Cookie", s.Cookies)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		mutex.Lock()
		s.Result.ErrorMessage = fmt.Sprintf("Error performing request: %s", err.Error())
		mutex.Unlock()
		return
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		s.Result.ErrorMessage = err.Error()
		return
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	vulnerable, details := evaluateResponse(payload, acao, acac)
	if vulnerable {
		mutex.Lock()
		s.Result.Vulnerable = true
		s.Result.Payload = payload
		s.Result.Details = append(s.Result.Details, details...)
		mutex.Unlock()
	}
}

// evaluateResponse evaluates the response for potential security vulnerabilities.
// It takes in the payload, Access-Control-Allow-Origin (ACAO), and Access-Control-Allow-Credentials (ACAC) as parameters.
// It returns a boolean indicating whether any vulnerabilities were found, and a slice of strings containing the details of the vulnerabilities.
func evaluateResponse(payload, acao, acac string) (bool, []string) {
	details := make([]string, 0)

	if vulnerable, detail := checkOriginReflected(payload, acao, acac); vulnerable {
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

// checkOriginReflected checks if the ACAO (Access-Control-Allow-Origin) header reflects the Origin or if the ACAC (Access-Control-Allow-Credentials) header is set to true.
// It returns a boolean indicating whether a misconfiguration is detected and a string providing additional details about the misconfiguration.
func checkOriginReflected(payload, acao, acac string) (bool, string) {
	// Check for ACAO reflecting the Origin or ACAC set to true.
	var detail string
	if acao == payload || acac == "true" {

		if acac == "" {
			detail = fmt.Sprintf("%sACAO Header:%s %s", logz.Green, logz.NC, acao)
		} else {
			detail = fmt.Sprintf("%sACAO Header:%s %s, ACAC Header: %s", logz.Green, logz.NC, acao, acac)
		}

		return true, detail
	}

	// No misconfiguration detected.
	return false, ""
}

// checkWildCard checks if the given ACAO (Access-Control-Allow-Origin) header value is a wildcard.
// It returns a boolean indicating whether the ACAO header is a wildcard and a string with additional details if applicable.
func checkWildCard(acao string) (bool, string) {
	if acao == "*" {
		details := fmt.Sprintf("Wildcard ACAO header found. %s", acao)

		return true, details
	}
	// No misconfiguration detected.
	return false, ""
}

// preflightRequestCheck performs a preflight request to see how it's handled.
func (s *Scanner) preflightRequest() {
	req, err := http.NewRequest("OPTIONS", s.URL, nil)
	if err != nil {
		s.Result.ErrorMessage = err.Error()
		return
	}

	req.Header.Set("Origin", s.Origin)
	if s.Header != "" {
		key, value, err := utils.ParseHeader(s.Header)
		if err != nil {
			s.Result.ErrorMessage = err.Error()
			return
		}
		req.Header.Set(key, value)
	}
	if s.Cookies != "" {
		req.Header.Set("Cookie", s.Cookies)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		s.Result.ErrorMessage = err.Error()
		return
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		s.Result.ErrorMessage = err.Error()
		return
	}

	s.Result.ReqData.ACAO = resp.Header.Get("Access-Control-Allow-Origin")
	s.Result.ReqData.ACAC = resp.Header.Get("Access-Control-Allow-Credentials")
	s.Result.ReqData.Methods = utils.ParseMethods(resp.Header.Get("Access-Control-Allow-Methods"))
	s.Result.ReqData.Headers = utils.ParseHeaders(resp.Header.Get("Access-Control-Allow-Headers"))
}

func checkNullOriginAllowed(acao string) (bool, string) {
	if acao == "null" {
		detail := "Null origin allowed in ACAO header."
		return true, detail
	}
	return false, ""
}
