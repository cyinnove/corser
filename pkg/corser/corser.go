package corser

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/zomasec/corser/utils"
	"github.com/zomasec/logz"
)

// var logger = logz.DefaultLogs()

type Result struct {
	URL          string `json:"url"`
	Vulnerable   bool
	Payload      string         `json:"payload"`
	Details      []string       `json:"details"`
	ReqData      *PreFlightData `json:"request_data"`
	ErrorMessage string
}

type Scanner struct {
	URL      string
	Origin   string
	Method   string
	Cookies  string
	Header   string
	DeepScan bool
	NoColor  bool
	Payloads []string
	Timeout  int
	Host     *Host
	Client   *http.Client
	Result   *Result
}
type PreFlightData struct {
	ACAO    string
	ACAC    string
	Headers []string
	Methods []string
}

type Host struct {
	Full      string
	Domain    string
	TLD       string
	Subdomain string
}

func NewScanner(url, method, header, origin, cookies string, isDeep bool, timeout int) *Scanner {

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Dial: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	client := http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
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

func (s *Scanner) performRequest(payload string, mutex *sync.Mutex) {

	req, err := http.NewRequest(s.Method, s.URL, nil)
	if err != nil {
		mutex.Lock()
		s.Result.ErrorMessage = fmt.Sprintf("Error creating request: %s", err.Error())
		mutex.Unlock()
		return
	}

	req.Header.Add("Origin", payload)

	if s.Header != "" {
		key, value, err := utils.ParseHeader(s.Header)
		if err != nil {
			s.Result.ErrorMessage = fmt.Sprintf("Error formating error: %s", err.Error())
			return
		}
		req.Header.Add(key, value)

	}

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

// checkOriginReflected checks for specific CORS misconfigurations involving the Access-Control-Allow-Origin (ACAO)
// and Access-Control-Allow-Credentials (ACAC) headers.
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

	//Access-Control-Allow-Headers
	s.Result.ReqData.Methods = utils.ParseMethods(resp.Header.Get("Access-Control-Request-Method"))

	s.Result.ReqData.Headers = utils.ParseHeaders(resp.Header.Get("Access-Control-Request-Headers"))

}

func checkNullOriginAllowed(acao string) (bool, string) {
	if acao == "null" {
		detail := "Null origin allowed in ACAO header."
		return true, detail
	}
	return false, ""
}
