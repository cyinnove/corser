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

var logger = logz.DefaultLogs()

type Result struct {
	URL          string
	Vulnerable   bool
	Payload		 string
	Details      []string
	ErrorMessage string
}

type Scanner struct {
	URL     string
	Origin  string
	Method  string
	Cookies string
	Header  string
	DeepScan bool
	Payloads []string 
	Timeout int
	Host    *Host
	//ReqData	*PreFlightData
	Client *http.Client
	
}
// type PreFlightData struct{
// 	ACAO string
// 	ACAC string
// 	Headers []string
// 	Methods []string

// }

type Host struct {
	Full 	   string
	Domain     string
	TLD        string
	Subdomain string
}

func NewScanner(url, method, header, origin, cookies string,isDeep bool, timeout int) *Scanner {
	
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
		URL:     url,
		Origin:  origin,
		Method: method,
		Cookies: cookies,
		Timeout: timeout,
		Header: header,
		DeepScan: isDeep,
		Client: &client,
		// ReqData: &PreFlightData{
		// 	Methods: make([]string, 0),
		// 	Headers: make([]string, 0),
		// },
	}
}

func (s *Scanner) Scan() *Result {

	result := &Result{URL: s.URL}
	s.preflightRequest(result)

	
	if result.ErrorMessage != "" {
		return &Result{
			URL: s.URL,
			Vulnerable: false,
			Details: []string{},
			ErrorMessage: fmt.Sprintf("URL not alive or an error in request : %s", result.ErrorMessage),
		}
	}

	s.RequestCheck(result)
	
	
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
			s.performRequest(origin, result, &mutex)
		}(payload)
	}
	wg.Wait()
}

func (s *Scanner) performRequest(payload string, result *Result, mutex *sync.Mutex) {
	
	
	req, err := http.NewRequest(s.Method, s.URL, nil)
	if err != nil {
		mutex.Lock()
		result.ErrorMessage = fmt.Sprintf("Error creating request: %s", err.Error())
		mutex.Unlock()
		return
	}

	req.Header.Add("Origin", payload)
	
	if s.Header != "" {
		key, value, err := utils.ParseHeader(s.Header)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Error formating error: %s", err.Error())
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
		result.ErrorMessage = fmt.Sprintf("Error performing request: %s", err.Error())
		mutex.Unlock()
		return
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
    if err != nil {
		result.ErrorMessage = err.Error()
		return 
    }

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	
	vulnerable, details := evaluateResponse(payload, acao, acac)
	if vulnerable {
		mutex.Lock()
		result.Vulnerable = true
		result.Payload = payload
		result.Details = append(result.Details, details...)
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
	var detail  string
	if acao == payload || acac == "true" {
		
		if acac == "" {
			detail = fmt.Sprintf("%sACAO Header:%s %s",logz.Green, logz.NC, acao)
		} else {
			detail = fmt.Sprintf("%sACAO Header:%s %s, ACAC Header: %s",logz.Green, logz.NC, acao, acac)
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
func (s *Scanner) preflightRequest(result *Result) {
	
	req, err := http.NewRequest("OPTIONS", s.URL, nil)
	if err != nil {
		result.ErrorMessage = err.Error()
		return 
	}

	
	resp, err := s.Client.Do(req)
	if err != nil {
		result.ErrorMessage = err.Error()
		return 
	}
	defer resp.Body.Close()

	_, err = io.Copy(io.Discard, resp.Body)
    if err != nil {
		result.ErrorMessage = err.Error()
		return 
    }


	//##############
	//#
	//# Will be used in the nexet version 
	//#
	//##############
	// s.ReqData.ACAO = resp.Header.Get("Access-Control-Allow-Origin")
	// s.ReqData.ACAC = resp.Header.Get("Access-Control-Allow-Credentials")

	// //Access-Control-Allow-Headers
	// s.ReqData.Methods = utils.ParseMethods(resp.Header.Get("Access-Control-Request-Method"))

	// s.ReqData.Headers = utils.ParseHeaders(resp.Header.Get("Access-Control-Request-Headers"))

		
}

func checkNullOriginAllowed(acao string) (bool, string) {
	if acao == "null" {
		detail := "Null origin allowed in ACAO header."
		return true, detail
	}
	return false, ""
}


