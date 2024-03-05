package requester

import (
	"net/http"
	"strings"
	"regexp"
	"crypto/tls"
	"fmt"
	"io"
	"time"
	"github.com/zomasec/tld"
	
)
type Request struct {
	Request *http.Request
	Cookies string
	Header  string
	Method  string
	Origin  string
	Timeout time.Duration
}


func NewRequester(method string, header string, cookies string, timeout int) *Request {
	return &Request{Method: method, Header: header, Cookies: cookies, Timeout: time.Duration(timeout) * time.Second}
}



func (r *Request) SetClient() *http.Client {
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

func (r *Request) addCustomHeader() {
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

func (r *Request) addMethod() {
	// If the default request method for this request is not the user input method then add it
	if r.Request.Method != r.Method {
		r.Request.Method = r.Method
	}

}



func (r *Request) Requester(client *http.Client, URL string, origins []string) {

	for _, origin := range origins {
		r.addMethod()
		r.Request.Header.Set("Origin", origin)

		if r.Header != "" {
			r.addCustomHeader()
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

func (r *Request) ScanTester(client *http.Client, URL string, wildcard bool) {

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