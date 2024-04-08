package requester

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zomasec/tld"
)


type Request struct {
	Request   *http.Request
	Cookies   string
	Header    string
	Method    string
	Origin    string
	Timeout   time.Duration
	httpClient *http.Client // Add an internal HTTP client
}

func NewRequester(method, header, origin, cookies string, timeout int) *Request {
    // Create the http.Request object here. Adjust as necessary for your use case.
    // For demonstration, I'm using a dummy URL. Replace "http://example.com" with your target URL or pass it as a parameter.
    req, err := http.NewRequest(method, "http://example.com", nil)
    if err != nil {
        // Handle error (for now, just print it)
        fmt.Printf("Failed to create HTTP request: %v\n", err)
        return nil
    }

    // Assuming cookies are passed as a string and need to be added to the request.
    // If your use case differs, adjust accordingly.
    if cookies != "" {
        req.Header.Set("Cookie", cookies)
    }

    return &Request{
        Request:    req,
        Method:     method,
        Header:     header,
        Cookies:    cookies,
        Origin:     origin,
        Timeout:    time.Duration(timeout) * time.Second,
        httpClient: nil, // This will be initialized when SetClient is called.
    }
}



func (r *Request) ScanTester(client *http.Client, URL string, wildcard bool) {
	parts, err := netParser(URL)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(7)

	go func() {
		defer wg.Done()
		r.requester(client, URL, anyOrigin(wildcard))
	}()

	go func() {
		defer wg.Done()
		r.requester(client, URL, prefix(parts))
	}()

	go func() {
		defer wg.Done()
		r.requester(client, URL, suffix(parts))
	}()

	go func() {
		defer wg.Done()
		r.requester(client, URL, notEscapeDot(parts))
	}()

	go func() {
		defer wg.Done()
		r.requester(client, URL, null())
	}()

	go func() {
		defer wg.Done()
		r.requester(client, URL, thirdParties())
	}()

	go func() {
		defer wg.Done()
		r.requester(client, URL, specialChars(parts))
	}()

	wg.Wait()
}

func (r *Request) requester(client *http.Client, URL string, origins []string) {
    
	var mutex sync.Mutex 
	
	if client == nil || r.Request == nil {
        fmt.Println("HTTP client or Request is nil, cannot proceed with the request")
        return
    }

    for _, origin := range origins {
        mutex.Lock() // Lock before modifying the request
        r.addMethod()
        r.Request.Header.Set("Origin", origin)

        if err := r.addCustomHeader(); err != nil {
            fmt.Printf("Error adding custom header: %s\n", err)
            mutex.Unlock() // Unlock even if there's an error
            continue
        }
        mutex.Unlock() // Unlock after modifications are done

        resp, err := client.Do(r.Request)
        if err != nil {
            fmt.Printf("Error sending request to %s: %s\n", URL, err)
            continue
        }

        // Ensure we read the response body and close it to free resources
        _, err = io.Copy(io.Discard, resp.Body)
        if err != nil {
            fmt.Println("Error discarding response body:", err)
        }
        resp.Body.Close()

        ACAOHeader := resp.Header.Get("Access-Control-Allow-Origin")
        ACACHeader := resp.Header.Get("Access-Control-Allow-Credentials")

        if ACAOHeader == origin {
            fmt.Printf("[+] Misconfiguration found! => URL: %s\n", URL)
            if ACACHeader == "true" {
                fmt.Printf("[+] Access-Control-Allow-Credentials: %s\n", ACACHeader)
            }
        }
    }
}



func (r *Request) addCustomHeader() error {
    // No headers to add, not necessarily an error.
    if r.Header == "" {
        return nil // Early exit if there are no custom headers to add.
    }

    if r.Request == nil {
        return fmt.Errorf("http.Request is nil")
    }

    // Split the header string on newline, then iterate through each line to add headers.
    headers := strings.Split(r.Header, "\\n")
    for _, header := range headers {
        parts := strings.SplitN(header, ":", 2)
        if len(parts) != 2 {
            // If any header doesn't conform to "key: value", return an error.
            return fmt.Errorf("header parsing failed for: %s", header)
        }
        key := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])
        r.Request.Header.Add(key, value)
    }

    return nil
}


func (r *Request) addMethod() {
	if r.Request != nil && r.Request.Method != r.Method {
		r.Request.Method = r.Method
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

func specialChars(parts []string) []string {
	var origins []string
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	for _, char := range chars {
		origin := fmt.Sprintf("https://%s.%s.%s%s.zomasec.io", parts[0], parts[1], parts[2], char)
		origins = append(origins, origin)
	}
	return origins
}


// getClient ensures that the Request has a valid *http.Client, initializing a default one if none is set.
func (r *Request) SetClient() *http.Client {
	if r.httpClient == nil {
		// Lazily initialize the default client
		r.httpClient = &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:    30,
				IdleConnTimeout: 750 * time.Millisecond,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: r.Timeout,
		}
	}
	return r.httpClient
}

