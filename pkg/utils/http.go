package utils

import (
	"fmt"
	"net/http"
	"strings"
)

func ParseHeader(header string) (key, value string, err error) {
	parts := strings.SplitN(header, ":", 2) // SplitN ensures we only split on the first colon
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format")
	}

	key = strings.TrimSpace(parts[0])   // Remove whitespace around the key
	value = strings.TrimSpace(parts[1]) // Remove whitespace around the value
	return key, value, nil
}

func ParseMethods(methods string) []string {
	return strings.Split(methods, ",")
}

func ParseHeaders(methods string) []string {
	return strings.Split(methods, ",")
}


// CookiesToString formats the cookies from an HTTP request into a detailed string
func CookiesToString(request *http.Request) string {
	var cookieStrs []string
	cookies := request.Cookies()
	for _, cookie := range cookies {
		parts := []string{fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)}
		if cookie.Path != "" {
			parts = append(parts, fmt.Sprintf("Path=%s", cookie.Path))
		}
		if cookie.Domain != "" {
			parts = append(parts, fmt.Sprintf("Domain=%s", cookie.Domain))
		}
		if cookie.Secure {
			parts = append(parts, "Secure")
		}
		if cookie.HttpOnly {
			parts = append(parts, "HttpOnly")
		}
		if !cookie.Expires.IsZero() {
			parts = append(parts, fmt.Sprintf("Expires=%s", cookie.Expires.Format(time.RFC1123)))
		}
		if cookie.MaxAge > 0 {
			parts = append(parts, fmt.Sprintf("Max-Age=%d", cookie.MaxAge))
		}
		cookieStrs = append(cookieStrs, strings.Join(parts, "; "))
	}
	return strings.Join(cookieStrs, "; ")
}
