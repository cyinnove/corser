package main

import (
    "regexp"
    "testing"
)

func TestValidURLs(t *testing.T) {
    validURLs := []string{
        "https://target.com",
        "http://target.com",
        "https://www.target.com",
        "https://subdomain.target.com",
		// payload
		"https://evil.com/https://zomasec.target.com",
    }

    pattern := regexp.MustCompile(`(https?://)([^/@]+@)?(.*\.)?target\.com`)

    for _, url := range validURLs {
        if !pattern.MatchString(url) {
            t.Errorf("URL '%s' should match the pattern but it didn't.", url)
        }
    }
}

func TestInvalidURLs(t *testing.T) {
    invalidURLs := []string{
        "https://example.com",
        "http://example.com",
        "https://subdomain.target.org",
        "https://subdomain.example.com",
    }

    pattern := regexp.MustCompile(`(https?://)([^/@]+@)?(.*\.)?target\.com`)

    for _, url := range invalidURLs {
        if pattern.MatchString(url) {
            t.Errorf("URL '%s' should not match the pattern but it did.", url)
        }
    }
}
