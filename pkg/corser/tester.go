package corser

import (
	"fmt"
	"github.com/zomasec/tld"
)

func NetParser(url string) (*Host, error) {
	
	URL, err := tld.Parse(url)
	
	if err != nil {
		return nil, err
	}

	subdomain := URL.Subdomain
	domain := URL.Domain
	topLevelDomain := URL.TLD

	return &Host{
		Domain: domain,
		TLD: topLevelDomain,
		Subdomains: subdomain,
	}, nil
}

func (s *Scanner) anyOrigin() {
	s.Payloads = append(s.Payloads, "zomasec.io")

}

func (s *Scanner) Prefix() {
	// Don't forget to use netParser
	// payload => https://target.com.zomasec.io
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s.%s.%s", s.Host.Domain, s.Host.TLD, s.Origin))
	
}

func (s *Scanner) Wildcard() {
	
	// Don't forget to use netParser
	// payload => https://zomasec.io/sub.target.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s/%s.%s.%s",s.Origin, s.Host.Subdomains, s.Host.Domain, s.Host.TLD)) 
	
	// payload => https://zomasec.io/target.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s/%s.%s",s.Origin, s.Host.Domain, s.Host.TLD))
	
}

func (s *Scanner) Suffix() {
	// Don't forget to use netParser
	// payload => https://zomasec.io.target.com
	s.Payloads = append(s.Payloads,  fmt.Sprintf("https://%s.%s.%s", s.Origin,s.Host.Domain, s.Host.TLD))
	
}

func (s *Scanner) Null() {
	s.Payloads = append(s.Payloads, "null")
}

func (s *Scanner) SpecialChars() {
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	
		for _, char := range chars {
			s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s.%s%s.%s",s.Host.Domain, s.Host.TLD, char, s.Origin))	
		}
}


