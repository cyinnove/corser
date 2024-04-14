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
	if subdomain != "" {
		subdomain = fmt.Sprintf("%s.", subdomain)
	}

	domain := URL.Domain

	if domain != "" {
		domain = fmt.Sprintf("%s.", domain)

	}
	
	topLevelDomain := URL.TLD

	return &Host{
		Full: fmt.Sprintf("%s%s%s", subdomain, domain, topLevelDomain ),
		Domain: domain,
		TLD: topLevelDomain,
		Subdomain: subdomain,
	}, nil
}

func (s *Scanner) JoinTwoice() {
	org, _ := NetParser(s.Origin)
	// payload => https://zomasectarget.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s%s", org.Domain, s.Host.Domain, s.Host.TLD))
}


func (s *Scanner) anyOrigin() {
	s.Payloads = append(s.Payloads, "zomasec.io")
}

func (s *Scanner) Prefix() {
	
	// payload => https://target.com.zomasec.io
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s.%s", s.Host.Domain, s.Host.TLD, s.Origin))
	
}

func (s *Scanner) Wildcard() {
	
	// Don't forget to use netParser
	// payload => https://zomasec.io/sub.target.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s/%s",s.Origin, s.Host.Full)) 

}

func (s *Scanner) Suffix() {
	// Don't forget to use netParser
	// payload => https://zomasec.io.target.com
	s.Payloads = append(s.Payloads,  fmt.Sprintf("https://%s.%s%s", s.Origin,s.Host.Domain, s.Host.TLD))
	
}

func (s *Scanner) Null() {
	s.Payloads = append(s.Payloads, "null")
}

func (s *Scanner) UserAtDomain() {
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s@%s", s.Host.Full, s.Origin))
}

func (s *Scanner) SpecialChars() {
	// Remove some of them if they will do the same thing
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	// payload : https://website.com`.attacker.com/
		for _, char := range chars {
			s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s.%s",s.Host.Full, char, s.Origin))	
		}
}


