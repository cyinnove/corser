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
	s.Payloads = append(s.Payloads, "https://zomasec.io")
}

func (s *Scanner) Prefix() {

	org, _ := NetParser(s.Origin)
	
	// payload => https://target.com.zomasec.io
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s.%s", s.Host.Domain, s.Host.TLD, org.Full))
	
}

func (s *Scanner) Wildcard() {
	org, _ := NetParser(s.Origin)
	// Don't forget to use netParser
	// payload => https://zomasec.io/sub.target.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s/%s", org.Full, s.Host.Full)) 

}

func (s *Scanner) Suffix() {
	org, _ := NetParser(s.Origin)

	// Don't forget to use netParser
	// payload => https://zomasec.io.target.com
	s.Payloads = append(s.Payloads,  fmt.Sprintf("https://%s.%s%s", org.Full ,s.Host.Domain, s.Host.TLD))
	
}

func (s *Scanner) Null() {
	s.Payloads = append(s.Payloads, "null")
}

func (s *Scanner) UserAtDomain() {
	org, _ := NetParser(s.Origin)

	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s@%s", s.Host.Full, org.Full))
}

func (s *Scanner) SpecialChars() {
	org, _ := NetParser(s.Origin)
	// Remove some of them if they will do the same thing
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	// payload : https://website.com`.attacker.com/
		for _, char := range chars {
			s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s.%s",s.Host.Full, char, org.Full))	
		}
}


