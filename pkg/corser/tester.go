package corser

import (
	"fmt"

	"github.com/cyinnove/logify"
	"github.com/cyinnove/tldify"
)


// NetParser parses the given URL and returns a Host object containing the subdomain, domain, and top-level domain.
// If an error occurs during parsing, it returns nil and the error.
func NetParser(url string) (*Host, error) {

	URL, err := tldify.Parse(url)
	if err != nil {
		logify.Errorf("Error parsing the URL %s", url)
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
		Full:      fmt.Sprintf("%s%s%s", subdomain, domain, topLevelDomain),
		Domain:    domain,
		TLD:       topLevelDomain,
		Subdomain: subdomain,
	}, nil
}

// JoinTwoice joins the origin, host domain, and host TLD to create a payload URL.
// It appends the payload URL to the list of payloads in the Scanner.
func (s *Scanner) JoinTwoice() {
	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}

	// payload => https://zomasectarget.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s%s", org.Domain, s.Host.Domain, s.Host.TLD))
}

// anyOrigin appends a payload to the Scanner's Payloads slice.
func (s *Scanner) anyOrigin() {
	s.Payloads = append(s.Payloads, "https://zomasec.io")
}

// Prefix adds a prefix to the payloads based on the scanner's origin and host information.
func (s *Scanner) Prefix() {

	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}

	// payload => https://target.com.zomasec.io
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s.%s", s.Host.Domain, s.Host.TLD, org.Full))

}

// Wildcard generates a wildcard payload based on the scanner's origin and host.
// It appends the generated payload to the scanner's list of payloads.
func (s *Scanner) Wildcard() {
	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}

	// Don't forget to use netParser
	// payload => https://zomasec.io/sub.target.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s/%s", org.Full, s.Host.Full))
}

// Suffix appends a payload to the Scanner's Payloads slice.
// It constructs a payload URL using the origin, domain, and TLD of the Scanner's Host,
// and appends it to the Payloads slice.
func (s *Scanner) Suffix() {
	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}

	// Don't forget to use netParser
	// payload => https://zomasec.io.target.com
	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s.%s%s", org.Full, s.Host.Domain, s.Host.TLD))
}

// Null appends the string "null" to the list of payloads in the Scanner.
func (s *Scanner) Null() {
	s.Payloads = append(s.Payloads, "null")
}

// UserAtDomain appends a payload to the Scanner's Payloads slice
// in the format "https://<username>@<domain>".
func (s *Scanner) UserAtDomain() {
	org, _ := NetParser(s.Origin)

	s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s@%s", s.Host.Full, org.Full))
}

// SpecialChars generates payloads by appending special characters to the host URL.
// It removes some special characters if they will result in the same payload.
func (s *Scanner) SpecialChars() {
	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}

	// Remove some of them if they will do the same thing
	chars := []string{"_", "-", "{", "}", "^", "%60", "!", "~", "`", ";", "|", "&", "(", ")", "*", "'", "\"", "$", "=", "+", "%0b"}
	// payload : https://website.com`.attacker.com/
	for _, char := range chars {
		s.Payloads = append(s.Payloads, fmt.Sprintf("https://%s%s.%s", s.Host.Full, char, org.Full))
	}
}

// PortManipulation adds different ports to test origin handling
// PortManipulation generates payload URLs by appending different ports to the origin URL.
func (s *Scanner) PortManipulation() {
	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}

	ports := []string{"8080", "443", "80"}
	for _, port := range ports {
		portOrigin := fmt.Sprintf("https://%s:%s", org.Full, port)
		s.Payloads = append(s.Payloads, portOrigin)
	}
}

// SubdomainFlipping switches subdomain positions
// SubdomainFlipping generates payloads by flipping the subdomain of the origin URL.
// It appends the flipped origin URL to the list of payloads.
func (s *Scanner) SubdomainFlipping() {
	org, err := NetParser(s.Origin)
	if err != nil {
		return
	}
	flippedOrigin := fmt.Sprintf("https://%s%s.%s", org.TLD, org.Subdomain, org.Domain)
	s.Payloads = append(s.Payloads, flippedOrigin)
}
