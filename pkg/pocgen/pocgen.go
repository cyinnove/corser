package pocgen

import (
	"bytes"
	"github.com/cyinnove/corser/templates"
	"html/template"
	"os"
)

// Config holds the configuration for the PoC generator.
// Config represents the configuration for generating proof-of-concept (PoC) code.
type Config struct {
	Method           string // HTTP method to be used for the request.
	TargetURL        string // Target URL for the request.
	Params           string // Parameters to be included in the request.
	SetRequestHeader string // Custom request headers to be set.
	CustomOrigin     string // Custom origin to be used for the request.
}

// GeneratePoC generates an HTML page as a string that acts as a PoC for CORS misconfigurations.
// GeneratePoC generates a Proof of Concept (PoC) based on the provided configuration.
// It takes a pointer to a Config struct as input and returns the generated PoC as a string.
// If an error occurs during the generation process, it returns an empty string and the error.
func GeneratePoC(config *Config) (string, error) {
	var tmpl *template.Template
	var err error

	// Choose the template based on the CustomOrigin value
	if config.CustomOrigin == "null" {
		tmpl, err = template.New("POCNull-File").Parse(templates.POCNull)
	} else {
		tmpl, err = template.New("POC-File").Parse(templates.POC)
	}

	if err != nil {
		return "", err
	}

	var html bytes.Buffer
	if err := tmpl.Execute(&html, config); err != nil {
		return "", err
	}

	return html.String(), nil
}

// SavePoCToFile saves the generated PoC HTML to a specified file.
// SavePoCToFile saves the generated Proof of Concept (PoC) HTML content to a file.
// It takes a pointer to a Config struct and a filename as input parameters.
// It returns an error if there was an issue generating the PoC or writing it to the file.
func SavePoCToFile(config *Config, filename string) error {
	html, err := GeneratePoC(config)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(html), 0644)
}
