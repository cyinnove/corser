package pocgen

import (
	"bytes"
	"html/template"
	"github.com/zomasec/corser/templates"
	"os"
)

// Config holds the configuration for the PoC generator.
type Config struct {
	Method           string
	TargetURL        string
	Params           string
	SetRequestHeader string
	CustomOrigin     string 
}

// GeneratePoC generates an HTML page as a string that acts as a PoC for CORS misconfigurations.
func GeneratePoC(config *Config) (string, error) {

	tmpl := template.New("Poc-File")
	tmpl.Parse(templates.POC)
	var html bytes.Buffer
	if err := tmpl.Execute(&html, config); err != nil {
		return "", err
	}

	return html.String(), nil
}

// SavePoCToFile saves the generated PoC HTML to a specified file.
func SavePoCToFile(config *Config, filename string) error {
	html, err := GeneratePoC(config)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(html), 0644)
}
