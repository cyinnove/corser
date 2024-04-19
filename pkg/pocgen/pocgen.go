package pocgen

import (
	"bytes"
	"github.com/zomasec/corser/templates"
	"html/template"
	"os"
)

// Config holds the configuration for the PoC generator.
type Config struct {
	Method           string
	TargetURL        string
	Params           string
	SetRequestHeader string
	CustomOrigin     string // This field can dictate which template to use
}

// GeneratePoC generates an HTML page as a string that acts as a PoC for CORS misconfigurations.
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
func SavePoCToFile(config *Config, filename string) error {
	html, err := GeneratePoC(config)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, []byte(html), 0644)
}

// package pocgen

// import (
// 	"bytes"
// 	"html/template"
// 	"github.com/zomasec/corser/templates"
// 	"os"
// )

// // Config holds the configuration for the PoC generator.
// type Config struct {
// 	Method           string
// 	TargetURL        string
// 	Params           string
// 	SetRequestHeader string
// 	CustomOrigin     string
// }

// // GeneratePoC generates an HTML page as a string that acts as a PoC for CORS misconfigurations.
// func GeneratePoC(config *Config) (string, error) {

// 	tmpl := template.New("Poc-File")
// 	tmpl.Parse(templates.POC)
// 	var html bytes.Buffer
// 	if err := tmpl.Execute(&html, config); err != nil {
// 		return "", err
// 	}

// 	return html.String(), nil
// }

// // SavePoCToFile saves the generated PoC HTML to a specified file.
// func SavePoCToFile(config *Config, filename string) error {
// 	html, err := GeneratePoC(config)
// 	if err != nil {
// 		return err
// 	}

// 	return os.WriteFile(filename, []byte(html), 0644)
// }
