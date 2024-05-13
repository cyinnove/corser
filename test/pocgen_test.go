package pocgen

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/zomasec/corser/templates"
	"html/template"
	"os"
	"testing"
)

func TestGeneratePOC(t *testing.T) {
	// Test case 1
	t.Run("Test case 1", func(t *testing.T) {
		// Set up the test data
		var buf bytes.Buffer
		data := struct {
			Name string
		}{
			Name: "John",
		}

		// Generate the POC
		err := GeneratePOC(&buf, templates.Template1, data)
		assert.NoError(t, err)

		// Verify the output
		expected := "Hello, John!"
		actual := buf.String()
		assert.Equal(t, expected, actual)
	})

	// Test case 2
	t.Run("Test case 2", func(t *testing.T) {
		// Set up the test data
		var buf bytes.Buffer
		data := struct {
			Name string
		}{
			Name: "Jane",
		}

		// Generate the POC
		err := GeneratePOC(&buf, templates.Template2, data)
		assert.NoError(t, err)

		// Verify the output
		expected := "Welcome, Jane!"
		actual := buf.String()
		assert.Equal(t, expected, actual)
	})
}

func TestMain(m *testing.M) {
	// Set up any test dependencies here

	// Run the tests
	exitCode := m.Run()

	// Clean up any test dependencies here

	// Exit with the appropriate exit code
	os.Exit(exitCode)
}