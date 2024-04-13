package corser

import (
	"testing"
	"github.com/stretchr/testify/assert"
)


func Test_Suffix(t *testing.T) {
	scan := &Scanner{
		Origin: "zomasec.io",
		Host: &Host{
			Domain: "target",
			Subdomains: "sub",
			TLD: "com",
		},
	}

	scan.Suffix()

	want := []string{"https://zomasec.io.target.com"}
	got := scan.Payloads



	assert.ElementsMatch(t, want, got, "Want %v but got %v", want, got)
} 

func TestPrefix(t *testing.T) {
	scan := &Scanner{
		Origin: "zomasec.io",
		Host: &Host{
			Domain: "target",
			Subdomains: "sub",
			TLD: "com",
		},
	}
	
	scan.Prefix()

	want := []string{"https://target.com.zomasec.io"}
	got := scan.Payloads


	assert.ElementsMatch(t, want, got, "Want %v but got %v", want, got)
}