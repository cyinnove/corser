package test

import (
	
	"net/http"
	"testing"

	"github.com/cyinnove/corser/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestParseHeader(t *testing.T) {
	tests := []struct {
		header       string
		expectedKey  string
		expectedValue string
		expectError  bool
	}{
		{"Content-Type: application/json", "Content-Type", "application/json", false},
		{"Authorization: Bearer token", "Authorization", "Bearer token", false},
		{"InvalidHeader", "", "", true},
		{"KeyWithoutValue:", "KeyWithoutValue", "", false},
		{":ValueWithoutKey", "", "ValueWithoutKey", false},
	}

	for _, test := range tests {
		key, value, err := utils.ParseHeader(test.header)
		if test.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expectedKey, key)
			assert.Equal(t, test.expectedValue, value)
		}
	}
}

func TestParseMethods(t *testing.T) {
	methods := "GET,POST,PUT,DELETE"
	expected := []string{"GET", "POST", "PUT", "DELETE"}
	result := utils.ParseMethods(methods)
	assert.Equal(t, expected, result)
}

func TestParseHeaders(t *testing.T) {
	headers := "Accept,Content-Type,Authorization"
	expected := []string{"Accept", "Content-Type", "Authorization"}
	result := utils.ParseHeaders(headers)
	assert.Equal(t, expected, result)
}

func TestCookiesToString(t *testing.T) {
	cookie1 := &http.Cookie{
		Name:   "session_id",
		Value:  "abc123",
		Path:   "/",
		Domain: "example.com",
		Secure: true,
	}

	request := &http.Request{
		Header: http.Header{
			"Cookie": []string{cookie1.String()},
		},
	}

	result := utils.CookiesToString(request)

	expectedParts := []string{
		"session_id=abc123; Path=/; Domain=example.com; Secure",
	}

	for _, part := range expectedParts {
		assert.Contains(t, result, part)
	}
}


func TestElementExists(t *testing.T) {
	tests := []struct {
		slice     []string
		element   string
		expected  bool
	}{
		{[]string{"apple", "banana", "cherry"}, "banana", true},
		{[]string{"apple", "banana", "cherry"}, "grape", false},
		{[]string{}, "banana", false},
		{[]string{"apple", "banana", "banana"}, "banana", true},
	}

	for _, test := range tests {
		result := utils.ElementExists(test.slice, test.element)
		assert.Equal(t, test.expected, result)
	}
}


