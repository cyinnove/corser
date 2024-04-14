package utils

import (
	"fmt"
	"strings"
)

func ParseHeader(header string) (key, value string, err error) {
	parts := strings.SplitN(header, ":", 2) // SplitN ensures we only split on the first colon
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format")
	}

	key = strings.TrimSpace(parts[0])   // Remove whitespace around the key
	value = strings.TrimSpace(parts[1]) // Remove whitespace around the value
	return key, value, nil
}

func ParseMethods(methods string) []string {
	return strings.Split(methods, ",")
}

func ParseHeaders(methods string) []string {
	return strings.Split(methods, ",")
}