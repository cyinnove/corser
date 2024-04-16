package utils

import (
    "strings"
)

func ElementExists(slice []string, element string) bool {
    for _, v := range slice {
        if v == element {
            return true
        }
    }
    return false
}

func RemoveANSICodes(input string) string {

	input = strings.ReplaceAll(input, `\u001b[0;32m`, "")

	input = strings.ReplaceAll(input, `\u001b[0m`, "")
	return input
}