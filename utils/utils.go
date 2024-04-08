package utils

import (
	"os"
	"fmt"
	"bufio"
	"strings"
	"github.com/zomasec/logz"

)

var (
	logger = logz.DefaultLogs()
)

func ReadFileLines(fileName string ) []string {
	lines := make([]string, 0)
	
	file, err := os.Open(fileName)
	
	if err != nil {
		logger.ERROR("Failed to open file: %s\n", err)
		os.Exit(1)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		logger.ERROR("Failed to read file: %s\n", err)
		
	}
	return lines
}

func ParseHeader(header string) (key, value string, err error) {
	parts := strings.SplitN(header, ":", 2) // SplitN ensures we only split on the first colon
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format")
	}

	key = strings.TrimSpace(parts[0])   // Remove whitespace around the key
	value = strings.TrimSpace(parts[1]) // Remove whitespace around the value
	return key, value, nil
}