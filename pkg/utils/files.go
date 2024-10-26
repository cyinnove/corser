package utils

import (
	"fmt"
	"os"

	"bufio"
	"strings"

	"github.com/cyinnove/logify"
	"github.com/zomasec/logz"
)

var (
	Logger = logz.DefaultLogs()
)

func ReadFileLines(fileName string) []string {
	lines := make([]string, 0)

	file, err := os.Open(fileName)

	if err != nil {
		logify.Errorf("Failed to open file: %s\n", err)
		os.Exit(1)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if scanner.Text() != "" {
			lines = append(lines, strings.TrimSpace(scanner.Text()))
		}

	}

	if err := scanner.Err(); err != nil {
		logify.Errorf("Failed to read file: %s\n", err)

	}
	return lines
}

func OutputJSONFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = fmt.Fprint(file, data)
	if err != nil {
		return err
	}

	return nil
}

func ReadURLsFromStdin() []string {
	scanner := bufio.NewScanner(os.Stdin)
	var urls []string
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
		os.Exit(1)
	}
	return urls
}
