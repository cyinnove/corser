package main

import (
    "flag"
    "fmt"
    "os"
    "strings"
    "corser/runner" // Make sure this import path is correct for your project.
	"corser/utils"
)

func parseHeaders(headerStr string) map[string]string {
    headers := make(map[string]string)
    pairs := strings.Split(headerStr, ",")
    for _, pair := range pairs {
        parts := strings.SplitN(pair, ":", 2)
        if len(parts) == 2 {
            headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
        }
    }
    return headers
}

func main() {
    // Define flags
    urlFlag := flag.String("url", "", "URL to scan for CORS misconfigurations.")
    fileFlag := flag.String("file", "", "File containing URLs to scan, one per line.")
    originFlag := flag.String("origin", "http://example.com", "Origin header value to use in the scan.")
    headersFlag := flag.String("headers", "", "Comma-separated list of custom headers to include in the scan. Format: key:value,key2:value2")

    // Parse the flags
    flag.Parse()

    // Parse custom headers if provided
    headers := parseHeaders(*headersFlag)

    // URLs slice to hold either single URL or URLs from the file
    var urls []string

    // Check if the file flag is provided
    if *fileFlag != "" {
       urls = append(urls, utils.ReadFileLines(*fileFlag)...)
    } else if *urlFlag != "" {
        // Single URL provided
        urls = append(urls, *urlFlag)
    } else {
        fmt.Println("Usage: cors-scanner -url <URL> or cors-scanner -file <file path> [-origin <Origin>] [-headers <Headers>]")
        flag.PrintDefaults()
        os.Exit(1)
    }

    // Run the scanner for the URLs
    r := runner.NewRunner(urls, *originFlag, headers) // Adjust NewRunner accordingly.
    err := r.Start()
    if err != nil {
        fmt.Printf("Error running scan: %s\n", err)
        os.Exit(1)
    }
}
