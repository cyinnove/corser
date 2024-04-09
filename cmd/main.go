package main

import (
    "flag"
    "fmt"
    "os"
    "github.com/zomasec/corser/runner" 
	"github.com/zomasec/corser/utils"
)



func main() {

    urlFlag := flag.String("url", "", "Specifies the URL to scan for CORS misconfigurations.")
    methodFlag := flag.String("method", "GET", "Specifies the HTTP method to use when sending requests.")
    timeoutFlag := flag.Int("timeout", 5, "Sets the timeout (in seconds) for each request.")
    clevelFlag := flag.Int("c", 10, "Determines the concurrency level, i.e., the number of concurrent requests to make.")
    cookieFlag := flag.String("cookie", "", "Defines cookies to include in the scan requests. Format as a single string (e.g., 'sessionId=abc123; token=xyz').")
    fileFlag := flag.String("l", "", "Specifies a file path containing URLs to scan, with one URL per line.")
    originFlag := flag.String("origin", "http://zomasec.io", "Sets the Origin header value to use in the scan requests.")
    headerFlag := flag.String("header", "", "Specifies additional headers to include in the scan requests. Format as a single string (e.g., 'X-Custom-Header=Value').")
    // pocFlag := flag.Bool("poc", false, "Generate poc for any vuln request with the name of the url, result found  ")
    // pocFileFlag := flag.String("pf")

    flag.Parse()
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
    r := runner.NewRunner(urls, *methodFlag, *headerFlag, *originFlag, *cookieFlag, *timeoutFlag, *clevelFlag) 
    err := r.Start()
    if err != nil {
        fmt.Printf("Error running scan: %s\n", err)
        os.Exit(1)
    }
}
