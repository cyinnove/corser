package main

import (
	"flag"
	"os"

	"github.com/zomasec/logz"
	"corser/runner"
)

var logger = logz.DefaultLogs()

func main() {
	cLevel := flag.Int("c", 30, "Concurrency level or the number of workers to use.")
	checkWildcard := flag.Bool("wc", false, "Enable to check the wildcard in Access-Control-Allow-Origin.")
	header := flag.String("H", "", "Custom header added to each request.")
	method := flag.String("m", "GET", "Specific method name requested with it in each request.")
	cookies := flag.String("cookies", "", "Add cookies to each request to access authenticated pages.")
	origin := flag.String("origin", "zomasec.io", "Add custom origin.")
	list := flag.String("l", "", "List of URLs to scan.")
	timeout := flag.Int("timeout", 5, "Timeout for each request in seconds.")

	flag.Parse()

	// Initialize the runner
	runner := runner.NewRunner()

	// Load URLs from file or stdin
	if *list != "" {
		if err := runner.ReadURLsFromFile(*list); err != nil {
			logger.FATAL("Error reading from a file %s, %v\n", *list, err)
			os.Exit(1) // Exit the program on fatal errors
		}
	} else {
		if err := runner.ReadURLsFromStdin(); err != nil {
			logger.FATAL("Error reading from Stdin: %v\n", err)
			os.Exit(1) // Exit the program on fatal errors
		}
	}

	// Execute the scan
	runner.RunScan(*cLevel, *checkWildcard, *method, *header,*origin, *cookies, *timeout)
}
