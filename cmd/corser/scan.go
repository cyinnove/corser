package main

import (
	"fmt"
	"os"
	"github.com/zomasec/corser/runner"
)

func runScan(urls []string, opts *options) {
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "No URLs provided to scan.")
		return
	}
	r := runner.NewRunner(urls, opts.method, opts.header, opts.origin, opts.cookie, opts.deepScan, opts.verbose, opts.timeout, opts.concurrency, opts.pocFile, opts.outputFile)
	err := r.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running scan: %s\n", err)
		os.Exit(1)
	}
}
