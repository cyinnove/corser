package main

import (
	"os"

	"github.com/zomasec/corser/pkg/config"
	"github.com/zomasec/corser/pkg/runner"
)

func runScan(options *config.Options) {
	if options.URL != "" && len(options.URLs) == 0 {
		options.URLs = append(options.URLs, options.URL)
	}

	if len(options.URLs) == 0 {
		logger.FATAL("No URLs provided to scan.")
		os.Exit(1)
	}

	r := runner.NewRunner(*options)
	err := r.Start()
	if err != nil {
		logger.FATAL("Error running scan: %s\n", err.Error())
		os.Exit(1)
	}
}
