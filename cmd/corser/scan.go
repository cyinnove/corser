package main

import (
	"os"

	"github.com/cyinnove/corser/pkg/config"
	"github.com/cyinnove/corser/pkg/runner"
	"github.com/cyinnove/logify"
)

func runScan(options *config.Options) {
	if options.URL != "" && len(options.URLs) == 0 {
		options.URLs = append(options.URLs, options.URL)
	}

	if len(options.URLs) == 0 {
		logify.Fatalf("No URLs provided to scan.")
		os.Exit(1)
	}

	r := runner.NewRunner(*options)
	err := r.Start()
	if err != nil {
		logify.Fatalf("Error running scan: %s\n", err.Error())
		os.Exit(1)
	}
}
