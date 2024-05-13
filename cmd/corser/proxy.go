package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/elazarl/goproxy"
)

func createProxyCmd(opts *options) *cobra.Command {
	var proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "Receives requests from an upstreaming proxy and scans them",
		Run: func(cmd *cobra.Command, args []string) {
			// Here you would add the logic to receive requests from the proxy,
			// scan them, and return the results to the user.
			// You can use the runScan function from [`cmd/corser/scan.go`](cmd/corser/scan.go) to perform the scan.
			runScan()
		},
	}


	proxyCmd.Flags().StringVarP(&opts.proxyAddress, "proxy", "p", "", "Specifies the address of the proxy server.")

	return proxyCmd
}

