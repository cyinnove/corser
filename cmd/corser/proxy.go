package main

import (
	"github.com/spf13/cobra"
	"github.com/cyinnove/corser/pkg/config"
	"github.com/cyinnove/corser/pkg/runner"
)

func createProxyCmd(options *config.ProxyOptions) *cobra.Command {
	var proxyCmd = &cobra.Command{
		Use:   "proxy",
		Short: "Receives requests from an upstreaming proxy and scan them, Ex: BurpSuite, ZAP ...",
		Run: func(cmd *cobra.Command, args []string) {
			// Here you would add the logic to receive requests from the proxy,
			// scan them, and return the results to the user.
			runner.StartProxyServer(*options)
		},
	}

	proxyCmd.Flags().IntVarP(&options.Port, "port", "p", 9090, "Specifies the port of the proxy server that will receive requests from burpsuite.")
	proxyCmd.Flags().StringVarP(&options.Origin, "origin", "O", "https://zomasec.io", "Sets the Origin header value to use in the scan requests.")
	proxyCmd.Flags().BoolVarP(&options.IsDeep, "deep-scan", "d", false, "Enable deep scan for more advanced CORS bypass techniques.")
	proxyCmd.Flags().BoolVarP(&options.Verbose, "verbose", "v", false, "Enable verbose mode for detailed logs.")

	return proxyCmd
}
