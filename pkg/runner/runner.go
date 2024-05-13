package runner

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/elazarl/goproxy"
	"github.com/zomasec/corser/pkg/config"
	"github.com/zomasec/corser/pkg/corser"
	"github.com/zomasec/corser/pkg/pocgen"
	"github.com/zomasec/corser/pkg/utils"
	"github.com/zomasec/logz"
)

var (
	logger  = logz.DefaultLogs()
	userLog = logz.DefaultLogs()
)

// Runner coordinates scans, now also includes origin and headers for customization.
type Runner struct {
	URLs       []string
	Origin     string
	Method     string
	Cookies    string
	DeepScan   bool
	Verbose    bool
	Timeout    int
	CLevel     int
	Header     string
	PocFile    string
	OutputFile string
	Output     *Output
}

type Output struct {
	Results []*corser.Result `json:"result"`
}

func (r *Runner) parseResultToJSON() error {

	jsonData, err := json.MarshalIndent(r.Output, "", "  ")
	if err != nil {
		logger.ERROR("Error Marshaling the output file")
		return err
	}

	if err := utils.OutputJSONFile(r.OutputFile, utils.RemoveANSICodes(string(jsonData))); err != nil {
		return err
	}

	return nil
}

// NewRunner creates a new Runner instance capable of scanning multiple URLs with custom settings.
func NewRunner(opions config.Options) *Runner {
	return &Runner{
		URLs:       opions.URLs,
		Origin:     opions.Origin,
		Method:     opions.Method,
		Cookies:    opions.Cookies,
		Timeout:    opions.Timeout,
		CLevel:     opions.Concurrency,
		DeepScan:   opions.IsDeep,
		Verbose:    opions.Verbose,
		Header:     opions.Header,
		OutputFile: opions.OutputFile,
		PocFile:    opions.PocFile,
		Output: &Output{
			Results: make([]*corser.Result, 0),
		},
	}
}

// Start begins the scanning process for all provided URLs with the specified origin and headers.
func (r *Runner) Start() error {
	var wg sync.WaitGroup
	clevel := make(chan struct{}, r.CLevel)

	logger.ErrorEnabled = r.Verbose
	logger.DebugEnabled = r.Verbose

	for _, url := range r.URLs {
		clevel <- struct{}{}
		wg.Add(1)

		go func(u string) {
			defer wg.Done()
			defer func() { <-clevel }()

			scanner := corser.NewScanner(u, r.Method, r.Header, r.Origin, r.Origin, r.DeepScan, r.Timeout)
			result := scanner.Scan()

			if result.Vulnerable && len(result.Details) > 0 {
				if r.OutputFile != "" {

					r.Output.Results = append(r.Output.Results, result)
				}

				logz.NewLogger("vuln", logz.Blue, result.URL).Log()
				for _, detail := range result.Details {
					fmt.Printf("\t %s-%s %s%s%s\n", logz.Yellow, logz.NC, logz.Green, detail, logz.NC)
				}

				// Generate PoC HTML and save it to a file
				if r.PocFile != "" {
					pocConfig := &pocgen.Config{
						Method:           r.Method,
						TargetURL:        u,
						SetRequestHeader: r.Header,
						CustomOrigin:     r.Origin,
					}

					filename := r.PocFile

					if err := pocgen.SavePoCToFile(pocConfig, filename); err != nil {
						userLog.ERROR("Error generating PoC: %v", err)
					} else {
						logger.INFO("PoC saved to %s", filename)
					}
				}
			}

			if result.ErrorMessage != "" {
				logger.ERROR("%s", result.ErrorMessage)
			}

		}(url)
	}

	wg.Wait()

	if r.OutputFile != "" {
		if err := r.parseResultToJSON(); err != nil {
			userLog.ERROR("Error cannot create the file to output result in it : %s", err.Error())
		}
	}

	return nil
}

func StartProxyServer(options config.ProxyOptions) {
	proxy := goproxy.NewProxyHttpServer()
	// Enable MITM and disable TLS certificate checking
	proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return goproxy.OkConnect, host
	}))

	// Customize the proxy's transport to ignore certificate errors
	proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Define your request handling logic
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			logger.ErrorEnabled = options.Verbose
			logger.DebugEnabled = options.Verbose

			logger.DEBUG("%s", r.RequestURI)
			logger.DEBUG("%s", r.URL.String())
			scanner := corser.NewScanner(r.URL.String(), r.Method, "", options.Origin, utils.CookiesToString(r), options.IsDeep, options.Timeout)
			result := scanner.Scan()

			if result.Vulnerable && len(result.Details) > 0 {
				logz.NewLogger("vuln", logz.Blue, result.URL).Log()
				for _, d := range result.Details {
					fmt.Printf("\t %s-%s %s%s%s\n", logz.Yellow, logz.NC, logz.Green, d, logz.NC)
				}
			}
			return r, nil
		})

	// Listen on the specified port set in options
	if err := http.ListenAndServe(fmt.Sprintf(":%d", options.Port), proxy); err != nil {
		logger.FATAL("Error while listening on port %d , change it to another port", options.Port)
		os.Exit(1)
	}
}
