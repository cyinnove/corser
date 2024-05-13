package config

type Options struct {
	URLs        []string
	URL         string
	Method      string
	Timeout     int
	Concurrency int
	Cookies     string
	File        string
	OutputFile  string
	IsDeep      bool
	Origin      string
	Header      string
	Verbose     bool
	PocFile     string
}

type ProxyOptions struct {
	Port    int
	Timeout int
	IsDeep  bool
	Origin  string
	Verbose bool
}
