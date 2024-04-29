<p align="center">
  <a href="https://pkg.go.dev/github.com/zomasec/corser/pkg/corser"><img src="https://pkg.go.dev/badge/github.com/zomasec/corser.svg"></a>
<!--   <a href="https://goreportcard.com/report/github.com/zomasec/corser"><img src="https://goreportcard.com/badge/github.com/zomasec/corser"></a> -->
  <a href="https://codecov.io/gh/zomasec/corser"><img src="https://codecov.io/gh/zomasec/corser/branch/main/graph/badge.svg"/></a>
  <a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/zomasec?style=flat&logo=x"></a>
</p>

![CORSER](./static/corser-logo.png)

## Corser: Scanner For Advanced CORS Misconfiguration Detection

Welcome to the GitHub repository for **Corser**, a powerful command-line tool designed for detecting CORS misconfigurations in web applications. Corser is developed with the goal of providing security professionals and developers with an efficient means to identify and exploit CORS issues.

## Installation

Install Corser using the following command:

    go install -v github.com/zomasec/corser/cmd/corser@latest

## Features

- **Single URL Scan:** Perform a CORS scan on a specified URL.
- **Multiple URL Scan:** Perform CORS scans on multiple URLs from a specified file.

## Usage

Run Corser with the desired commands and options:

    corser [command] [flags]
    corser help # this for help 

### Available Subcommands

- `completion` Generate the autocompletion script for the specified shell.
- `help` Help about any command.
- `multi` Performs scans on multiple URLs from a specified file.
- `single` Performs a scan on a single specified URL.

### Flags for `single` Command

| Flag         | Description                                                      |
|--------------|------------------------------------------------------------------|
| `-g, --gen-poc`  | Generate a PoC for any vulnerable request with the name of the URL and result found. |
| `-h, --help`     | Help for single command.                                         |
| `-u, --url`      | Specifies the URL to scan for CORS misconfigurations.            |

### Flags for `multi` Command

| Flag         | Description                                                      |
|--------------|------------------------------------------------------------------|
| `-h, --help`     | Help for multi command.                                          |
| `-l, --list`     | Specifies a file path containing URLs to scan, with one URL per line. |
| `-o, --output`   | Specifies the output file path where results should be saved.    |

### Global Flags

| Flag         | Default        | Description                                             |
|--------------|----------------|---------------------------------------------------------|
| `-c, --concurrency` | 10             | Determines the concurrency level.                        |
| `-k, --cookie`      |                | Defines cookies to include in the scan requests.        |
| `-d, --deep-scan`   | false          | Enable deep scan for more advanced CORS bypass techniques. |
| `-H, --header`      |                | Specifies additional headers to include in the scan requests. |
| `-m, --method`      | "GET"          | Specifies the HTTP method to use when sending requests. |
| `-O, --origin`      | "http://zomasec.io" | Sets the Origin header value to use in the scan requests. |
| `-t, --timeout`     | 5              | Sets the timeout (in seconds) for each request.         |
| `-v, --verbose`     | false          | Enable verbose mode for detailed logs.                  |

### Sample Command Usage

- Single URL Scan:
  
      ./corser single --url "http://example.com"

- Multiple URL Scan:

      ./corser multi --list "./url_list.txt" --output "./results.txt"

## Additional Information
```
     ____ ___  ____  ____  _____ ____  
    / ___/ _ \|  _ \/ ___|| ____|  _ \ 
   | |  | | | | |_) \___ \|  _| | |_) |
   | |__| |_| |  _ < ___) | |___|  _ < 
    \____\___/|_| \_\____/|_____|_| \_\   v1.0.0 #Free_Palestine 
```
- **Developer:** @zomasec
- **Contributor:** @h0tak88r

## TODO 
- Add proxy subcommand to recive urls form burpsuite
- Recheck at the preflight request correct usage
- Add http test origin
- Enhance the output of the tool (Adding description and explot and ... like corsy tool)
- Add config or options file to handle the flags
- add ability to control the output drom the user by adding flag like -d
