package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/AmpedWasTaken/wcdscan/internal/model"
	"github.com/AmpedWasTaken/wcdscan/internal/report"
	"github.com/AmpedWasTaken/wcdscan/internal/scanner"
	"github.com/AmpedWasTaken/wcdscan/internal/ui"
)

var version = "dev"

func main() {
	var headers scanner.HeaderList
	var (
		target      = flag.String("url", "", "authorized URL to test")
		cookie      = flag.String("cookie", "", "test-account Cookie header")
		authz       = flag.String("authorization", "", "test-account Authorization header")
		proxy       = flag.String("proxy", "", "HTTP(S) proxy, e.g. http://127.0.0.1:8080")
		insecure    = flag.Bool("insecure", false, "skip TLS verification (labs/local proxies only)")
		authorized  = flag.Bool("authorized", false, "confirm you are authorized to test this target")
		timeout     = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		pause       = flag.Duration("pause", 500*time.Millisecond, "pause between confirmation requests")
		confirm     = flag.Int("confirm", 2, "anonymous confirmation requests per variant")
		maxBody     = flag.Int64("max-body", 2<<20, "maximum response bytes to hash")
		jsonStdout  = flag.Bool("json", false, "print JSON report to stdout")
		jsonFile    = flag.String("json-file", "", "write JSON report to file")
		htmlFile    = flag.String("html-file", "", "write HTML report to file")
		quiet       = flag.Bool("quiet", false, "print only suspicious variant URLs")
		showVersion = flag.Bool("version", false, "print version and exit")
		failOn      = flag.String("fail-on", "", "exit 2 when findings reach severity: low, medium, or high")
		userAgent   = flag.String("user-agent", "wcdscan/"+version+" (+authorized-security-test)", "User-Agent")
	)
	flag.Var(&headers, "header", "extra request header, repeatable: 'Name: value'")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *target == "" {
		fatal("missing --url")
	}
	if !*authorized {
		fatal("refusing to scan without --authorized")
	}

	s, err := scanner.New(scanner.Config{
		Target: *target, Cookie: *cookie, Authorization: *authz, Headers: headers,
		Proxy: *proxy, InsecureTLS: *insecure, Timeout: *timeout, Pause: *pause,
		Confirmations: *confirm, MaxBody: *maxBody, UserAgent: *userAgent,
	})
	if err != nil {
		fatal(err.Error())
	}

	r, err := s.Run(context.Background(), version)
	if err != nil {
		fatal(err.Error())
	}

	if *jsonFile != "" {
		if err := report.WriteJSON(*jsonFile, r); err != nil {
			fatal(err.Error())
		}
	}
	if *htmlFile != "" {
		if err := report.WriteHTML(*htmlFile, r); err != nil {
			fatal(err.Error())
		}
	}
	if *jsonStdout {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fatal(err.Error())
		}
		return
	}
	ui.PrintHuman(os.Stdout, r, *quiet)
	if *jsonFile != "" {
		fmt.Println("JSON report:", *jsonFile)
	}
	if *htmlFile != "" {
		fmt.Println("HTML report:", *htmlFile)
	}
	if thresholdReached(r, *failOn) {
		os.Exit(2)
	}
}

func thresholdReached(r model.Report, threshold string) bool {
	if threshold == "" {
		return false
	}
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3}
	min, ok := rank[threshold]
	if !ok {
		fatal("invalid --fail-on value; use low, medium, or high")
	}
	for _, f := range r.Findings {
		if rank[f.Severity] >= min {
			return true
		}
	}
	return false
}

func fatal(msg string) { fmt.Fprintln(os.Stderr, "error:", msg); os.Exit(1) }
