package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/AmpedWasTaken/wcdscan/internal/model"
)

func PrintHuman(w io.Writer, r model.Report, quiet bool) {
	if quiet {
		for _, f := range r.Findings {
			if f.Suspicious {
				fmt.Fprintln(w, f.Variant)
			}
		}
		return
	}

	fmt.Fprintln(w, "┌─[ wcdscan ]────────────────────────────────────────┐")
	fmt.Fprintf(w, "│ evidence-first cache security  //  v%-15s│\n", r.ToolVersion)
	fmt.Fprintln(w, "└─ crafted by @AmpedWasTaken ────────────────────────┘")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Target: %s\n", r.Target)
	fmt.Fprintf(w, "CDN:    %s\n", r.CDN)
	if r.Proxy != "" {
		fmt.Fprintf(w, "Proxy:  %s\n", r.Proxy)
	}
	fmt.Fprintf(w, "Baseline: auth=%d %s  anon=%d %s\n\n", r.AuthBaseline.Status, short(r.AuthBaseline.BodySHA256), r.AnonBaseline.Status, short(r.AnonBaseline.BodySHA256))
	for _, f := range r.Findings {
		tag := strings.ToUpper(f.Severity)
		if f.Suspicious {
			tag = "HIGH/SUSPICIOUS"
		}
		fmt.Fprintf(w, "[%s] %s\n", tag, f.Variant)
		fmt.Fprintf(w, "  confidence=%s match=%v cache_confirmed=%v\n", f.Confidence, f.AllAnonymousMatch, f.CacheConfirmed)
		fmt.Fprintf(w, "  %s\n", f.Reason)
		if len(f.CacheEvidence) > 0 {
			fmt.Fprintf(w, "  evidence: %s\n", strings.Join(f.CacheEvidence, ", "))
		}
		for _, warning := range f.CachePolicyWarnings {
			fmt.Fprintf(w, "  warning: %s\n", warning)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "Summary: %d variants · %d suspicious · %d high · %d medium · %d low\n", r.Summary.TotalVariants, r.Summary.Suspicious, r.Summary.High, r.Summary.Medium, r.Summary.Low)
	fmt.Fprintln(w, "signature: wcdscan/@AmpedWasTaken")
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
