package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AmpedWasTaken/wcdscan/internal/model"
)

type HeaderList []string

func (h *HeaderList) String() string { return strings.Join(*h, ", ") }
func (h *HeaderList) Set(v string) error {
	if !strings.Contains(v, ":") {
		return fmt.Errorf("header must be in 'Name: value' format")
	}
	*h = append(*h, v)
	return nil
}

type Config struct {
	Target        string
	Cookie        string
	Authorization string
	Headers       HeaderList
	Proxy         string
	InsecureTLS   bool
	Timeout       time.Duration
	Pause         time.Duration
	Confirmations int
	MaxBody       int64
	UserAgent     string
}

type Scanner struct {
	cfg    Config
	base   *url.URL
	client *http.Client
}

func New(cfg Config) (*Scanner, error) {
	base, err := url.Parse(cfg.Target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, errors.New("invalid target URL")
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, errors.New("only http and https targets are supported")
	}
	if cfg.Confirmations < 1 {
		cfg.Confirmations = 1
	}
	if cfg.MaxBody <= 0 {
		cfg.MaxBody = 2 << 20
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Proxy != "" {
		p, err := url.Parse(cfg.Proxy)
		if err != nil || p.Scheme == "" || p.Host == "" {
			return nil, errors.New("invalid proxy URL")
		}
		transport.Proxy = http.ProxyURL(p)
	}
	if cfg.InsecureTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: true} // #nosec G402 - explicit user opt-in for local labs/proxies.
		if transport.TLSClientConfig != nil {
			tlsCfg = transport.TLSClientConfig.Clone()
			tlsCfg.InsecureSkipVerify = true
		}
		transport.TLSClientConfig = tlsCfg
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}
			if !sameHost(req.URL, via[0].URL) {
				return errors.New("cross-host redirect blocked")
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	return &Scanner{cfg: cfg, base: base, client: client}, nil
}

func (s *Scanner) Run(ctx context.Context, version string) (model.Report, error) {
	authBaseline, err := s.fetch(ctx, s.base.String(), true)
	if err != nil {
		return model.Report{}, fmt.Errorf("authenticated baseline failed: %w", err)
	}
	anonBaseline, err := s.fetch(ctx, s.base.String(), false)
	if err != nil {
		return model.Report{}, fmt.Errorf("anonymous baseline failed: %w", err)
	}

	report := model.Report{
		ToolVersion:  version,
		Target:       s.base.String(),
		GeneratedAt:  time.Now().UTC(),
		Proxy:        s.cfg.Proxy,
		CDN:          fingerprintCDN(authBaseline, anonBaseline),
		AuthBaseline: authBaseline,
		AnonBaseline: anonBaseline,
	}

	baselineDifferent := authBaseline.BodySHA256 != anonBaseline.BodySHA256 || authBaseline.Status != anonBaseline.Status

	for _, variant := range makeVariants(s.base) {
		finding := model.Finding{
			Variant:           variant,
			BaselineDifferent: baselineDifferent,
			Severity:          "info",
			Confidence:        "low",
			Reason:            "no strong cache-deception signal",
		}

		authRes, err := s.fetch(ctx, variant, true)
		if err != nil {
			finding.Reason = "authenticated variant request failed: " + err.Error()
			report.Findings = append(report.Findings, finding)
			continue
		}
		finding.AuthStatus = authRes.Status
		finding.AuthBodySHA256 = authRes.BodySHA256

		allMatch := true
		cacheConfirmed := false
		var evidence []string
		var warnings []string

		for i := 1; i <= s.cfg.Confirmations; i++ {
			if s.cfg.Pause > 0 {
				time.Sleep(s.cfg.Pause)
			}
			anonRes, err := s.fetch(ctx, variant, false)
			if err != nil {
				allMatch = false
				finding.Confirmations = append(finding.Confirmations, model.Confirmation{Attempt: i})
				continue
			}

			match := authRes.Status == anonRes.Status && authRes.BodySHA256 == anonRes.BodySHA256 && authRes.BodyBytes == anonRes.BodyBytes
			if !match {
				allMatch = false
			}
			if looksCached(anonRes) {
				cacheConfirmed = true
			}

			evidence = append(evidence, anonRes.CacheEvidence...)
			warnings = append(warnings, anonRes.CachePolicyWarnings...)
			finding.Confirmations = append(finding.Confirmations, model.Confirmation{
				Attempt:       i,
				Status:        anonRes.Status,
				BodySHA256:    anonRes.BodySHA256,
				BodyBytes:     anonRes.BodyBytes,
				LooksCached:   looksCached(anonRes),
				CacheEvidence: anonRes.CacheEvidence,
			})
		}

		finding.AllAnonymousMatch = allMatch
		finding.CacheConfirmed = cacheConfirmed
		finding.CacheEvidence = uniqueStrings(evidence)
		finding.CachePolicyWarnings = uniqueStrings(warnings)

		switch {
		case baselineDifferent && allMatch && cacheConfirmed:
			finding.Suspicious = true
			finding.Severity = "high"
			finding.Confidence = "high"
			finding.Reason = "authenticated content appears reproducible anonymously on a static-looking path with shared-cache evidence"
		case baselineDifferent && allMatch:
			finding.Severity = "medium"
			finding.Confidence = "medium"
			finding.Reason = "authenticated and anonymous variant responses match, but shared-cache behavior was not confirmed"
		case cacheConfirmed && len(finding.CachePolicyWarnings) > 0:
			finding.Severity = "low"
			finding.Confidence = "low"
			finding.Reason = "shared-cache evidence and cache-policy warnings were observed, but anonymous content did not match the authenticated variant"
		case cacheConfirmed:
			finding.Reason = "shared-cache evidence observed, but authenticated and anonymous variant bodies differ"
		}

		report.Findings = append(report.Findings, finding)
	}

	report.Summary = summarize(report.Findings)
	return report, nil
}

func (s *Scanner) fetch(ctx context.Context, target string, authenticated bool) (model.Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return model.Result{}, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	req.Header.Set("Accept", "*/*")

	for _, raw := range s.cfg.Headers {
		parts := strings.SplitN(raw, ":", 2)
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		switch strings.ToLower(name) {
		case "host", "cookie", "authorization":
			continue
		default:
			req.Header.Set(name, value)
		}
	}

	if authenticated {
		if s.cfg.Cookie != "" {
			req.Header.Set("Cookie", s.cfg.Cookie)
		}
		if s.cfg.Authorization != "" {
			req.Header.Set("Authorization", s.cfg.Authorization)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return model.Result{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBody))
	if err != nil {
		return model.Result{}, err
	}
	sum := sha256.Sum256(body)

	r := model.Result{
		URL:                target,
		Status:             resp.StatusCode,
		BodySHA256:         hex.EncodeToString(sum[:]),
		BodyBytes:          len(body),
		ContentType:        resp.Header.Get("Content-Type"),
		CacheControl:       resp.Header.Get("Cache-Control"),
		CDNCacheControl:    resp.Header.Get("CDN-Cache-Control"),
		SurrogateControl:   resp.Header.Get("Surrogate-Control"),
		Age:                resp.Header.Get("Age"),
		XCache:             resp.Header.Get("X-Cache"),
		XCacheHits:         resp.Header.Get("X-Cache-Hits"),
		CFCacheStatus:      resp.Header.Get("CF-Cache-Status"),
		Vary:               resp.Header.Get("Vary"),
		ETag:               resp.Header.Get("ETag"),
		LastModified:       resp.Header.Get("Last-Modified"),
		SetCookiePresent:   len(resp.Header.Values("Set-Cookie")) > 0,
		Location:           resp.Header.Get("Location"),
		Server:             resp.Header.Get("Server"),
		Via:                resp.Header.Get("Via"),
		InterestingHeaders: map[string]string{},
	}

	for _, h := range []string{
		"X-Served-By", "X-Timer", "Server-Timing", "X-Proxy-Cache", "X-Cacheable",
		"X-Drupal-Cache", "X-Varnish", "CF-Ray", "Fastly-Debug-Digest", "Akamai-Cache-Status",
	} {
		if v := resp.Header.Get(h); v != "" {
			r.InterestingHeaders[h] = v
		}
	}
	if len(r.InterestingHeaders) == 0 {
		r.InterestingHeaders = nil
	}

	r.CacheEvidence = cacheEvidence(r)
	r.CachePolicyWarnings = cachePolicyWarnings(r)
	return r, nil
}

func makeVariants(u *url.URL) []string {
	token := strconv.FormatInt(time.Now().UnixNano(), 36)
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	trimmed := strings.TrimSuffix(path, "/")
	paths := []string{
		trimmed + "/wcd-" + token + ".css",
		trimmed + "/wcd-" + token + ".js",
		trimmed + "/wcd-" + token + ".png",
		trimmed + "/wcd-" + token + ".woff2",
		trimmed + ";wcd-" + token + ".css",
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		v := *u
		v.RawPath = ""
		v.Path = p
		s := v.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func cacheEvidence(r model.Result) []string {
	var out []string
	if n, err := strconv.Atoi(strings.TrimSpace(r.Age)); err == nil && n > 0 {
		out = append(out, "Age="+r.Age)
	}
	for name, value := range map[string]string{
		"X-Cache": r.XCache, "X-Cache-Hits": r.XCacheHits, "CF-Cache-Status": r.CFCacheStatus,
	} {
		if strings.TrimSpace(value) != "" {
			out = append(out, name+"="+value)
		}
	}
	for k, v := range r.InterestingHeaders {
		lk := strings.ToLower(k)
		lv := strings.ToLower(v)
		if strings.Contains(lk, "cache") || strings.Contains(lv, "hit") {
			out = append(out, k+"="+v)
		}
	}
	sort.Strings(out)
	return out
}

func cachePolicyWarnings(r model.Result) []string {
	var out []string
	cc := strings.ToLower(strings.Join([]string{r.CacheControl, r.CDNCacheControl, r.SurrogateControl}, ","))
	if r.SetCookiePresent && (strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage")) {
		out = append(out, "response sets a cookie while advertising shared-cache directives")
	}
	if strings.Contains(cc, "public") && strings.Contains(strings.ToLower(r.ContentType), "text/html") {
		out = append(out, "HTML response is explicitly public-cacheable")
	}
	if !strings.Contains(cc, "private") && !strings.Contains(cc, "no-store") && !strings.Contains(cc, "no-cache") && r.SetCookiePresent {
		out = append(out, "Set-Cookie present without an obvious private/no-store cache directive")
	}
	if r.SetCookiePresent && !strings.Contains(strings.ToLower(r.Vary), "cookie") {
		out = append(out, "response sets cookies but Vary does not mention Cookie")
	}
	if strings.Contains(strings.ToLower(r.ContentType), "text/html") && looksCached(r) {
		out = append(out, "HTML response appears to be served from a shared cache")
	}
	return uniqueStrings(out)
}

func looksCached(r model.Result) bool {
	if n, err := strconv.Atoi(strings.TrimSpace(r.Age)); err == nil && n > 0 {
		return true
	}
	for _, v := range []string{r.XCache, r.CFCacheStatus, r.XCacheHits} {
		s := strings.ToUpper(v)
		if strings.Contains(s, "HIT") || strings.Contains(s, "REVALIDATED") {
			return true
		}
	}
	for k, v := range r.InterestingHeaders {
		if strings.Contains(strings.ToLower(k), "cache") && strings.Contains(strings.ToUpper(v), "HIT") {
			return true
		}
	}
	return false
}

func fingerprintCDN(results ...model.Result) string {
	for _, r := range results {
		if r.CFCacheStatus != "" || r.InterestingHeaders["CF-Ray"] != "" {
			return "Cloudflare"
		}
		if r.InterestingHeaders["Fastly-Debug-Digest"] != "" || r.XCacheHits != "" || strings.Contains(strings.ToLower(r.Via), "varnish") {
			return "Fastly/Varnish-like"
		}
		if r.InterestingHeaders["Akamai-Cache-Status"] != "" {
			return "Akamai"
		}
	}
	return "unknown"
}

func summarize(findings []model.Finding) model.Summary {
	var s model.Summary
	s.TotalVariants = len(findings)
	for _, f := range findings {
		if f.Suspicious {
			s.Suspicious++
		}
		switch f.Severity {
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		}
	}
	return s
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sameHost(a, b *url.URL) bool {
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a) == effectivePort(b)
}
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}
