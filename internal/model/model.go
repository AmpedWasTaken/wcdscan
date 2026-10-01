package model

import "time"

type Result struct {
	URL                 string            `json:"url"`
	Status              int               `json:"status"`
	BodySHA256          string            `json:"body_sha256"`
	BodyBytes           int               `json:"body_bytes"`
	ContentType         string            `json:"content_type,omitempty"`
	CacheControl        string            `json:"cache_control,omitempty"`
	CDNCacheControl     string            `json:"cdn_cache_control,omitempty"`
	SurrogateControl    string            `json:"surrogate_control,omitempty"`
	Age                 string            `json:"age,omitempty"`
	XCache              string            `json:"x_cache,omitempty"`
	XCacheHits          string            `json:"x_cache_hits,omitempty"`
	CFCacheStatus       string            `json:"cf_cache_status,omitempty"`
	Vary                string            `json:"vary,omitempty"`
	ETag                string            `json:"etag,omitempty"`
	LastModified        string            `json:"last_modified,omitempty"`
	SetCookiePresent    bool              `json:"set_cookie_present"`
	Location            string            `json:"location,omitempty"`
	Server              string            `json:"server,omitempty"`
	Via                 string            `json:"via,omitempty"`
	InterestingHeaders  map[string]string `json:"interesting_headers,omitempty"`
	CacheEvidence       []string          `json:"cache_evidence,omitempty"`
	CachePolicyWarnings []string          `json:"cache_policy_warnings,omitempty"`
}

type Confirmation struct {
	Attempt       int      `json:"attempt"`
	Status        int      `json:"status"`
	BodySHA256    string   `json:"body_sha256"`
	BodyBytes     int      `json:"body_bytes"`
	LooksCached   bool     `json:"looks_cached"`
	CacheEvidence []string `json:"cache_evidence,omitempty"`
}

type Finding struct {
	Variant             string         `json:"variant"`
	AuthStatus          int            `json:"auth_status"`
	AuthBodySHA256      string         `json:"auth_body_sha256"`
	BaselineDifferent   bool           `json:"baseline_auth_vs_anon_different"`
	AllAnonymousMatch   bool           `json:"all_anonymous_match_auth_variant"`
	CacheConfirmed      bool           `json:"cache_confirmed"`
	Suspicious          bool           `json:"suspicious"`
	Severity            string         `json:"severity"`
	Confidence          string         `json:"confidence"`
	Reason              string         `json:"reason"`
	CacheEvidence       []string       `json:"cache_evidence,omitempty"`
	CachePolicyWarnings []string       `json:"cache_policy_warnings,omitempty"`
	Confirmations       []Confirmation `json:"confirmations,omitempty"`
}

type Summary struct {
	TotalVariants int `json:"total_variants"`
	Suspicious    int `json:"suspicious"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
}

type Report struct {
	ToolVersion  string    `json:"tool_version"`
	Target       string    `json:"target"`
	GeneratedAt  time.Time `json:"generated_at"`
	Proxy        string    `json:"proxy,omitempty"`
	CDN          string    `json:"cdn,omitempty"`
	AuthBaseline Result    `json:"auth_baseline"`
	AnonBaseline Result    `json:"anon_baseline"`
	Findings     []Finding `json:"findings"`
	Summary      Summary   `json:"summary"`
}
