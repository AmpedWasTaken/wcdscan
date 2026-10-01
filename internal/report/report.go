package report

import (
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/AmpedWasTaken/wcdscan/internal/model"
)

func WriteJSON(path string, report model.Report) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteHTML(path string, report model.Report) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	funcs := template.FuncMap{
		"short": func(s string) string {
			if len(s) > 14 {
				return s[:14]
			}
			return s
		},
		"join": func(v []string) string { return strings.Join(v, ", ") },
	}
	t, err := template.New("report").Funcs(funcs).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, report)
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

const htmlTemplate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>wcdscan report</title>
<style>
:root{color-scheme:dark}body{font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;max-width:1180px;margin:40px auto;padding:0 20px;background:#090b0e;color:#eef1f4}h1,h2{margin:0 0 16px}.muted{color:#959ca6}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}.card{background:#11151a;border:1px solid #222832;border-radius:12px;padding:16px}table{width:100%;border-collapse:collapse;background:#11151a;border:1px solid #222832;border-radius:12px;overflow:hidden}th,td{text-align:left;padding:11px;border-bottom:1px solid #222832;vertical-align:top;font-size:14px}th{background:#151a20}.sev-high{color:#ff8f8f}.sev-medium{color:#ffd479}.sev-low{color:#9fc1ff}.sev-info{color:#959ca6}code{background:#0d1014;padding:2px 5px;border-radius:5px;word-break:break-all}.small{font-size:13px}ul{padding-left:18px;margin:6px 0}.pill{display:inline-block;padding:2px 8px;border:1px solid #303844;border-radius:999px;font-size:12px}
</style></head><body>
<h1>wcdscan</h1><p class="muted">Evidence-first Web Cache Deception report</p>
<p>Target: <code>{{.Target}}</code><br>Generated: {{.GeneratedAt}}<br>CDN: <span class="pill">{{.CDN}}</span>{{if .Proxy}}<br>Proxy: <code>{{.Proxy}}</code>{{end}}</p>
<div class="grid"><div class="card"><strong>Variants</strong><br><span style="font-size:28px">{{.Summary.TotalVariants}}</span></div><div class="card"><strong>Suspicious</strong><br><span style="font-size:28px">{{.Summary.Suspicious}}</span></div><div class="card"><strong>High</strong><br><span style="font-size:28px">{{.Summary.High}}</span></div><div class="card"><strong>Medium</strong><br><span style="font-size:28px">{{.Summary.Medium}}</span></div></div>
<h2>Baselines</h2><table><tr><th>Type</th><th>Status</th><th>Body hash</th><th>Cache-Control</th><th>Vary</th><th>Evidence</th></tr><tr><td>Authenticated</td><td>{{.AuthBaseline.Status}}</td><td><code>{{short .AuthBaseline.BodySHA256}}</code></td><td>{{.AuthBaseline.CacheControl}}</td><td>{{.AuthBaseline.Vary}}</td><td>{{join .AuthBaseline.CacheEvidence}}</td></tr><tr><td>Anonymous</td><td>{{.AnonBaseline.Status}}</td><td><code>{{short .AnonBaseline.BodySHA256}}</code></td><td>{{.AnonBaseline.CacheControl}}</td><td>{{.AnonBaseline.Vary}}</td><td>{{join .AnonBaseline.CacheEvidence}}</td></tr></table>
<h2 style="margin-top:28px">Findings</h2><table><tr><th>Severity</th><th>Confidence</th><th>Variant</th><th>Confirmed</th><th>Reason</th></tr>{{range .Findings}}<tr><td class="sev-{{.Severity}}"><strong>{{.Severity}}</strong></td><td>{{.Confidence}}</td><td><code>{{.Variant}}</code></td><td>{{.CacheConfirmed}}</td><td>{{.Reason}}{{if .CacheEvidence}}<div class="small"><strong>Cache:</strong> {{join .CacheEvidence}}</div>{{end}}{{if .CachePolicyWarnings}}<ul>{{range .CachePolicyWarnings}}<li>{{.}}</li>{{end}}</ul>{{end}}</td></tr>{{end}}</table>
<p class="muted small" style="margin-top:24px">Findings are evidence-backed leads, not automatic proof. Verify manually with a dedicated test account.</p>
</body></html>`
