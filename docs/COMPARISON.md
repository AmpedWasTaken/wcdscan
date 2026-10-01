# Why another Web Cache Deception tool?

There are already good cache-security projects. `wcdscan` is deliberately narrower.

## Existing approaches

- **Hackmanit Web Cache Vulnerability Scanner (WCVS)** is a broad Go scanner covering web cache poisoning and deception with crawling and many test classes.
- **wcde** implements the methodology from the *Web Cache Deception Escalates!* research and supports black-box testing and configurable path-confusion techniques.
- **PortSwigger's Web Cache Deception Scanner** integrates WCD testing directly into Burp Suite.

## wcdscan's niche

`wcdscan` focuses on one workflow:

> "I already found an authenticated endpoint. Can I quickly obtain high-quality evidence that this exact endpoint is exposed through shared caching?"

That leads to different design priorities:

| Priority | wcdscan approach |
|---|---|
| Proof quality | authenticated + anonymous baseline comparison and repeated confirmation |
| Privacy | hash response bodies rather than printing them |
| Pentest workflow | Burp proxy support and small request volume |
| Automation | JSON, quiet mode, and `--fail-on` exit status |
| Distribution | dependency-free Go binary |
| Reporting | explain the evidence behind severity instead of only printing vulnerable/not-vulnerable |

`wcdscan` is not intended to replace broad cache scanners. It is intended to be a focused verification tool that is easy to run after manual recon or as one stage in a larger workflow.

## References

- Hackmanit WCVS: https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
- wcde: https://github.com/golim/wcde
- PortSwigger Web Cache Deception Scanner: https://github.com/PortSwigger/web-cache-deception-scanner
