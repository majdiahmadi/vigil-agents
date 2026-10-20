# Security boundaries

VIGIL is read-only investigation software. Its LLM tool registries contain searches, safe static inspection, hash reputation lookup, internal delegation, and case reads. There is no shell, sample execution, file deletion, account change, IP blocking, Active Response, or automatic remediation path.

- API case endpoints require a constant-time compared bearer token. The server binds to loopback by default and configures no permissive CORS.
- Model catalog requests require HTTPS, reject redirects, and refuse pagination URLs whose exact origin differs from the configured provider. Credentials are not written to SQLite or project files.
- LLM rounds validate tool names and Pydantic arguments, enforce scope and time bounds, cap calls and rounds, block repeated identical queries, and return one result for every tool-call ID.
- Alert text, logs, filenames, model output, and enrichment are treated as untrusted data. They cannot register tools or change Python-side authorization.
- Static file analysis resolves paths under one allowlisted root, rejects symlinks and oversized/non-regular files, and reads bytes only.
- VirusTotal support is optional and hash-only. It uses a fixed official host and never uploads/downloads samples. Documentation-range IPs are not sent because this connector accepts only hashes.
- Wazuh requires HTTPS and TLS verification, validates its index pattern, and builds fixed-field structured DSL.
- SQLite jobs use atomic claims, owner/expiry leases, retry caps, and stale-only recovery. Agent failure/partial state is propagated to jobs and cases.
- Findings require stable evidence references. Structured field claims are checked against stored evidence. Reports always require analyst review and enforce `response_executed=false`.

Remaining limits: SQLite is intended for a controlled single-node FYP deployment, local telemetry may contain sensitive data at rest, cloud LLM use sends minimized case context to the selected provider, and live provider/Wazuh/n8n security depends on external configuration. Restrict filesystem access, define data retention, rotate tokens, and use TLS outside a trusted host boundary.
