# n8n integration

VIGIL uses an authenticated asynchronous flow. n8n submits an alert, receives `202 Accepted`, polls the case, and retrieves the report only after a terminal `completed` or `partial` state. No response action is executed.

## Start VIGIL on Windows

Generate a local token without committing it:

```powershell
$env:VIGIL_API_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
$env:VIGIL_CONNECTOR_MODE = 'mock'
vigil serve --host 0.0.0.0 --port 8000
```

Binding `0.0.0.0` is needed for Docker Desktop access. Use Windows Firewall to restrict port 8000 to the local Docker/host network. Plain HTTP is only suitable for this trusted local boundary. Use TLS through a reverse proxy before crossing any untrusted network.

Start the durable worker in a second activated terminal with the same `VIGIL_DATA_DIR`:

```powershell
vigil worker
```

Inside a Docker container, `localhost` refers to that container. The default host URL is:

```text
http://host.docker.internal:8000/api/v1/investigations
```

## HTTP contract

Request:

```http
POST /api/v1/investigations HTTP/1.1
Content-Type: application/json
Authorization: Bearer <VIGIL_API_TOKEN>
X-Idempotency-Key: demo-ssh-001
```

```json
{
  "alert": {
    "alert_id": "demo-ssh-001",
    "attack": "SSH Brute Force",
    "source_ip": "192.0.2.10",
    "attempts": 15,
    "host": "web-01",
    "observed_at": "2026-10-19T10:00:00Z",
    "description": "Multiple failed SSH logins; follow-up authentication must be investigated"
  }
}
```

The timestamp intentionally matches the offline fixture window. If an incoming alert omits a timestamp, VIGIL records receipt time as an explicit assumption. It does not silently reuse unrelated historic data.

Example response:

```json
{
  "case_id": "case-123example",
  "status": "queued",
  "poll_url": "/api/v1/investigations/case-123example",
  "created": true,
  "schema_version": "1.0"
}
```

Poll `GET /api/v1/investigations/{case_id}` with the bearer header until `terminal` is `true`. For `completed` or `partial`, fetch `GET /api/v1/investigations/{case_id}/report`. A report requested too early returns HTTP 409 with `report_not_ready`; a failed terminal case without a report returns HTTP 409 with `report_unavailable`. Reusing an idempotency key with the same payload returns the same case. Reusing it with different data returns HTTP 409.

## PowerShell simulation

```powershell
$headers = @{
  Authorization = "Bearer $env:VIGIL_API_TOKEN"
  'X-Idempotency-Key' = 'demo-ssh-001'
}
$body = @{
  alert = @{
    alert_id = 'demo-ssh-001'
    attack = 'SSH Brute Force'
    source_ip = '192.0.2.10'
    attempts = 15
    host = 'web-01'
    observed_at = '2026-10-19T10:00:00Z'
    description = 'Multiple failed SSH logins; follow-up authentication must be investigated'
  }
} | ConvertTo-Json -Depth 5
$submission = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/v1/investigations' -Headers $headers -ContentType 'application/json' -Body $body
$status = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:8000" + $submission.poll_url) -Headers $headers
$report = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:8000/api/v1/investigations/{0}/report" -f $submission.case_id) -Headers $headers
```

## Importable workflow

Import [`examples/n8n/vigil_investigation_workflow.json`](../examples/n8n/vigil_investigation_workflow.json). It contains no token. Configure `VIGIL_API_TOKEN` in the n8n container environment or replace the expression with an n8n credential. Review the bounded 5-second polling loop and add an execution timeout appropriate to the deployment before activation.

n8n exposes separate TEST and PRODUCTION webhook URLs. TEST works only while listening in the editor; PRODUCTION requires the workflow to be active. A Wazuh-to-n8n sender is a separate Izzat-owned configuration and is not created by this repository.

Live n8n/Docker connectivity is not verified until the running container, firewall, and token are available.
