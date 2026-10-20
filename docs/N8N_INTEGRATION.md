# n8n Integration Contract

VIGIL does not create or edit an n8n workflow. Configure a future HTTP Request node as follows:

- Method: `POST`
- URL from Docker: `http://host.docker.internal:8000/api/v1/investigations`
- Header: `Authorization: Bearer <VIGIL_API_TOKEN>`
- Header: `X-Idempotency-Key: {{$json.alert.id}}` or another stable notification ID
- JSON body:

```json
{"alert":{"attack":"SSH Brute Force","ip":"192.0.2.10","attempts":15}}
```

Expected `202 Accepted`:

```json
{"case_id":"case-...","status":"queued","poll_url":"/api/v1/investigations/case-...","created":true}
```

Poll `GET /api/v1/investigations/{case_id}` with the same bearer token until `completed`, `partial`, or `failed`, then fetch `/report`. Repeated POSTs with the same idempotency key reuse the same job/case.

Start `vigil serve --host 0.0.0.0` only with a strong token and restrictive Windows Firewall policy. Run `vigil worker` separately. VIGIL returns recommendations for human approval and performs no response action.

