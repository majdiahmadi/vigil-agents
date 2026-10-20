# API Reference

Interactive OpenAPI is available at `/docs` while the service runs.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | No | Process liveness. |
| GET | `/ready` | No | SQLite and connector-mode readiness. |
| POST | `/api/v1/investigations` | Bearer | Persist case and durable job, returning 202. |
| GET | `/api/v1/investigations/{case_id}` | Bearer | Job, case, and agent-run status. |
| GET | `/api/v1/investigations/{case_id}/report` | Bearer | Typed analyst report when ready. |
| GET | `/api/v1/agents` | Bearer | Agent capabilities and nonsecret model assignments. |

Requests are limited to a nonempty alert object no larger than 256 KiB. `X-Idempotency-Key` prevents duplicate webhook jobs. Stable outputs separate run state from security assessment and always include the analyst-review/no-response boundary in final reports.

