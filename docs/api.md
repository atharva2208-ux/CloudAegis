# API

FastAPI generates the OpenAPI document automatically:

- Swagger UI: `/api/docs`
- ReDoc: `/api/redoc`
- Schema: `/api/openapi.json`

All endpoints are versioned under `/api/v1`. Only `POST /auth/login` and `GET /auth/demo-info` are public.

## Conventions

**Authentication.** `POST /api/v1/auth/login` sets an `HttpOnly` session cookie and returns a `csrf_token`. Browser clients send that token as `X-CSRF-Token` on every `POST`, `PATCH` and `DELETE`. `GET /auth/me` returns the session and a fresh CSRF token.

```bash
# Sign in and keep the cookie jar
curl -sc jar -H 'Content-Type: application/json' \
  -d '{"email":"admin@cloudaegis.local","password":"CloudAegis!Demo2026"}' \
  http://localhost:8080/api/v1/auth/login | jq -r .csrf_token > csrf

# Read
curl -sb jar 'http://localhost:8080/api/v1/findings?severity=CRITICAL&page_size=5' | jq '.items[].title'

# Write (CSRF header required)
curl -sb jar -H "X-CSRF-Token: $(cat csrf)" -H 'Content-Type: application/json' \
  -d '{"status":"ACKNOWLEDGED","note":"Triaged"}' -X PATCH http://localhost:8080/api/v1/findings/15/status
```

**Pagination.** List endpoints accept `page` (≥ 1) and `page_size` (1–200, default 25) and return:

```json
{ "items": [...], "total": 598, "page": 1, "page_size": 25, "pages": 24 }
```

**Filtering and sorting.** Repeat a parameter to pass several values (`?severity=CRITICAL&severity=HIGH`). Sort fields come from a fixed list (`sort=severity|title|service|region|status|first_detected`, `order=asc|desc`); any other value returns `422`.

**Errors.** Every error uses one envelope, and every response carries `X-Request-ID`:

```json
{ "error": { "code": "validation_error", "message": "Request validation failed",
             "details": [{ "field": "page_size", "message": "Input should be less than or equal to 200" }],
             "request_id": "9f0c…" } }
```

| Status | `code` |
|---|---|
| 400 | `bad_request`, `connection_failed`, `account_mismatch`, `invalid_password` |
| 401 | `unauthenticated` |
| 403 | `forbidden`, `csrf_failed` |
| 404 | `not_found` |
| 409 | `conflict` (e.g. a scan already running), `account_unhealthy`, `no_scan_data`, `last_admin`, `self_modification` |
| 422 | `validation_error`, `weak_password` |
| 423 | `account_locked` |
| 429 | `rate_limited` (with `Retry-After`) |
| 500 | `internal_error` (no internals are exposed; quote the request ID) |

## Endpoints

### Auth and users
| Method | Path | Permission | Purpose |
|---|---|---|---|
| POST | `/auth/login` | public | Start a session |
| POST | `/auth/logout` | session | Revoke the session |
| GET | `/auth/me` | session | Current user, permissions, fresh CSRF token |
| POST | `/auth/change-password` | session | Change password; other sessions are signed out |
| GET | `/auth/demo-info` | public | Demo credentials when `DEMO_MODE=true` |
| GET/POST | `/users` | users:manage | List or create users |
| PATCH | `/users/{id}` | users:manage | Change name, role, active flag |
| POST | `/users/{id}/unlock` | users:manage | Clear a lockout |
| GET | `/users/roles` | users:manage | Roles and their permissions |

### Cloud accounts
| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/accounts` | accounts:read | Accounts with asset, finding and score summary |
| GET | `/accounts/onboarding-guide` | accounts:manage | Trust policy, least-privilege policy, CloudFormation template |
| POST | `/accounts/test-connection` | accounts:manage | Validate credentials and discover regions without saving |
| POST | `/accounts` | accounts:manage | Connect an account (validated first); optional first scan |
| POST | `/accounts/demo` | accounts:manage | Connect the simulated environment |
| GET/PATCH/DELETE | `/accounts/{id}` | read / manage | Detail, rename, change regions, rotate credentials, remove |
| POST | `/accounts/{id}/validate` | accounts:manage | Re-check stored credentials |

### Inventory and findings
| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/assets` | assets:read | Filter by `q`, `service`, `region`, `resource_type`, `public`, `encryption`, `risk`, `account_id`; sort by risk, name, findings… |
| GET | `/assets/stats` | assets:read | Totals by service, region and type; exposure and encryption counts |
| GET | `/assets/{id}` | assets:read | Configuration, tags, relationships, findings |
| GET | `/findings` | findings:read | Filter by `q`, `severity`, `status`, `service`, `region`, `rule_id`, `framework`+`control`, `public_only`, `detected_from` |
| GET | `/findings/facets` | findings:read | Counts for filter menus |
| GET | `/findings/{id}` | findings:read | Evidence, impact, remediation, compliance, references, history |
| PATCH | `/findings/{id}/status` | findings:update | OPEN, ACKNOWLEDGED, IN_PROGRESS, RESOLVED, SUPPRESSED (suppression needs a justification) |
| POST | `/findings/bulk-status` | findings:update | Atomic bulk transition |
| POST | `/findings/{id}/comments` | findings:update | Investigation note |
| GET | `/findings/{id}/ticket-draft` | findings:read | Ready-to-paste ticket text |
| POST | `/findings/{id}/ticket` | findings:update | Link a ticket reference |

### Scans
| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/scans` | scans:read | History (filter by account and status) |
| POST | `/scans` | scans:run | Queue a scan (`202`); optional `regions` and `services` |
| GET | `/scans/active` | scans:read | Queued and running scans with live progress |
| GET | `/scans/{id}` | scans:read | Progress, score breakdown, compliance snapshot, errors |
| POST | `/scans/{id}/cancel` | scans:run | Cooperative cancellation |
| GET | `/scans/compare?base=&target=` | scans:read | Score, severity and exposure deltas; new and resolved findings |

### Compliance, analytics and reports
| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/compliance/frameworks` | compliance:read | Framework scores with trend |
| GET | `/compliance/frameworks/{key}` | compliance:read | Controls with status and mapped rules |
| GET | `/compliance/frameworks/{key}/controls/{id}/findings` | compliance:read | Findings behind a failing control |
| GET | `/compliance/controls` | compliance:read | Cross-framework control list |
| GET | `/dashboard/summary` | findings:read | Everything on the overview page |
| GET | `/analytics/trends?days=` | findings:read | Per-scan series, MTTR, open-finding age |
| GET | `/analytics/risk` | findings:read | Risk by service, region and category; top rules and assets |
| GET | `/search?q=` | session | Categorised results: assets, findings, rules, IPs, accounts, regions |
| GET/POST | `/reports` | reports:read / generate | List or generate (`pdf`, `json`, `csv`; `executive` or `technical`) |
| GET | `/reports/{id}/download` | reports:read | File download |
| DELETE | `/reports/{id}` | reports:generate | Remove a report |

### Platform
| Method | Path | Permission | Purpose |
|---|---|---|---|
| GET | `/audit` | audit:read | Filter by `q`, `action`, `user`, `result`, `since`, `until` |
| GET | `/audit/facets` | audit:read | Values for filter menus |
| GET | `/notifications` · POST `/notifications/read` | session | In-app notifications |
| GET | `/rules` · PATCH `/rules/{id}` | rules:read / settings:manage | Rule catalogue; enable or disable a rule |
| GET/PATCH | `/settings` | session / settings:manage | Thresholds, default scan services, notifications |

### Health
| Path | Meaning |
|---|---|
| `GET /health` | Service metadata |
| `GET /health/live` | Process is up (liveness) |
| `GET /health/ready` | Database (and Redis, when configured) reachable (readiness); `503` otherwise |
