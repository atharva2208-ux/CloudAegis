# Security model

CloudAegis holds the keys to read every security-relevant setting in the accounts it audits, so it is built to the standard it checks others against. Each control below is covered by an automated test in `tests/security`, `tests/integration` or `tests/unit`.

## 1. Read-only cloud access

- The only AWS authentication methods are **IAM role assumption** (`sts:AssumeRole` with an external ID) and **temporary STS credentials** (`ASIA…` keys plus a session token). Long-lived IAM user keys (`AKIA…`) are rejected by validation in both the API and the UI.
- The onboarding guide generates a least-privilege inline policy from `providers/aws/permissions.py`: **only `Describe*`, `Get*` and `List*` actions, and no wildcards**. AWS's managed `SecurityAudit` policy is offered as an alternative.
- The trust policy requires `sts:ExternalId`, which protects against the confused-deputy problem.
- Collectors never call mutating APIs. `tests/unit/test_read_only_guarantee.py` statically scans every collector for `put_`, `create_`, `delete_`, `modify_` and similar calls, and checks that the required actions are read-only.
- Remediation is advice only. CLI examples are labelled "review before running", and CloudAegis never executes them.
- Secret values are never collected. For example, Secrets Manager discovery reads rotation metadata and never calls `GetSecretValue`, and Lambda environment variables are inspected for secret-looking *names* only.

## 2. Credential protection

- Stored credential material (external ID, temporary keys, session token) is encrypted at rest with **Fernet** (AES-128-CBC + HMAC-SHA256) using `CREDENTIAL_ENCRYPTION_KEY`. Production startup fails if the key is missing.
- API responses expose only `has_stored_secret` and non-secret identifiers such as the role ARN. Request schemas use `SecretStr`, so secrets never reach logs or error messages.
- Tests create an account with known secret values, then assert that the values appear in no API response, audit entry or log line, and that the database column holds only ciphertext.

## 3. Authentication and sessions

| Control | Implementation |
|---|---|
| Password storage | Argon2id (`argon2-cffi`, OWASP-aligned parameters) with transparent rehash on login |
| Password policy | 12–128 characters, at least three character classes, must not contain the email name; enforced in the API and mirrored in the UI |
| Session token | HS256 JWT (issuer, `exp`, `nbf`, `jti`) in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` when `COOKIE_SECURE=true`, which production requires) |
| Server-side sessions | Every token maps to a `user_sessions` row, so logout, password change, role change and deactivation revoke sessions immediately |
| Expiry | 30-minute idle timeout, 8-hour absolute lifetime (configurable) |
| Generic errors | Unknown user and wrong password return the same message and status; constant-time verification against a dummy hash prevents user enumeration by timing |
| Lockout | 5 failed attempts lock the account for 15 minutes. Admins can see locked users and unlock them |
| Rate limiting | Login: 10/min per IP and per account. API: 600/min per client. Redis-backed with an in-memory fallback; `429` with `Retry-After` |

## 4. Authorization (RBAC)

| Permission | Admin | Security analyst | Viewer |
|---|:-:|:-:|:-:|
| Read accounts, assets, findings, scans, compliance, rules, reports | ✓ | ✓ | ✓ |
| Update findings (acknowledge, resolve, suppress, comment, ticket) | ✓ | ✓ | |
| Run and cancel scans | ✓ | ✓ | |
| Generate reports | ✓ | ✓ | |
| Manage cloud accounts | ✓ | | |
| Read the audit log | ✓ | | |
| Manage users and roles | ✓ | | |
| Change settings and enable/disable rules | ✓ | | |

- Every endpoint declares its permission with `require(Perm.…)`; the UI only hides what the API already forbids.
- Denied requests return `403` and are written to the audit log as `access.denied`.
- Admins cannot demote or deactivate themselves, and the last active admin cannot be removed.
- `tests/security/test_authorization.py` checks that **every** `/api/v1` route returns `401` without a session, and runs a role × action matrix.

## 5. Web application protections

- **CSRF**: on state-changing requests, cookie-authenticated callers must send `X-CSRF-Token`. The token is double-submitted and **bound to the server-side session** (its hash is stored), so a token from one session is useless in another.
- **XSS**: React escapes all output and nothing uses `dangerouslySetInnerHTML`; evidence is rendered by a text-only JSON viewer. API responses are JSON with `Content-Security-Policy: default-src 'none'`. nginx serves the SPA with a strict CSP (`script-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`).
- **SQL injection**: all queries are built with SQLAlchemy expressions and bound parameters. Sort fields are allow-listed through `Literal` types, so `sort=password_hash` is rejected with `422`.
- **CSV injection**: report cells beginning with `= + - @` (or a tab or CR) are prefixed with `'`.
- **Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP/CORP, `Permissions-Policy`, `Cache-Control: no-store` on API responses, and HSTS when cookies are secure.
- **CORS**: explicit allow-list (`CORS_ORIGINS`) with credentials. In the Docker deployment the SPA and API share one origin through nginx.
- **Input validation**: Pydantic schemas with length limits, regexes (role ARN, region, external ID, account name), enums and bounded pagination (`page_size ≤ 200`). Request bodies over 1 MB are rejected.
- **Error handling**: unhandled exceptions return a generic `internal_error` with the request ID. The details go to logs only, never to the response (tested with an exception message containing a connection string).

## 6. Audit trail

Security-relevant actions are written to `audit_logs` with timestamp, user, action, resource, IP address, user agent, request ID and result (`success`, `failure` or `denied`):

`auth.login` · `auth.logout` · `user.created` · `user.role_changed` · `user.updated` · `user.unlocked` · `user.password_changed` · `account.created` · `account.updated` · `account.deleted` · `account.validated` · `scan.started` · `scan.completed` · `scan.cancelled` · `finding.acknowledged` · `finding.in_progress` · `finding.resolved` · `finding.suppressed` · `finding.reopened` · `finding.commented` · `finding.ticket_linked` · `report.generated` · `report.downloaded` · `report.deleted` · `settings.modified` · `settings.rule_toggled` · `access.denied`

Failed sign-ins and denials are recorded in a separate transaction, so they persist even when the request itself fails. The API has no endpoint to modify or delete audit entries.

## 7. Configuration and secrets

- `ENVIRONMENT=production` refuses to start without a strong `SECRET_KEY` (≥ 32 characters, not the development default), a `CREDENTIAL_ENCRYPTION_KEY`, and `COOKIE_SECURE=true`.
- `.env` files are git-ignored; `.env.example` documents every variable; `scripts/generate-secrets.sh` creates keys.
- Containers run as non-root (`uid 10001` for the API and worker; `nginx-unprivileged` for the web tier).
- CI runs `pip-audit` and `npm audit` against dependencies.

## Security score

```
weighted_pass_rate = 1 − (Σ weight of failing checks / Σ weight of all checks)
score = clamp(round(100 × weighted_pass_rate − min(25, 3 × open_critical)), 0, 100)
weights: CRITICAL 10 · HIGH 5 · MEDIUM 2 · LOW 1 · INFO 0
```

A *check* is one (rule, resource) evaluation. The critical penalty stops a large estate of passing checks from hiding a handful of critical exposures. Suppressed findings count as accepted risk: the check still counts toward the total but not toward the failing weight. The dashboard shows this calculation with the live numbers.

**Asset risk** (0–100) is the sum of the asset's open-finding weights, × 1.5 if it is internet-exposed, × 4, capped at 100. It is banded as Critical ≥ 70, High ≥ 40, Medium ≥ 15, Low > 0.

## Known limitations

- Exposure analysis is configuration-based. It does not trace full network paths through load balancers, peering or Transit Gateway.
- Access is evaluated per policy statement. Organization SCPs and permission boundaries are not yet modelled.
- In-process rate limiting is per API process when Redis is unavailable. Production should run Redis.
