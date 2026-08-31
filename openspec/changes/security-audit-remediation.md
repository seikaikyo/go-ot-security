# Security Audit Remediation

| Field | Value |
|-------|-------|
| Type | fix (security) |
| Status | in progress |
| Branch | `fix/security-audit-remediation` |
| Scope | `cmd/server`, `internal/server`, `internal/config`, docs |

## Problem

A security audit of the current `main` found the management API is fully
unauthenticated and reachable on every interface. The API serves the complete
OT asset inventory, the default-credential findings per device, and the
compliance report. It also exposes a Modbus snapshot endpoint whose target
host and port come straight from the request body, which turns the scanner
into an internal-network pivot with a working port-probe oracle.

| # | Severity | Finding |
|---|----------|---------|
| 1 | Critical | 19 API endpoints with no access control; listener binds `0.0.0.0` |
| 2 | High | SSRF via `POST /api/config/snapshot`; upstream error text returned verbatim |
| 3 | High | No CSRF protection on state-changing POSTs; no `Content-Type` check |
| 4 | Medium | Plaintext HTTP served on 8443, a port that signals HTTPS; docs claim HTTPS |
| 5 | Medium | CORS allowlist ships an external production origin by default |

## Changes

### 1. Token authentication + loopback default bind

- New in-repo middleware (`internal/server/auth.go`). No change to
  `go-common`, so no dependency release is needed.
- Token source: `OTSEC_API_TOKEN`, otherwise a 256-bit random token is
  generated at startup and printed once to the console.
- Comparison uses `crypto/subtle.ConstantTimeCompare`. Empty token fails
  closed (503), never open.
- Accepted as `Authorization: Bearer <token>` or `X-API-Token: <token>`.
  Not accepted as a query parameter (would land in proxy and access logs).
- Applies to every `/api/*` route. `/health` and the embedded static assets
  stay public.
- Default listen address becomes `127.0.0.1:8080`. Exposing the service
  beyond loopback requires the explicit `-listen` flag (or `OTSEC_LISTEN`).

### 2. Snapshot target allowlist + generic errors

- `req.Host` must parse as an IP literal and must match the IP of an asset
  already in `db.ListAssets()`. Hostnames are rejected outright, so there is
  no DNS-rebinding path.
- `req.Port` must be one of that asset's discovered open ports, or the Modbus
  default 502.
- Failures return a fixed string. The underlying error goes to `slog` only,
  which closes the port-enumeration oracle.

### 3. CSRF guard on non-GET routes

- Non-GET/HEAD/OPTIONS requests must carry `Content-Type: application/json`
  (parsed as a media type, `charset` parameter tolerated). This removes the
  `text/plain` simple-request path that skips preflight.
- If `Sec-Fetch-Site` is present and is not `same-origin`/`none`, the request
  must carry an `Origin` in the configured CORS allowlist.
- If `Origin` is present it must be same-origin or explicitly allowlisted.

### 4. Transport: honest HTTP on 8080, optional real TLS

Decision: keep plaintext by default, move the port from 8443 to 8080, and
support operator-supplied TLS via `TLS_CERT_FILE` / `TLS_KEY_FILE`.

Rationale: a startup-generated self-signed certificate trains the operator to
click through the browser interstitial, which is a worse habit than honest
plaintext on a loopback socket. With the default bind on `127.0.0.1` the
traffic never reaches a network interface, so TLS adds nothing there. The
real defect is the port lying about the transport: an operator seeing 8443
assumes encryption. When the service is deliberately exposed with `-listen`,
TLS becomes meaningful, so the cert/key path enables it with a real
certificate, and a non-loopback bind without TLS logs a startup warning.

### 5. CORS default: localhost only

Default allowlist drops `https://trace-demo.seikai.dev` and keeps only
`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:5173`,
`http://127.0.0.1:5173`. External origins are opt-in through
`CORS_ALLOWED_ORIGINS`.

### 6. Documentation

- `openspec/changes/phase1-asset-discovery.md:318` claimed authorization is
  satisfied by physical network access. Reworded to describe the token the
  implementation actually enforces.
- `openspec/specs/ot-security-platform.md` deployment table and README quick
  start / environment table updated for port 8080, the loopback default, and
  the new variables.

## Impact

| Area | Effect |
|------|--------|
| API clients | Must send the bearer token and `Content-Type: application/json` |
| Default URL | `http://localhost:8443` becomes `http://127.0.0.1:8080` |
| Remote access | No longer works without `-listen` |
| trace-demo | Needs `CORS_ALLOWED_ORIGINS` plus a token; no longer default-on |
| Snapshot API | Only reaches hosts already present in the asset inventory |
| Dependencies | None. Middleware is local to this repo |

## UI Spec

No UI change. `web/dashboard` is an empty gitlink in this repo, so no
frontend file is touched here. A dashboard consuming this API has to attach
the bearer token to its fetch calls.

## Test Plan

New Go table tests, run by `go test ./...`.

| Test | Assertion |
|------|-----------|
| `TestTokenAuth` | missing / malformed / wrong token rejected with 401; correct token passes; empty configured token fails closed |
| `TestCSRFGuard` | `text/plain` rejected; cross-site `Sec-Fetch-Site` rejected; foreign `Origin` rejected; allowlisted and same-origin pass; GET exempt |
| `TestValidateSnapshotTarget` | unknown IP, hostname, non-open port rejected; discovered IP with open port and with 502 accepted |
| `TestHandleSnapshotDoesNotLeakError` | upstream failure returns the fixed message, no address or syscall text in the body |
| `TestSnapshotRejectsUndiscoveredHost` | request is refused before any dial |
| `TestDefaultCORSOrigins` | default allowlist contains no non-loopback origin |
| `TestResolveListenAddr` | default is `127.0.0.1:8080`; flag and env override |

## Checklist

- [x] Token auth middleware + loopback default bind
- [x] Snapshot host/port allowlist + generic error responses
- [x] CSRF guard on non-GET API routes
- [x] Port 8080 + optional TLS
- [x] CORS default without external origin
- [x] Docs aligned with implementation
- [x] `go build ./...` and `go test ./...` pass

## Out of Scope

`web/dashboard` is a gitlink (mode 160000) with no `.gitmodules`, so a fresh
clone gets an empty directory while the README architecture tree points at
files inside it. Fixing that is a submodule-versus-vendor decision for the
repo owner and is deliberately untouched here.
