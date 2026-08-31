package server

import (
	"crypto/subtle"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/seikaikyo/go-common/response"
)

// Header names accepted for the API token. A query parameter is deliberately
// not accepted: it would be written to proxy and access logs.
const (
	headerAuthorization = "Authorization"
	headerAPIToken      = "X-API-Token"
	bearerPrefix        = "Bearer "
)

// TokenAuth guards every wrapped route with a shared bearer token.
//
// The token is compared in constant time. An empty configured token fails
// closed with 503 rather than allowing anonymous access, so a misconfigured
// deployment cannot silently serve the OT inventory to anyone.
func TokenAuth(token string) func(http.Handler) http.Handler {
	want := []byte(token)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS preflight carries no Authorization header by design.
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			if len(want) == 0 {
				slog.Error("api token not configured, refusing request", "path", r.URL.Path)
				response.Err(w, http.StatusServiceUnavailable, "server is not configured for authenticated access")
				return
			}

			got := []byte(requestToken(r))
			if len(got) == 0 {
				unauthorized(w, r, "missing token")
				return
			}
			if subtle.ConstantTimeCompare(got, want) != 1 {
				unauthorized(w, r, "invalid token")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func requestToken(r *http.Request) string {
	if h := r.Header.Get(headerAuthorization); h != "" {
		if len(h) > len(bearerPrefix) && strings.EqualFold(h[:len(bearerPrefix)], bearerPrefix) {
			return strings.TrimSpace(h[len(bearerPrefix):])
		}
		return ""
	}
	return strings.TrimSpace(r.Header.Get(headerAPIToken))
}

func unauthorized(w http.ResponseWriter, r *http.Request, reason string) {
	slog.Warn("unauthorized api request", "path", r.URL.Path, "remote", r.RemoteAddr, "reason", reason)
	w.Header().Set("WWW-Authenticate", `Bearer realm="go-ot-security"`)
	// The client is told it needs credentials, not which check failed.
	response.Err(w, http.StatusUnauthorized, "authentication required")
}

// CSRFGuard blocks cross-site state-changing requests.
//
// Two checks, both cheap and both header based:
//
//  1. A non-GET request must declare application/json. That removes the
//     text/plain simple-request path a cross-origin form or fetch call can
//     use to skip the CORS preflight entirely.
//  2. Origin and Sec-Fetch-Site must indicate same-origin, or the Origin has
//     to be one the operator explicitly allowlisted.
func CSRFGuard(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make([]string, 0, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o = strings.TrimSpace(o); o != "" {
			allowed = append(allowed, o)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}

			if !isJSONContentType(r.Header.Get("Content-Type")) {
				slog.Warn("rejected non-json request", "path", r.URL.Path, "remote", r.RemoteAddr)
				response.Err(w, http.StatusUnsupportedMediaType, "Content-Type: application/json is required")
				return
			}

			if !sameSiteOrAllowed(r, allowed) {
				slog.Warn("rejected cross-site request", "path", r.URL.Path,
					"remote", r.RemoteAddr, "origin", r.Header.Get("Origin"),
					"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
				response.Err(w, http.StatusForbidden, "cross-site request rejected")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isJSONContentType(v string) bool {
	if v == "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(v)
	if err != nil {
		return false
	}
	return mt == "application/json"
}

// sameSiteOrAllowed reports whether the request originates from this server's
// own origin or from an origin the operator listed in the CORS allowlist.
// A request with neither header (curl, an agent, a field script) is allowed:
// it already had to present the bearer token to get here.
func sameSiteOrAllowed(r *http.Request, allowed []string) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))

	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" {
		if site == "same-origin" || site == "none" {
			return true
		}
		// same-site and cross-site both need an explicit allowlist entry.
		return origin != "" && originAllowlisted(origin, allowed)
	}

	if origin == "" {
		return true
	}
	if u, err := url.Parse(origin); err == nil && u.Host != "" && strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return originAllowlisted(origin, allowed)
}

// originAllowlisted matches the origin literally. A wildcard CORS setting is
// deliberately not honoured here: relaxing CORS for reads must not also
// disable the CSRF check on writes.
func originAllowlisted(origin string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}
