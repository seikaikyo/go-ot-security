package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("reached"))
	})
}

func TestTokenAuth(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		method     string
		header     string
		value      string
		wantStatus int
	}{
		{"no header", testToken, http.MethodGet, "", "", http.StatusUnauthorized},
		{"empty bearer", testToken, http.MethodGet, "Authorization", "Bearer ", http.StatusUnauthorized},
		{"scheme only", testToken, http.MethodGet, "Authorization", "Bearer", http.StatusUnauthorized},
		{"wrong scheme", testToken, http.MethodGet, "Authorization", "Basic " + testToken, http.StatusUnauthorized},
		{"wrong token", testToken, http.MethodGet, "Authorization", "Bearer nope", http.StatusUnauthorized},
		{"prefix of token", testToken, http.MethodGet, "Authorization", "Bearer " + testToken[:10], http.StatusUnauthorized},
		{"token in query rejected", testToken, http.MethodGet, "", "", http.StatusUnauthorized},
		{"correct bearer", testToken, http.MethodGet, "Authorization", "Bearer " + testToken, http.StatusOK},
		{"correct bearer lowercase scheme", testToken, http.MethodGet, "Authorization", "bearer " + testToken, http.StatusOK},
		{"correct x-api-token", testToken, http.MethodGet, "X-API-Token", testToken, http.StatusOK},
		{"wrong x-api-token", testToken, http.MethodGet, "X-API-Token", "nope", http.StatusUnauthorized},
		{"post without token", testToken, http.MethodPost, "", "", http.StatusUnauthorized},
		{"preflight exempt", testToken, http.MethodOptions, "", "", http.StatusOK},
		{"unconfigured fails closed", "", http.MethodGet, "Authorization", "Bearer " + testToken, http.StatusServiceUnavailable},
		{"unconfigured rejects empty token", "", http.MethodGet, "", "", http.StatusServiceUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "/api/assets"
			if tc.name == "token in query rejected" {
				target += "?token=" + testToken
			}
			req := httptest.NewRequest(tc.method, target, nil)
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			rec := httptest.NewRecorder()

			TokenAuth(tc.configured)(okHandler()).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK && strings.Contains(rec.Body.String(), "reached") {
				t.Fatal("handler ran despite failed authentication")
			}
			if tc.wantStatus == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate header")
			}
			// The rejection must not disclose the expected token or say
			// which check failed.
			if strings.Contains(rec.Body.String(), testToken) {
				t.Error("response body echoes the token")
			}
		})
	}
}

func TestCSRFGuard(t *testing.T) {
	allowed := []string{"http://localhost:3000"}

	cases := []struct {
		name        string
		method      string
		contentType string
		origin      string
		secFetch    string
		wantStatus  int
	}{
		{"get exempt", http.MethodGet, "", "https://evil.example", "cross-site", http.StatusOK},
		{"head exempt", http.MethodHead, "", "https://evil.example", "cross-site", http.StatusOK},
		{"options exempt", http.MethodOptions, "", "https://evil.example", "cross-site", http.StatusOK},
		{"post no content type", http.MethodPost, "", "", "", http.StatusUnsupportedMediaType},
		{"post text plain", http.MethodPost, "text/plain", "", "", http.StatusUnsupportedMediaType},
		{"post form urlencoded", http.MethodPost, "application/x-www-form-urlencoded", "", "", http.StatusUnsupportedMediaType},
		{"post multipart", http.MethodPost, "multipart/form-data; boundary=x", "", "", http.StatusUnsupportedMediaType},
		{"post json cross-site", http.MethodPost, "application/json", "https://evil.example", "cross-site", http.StatusForbidden},
		{"post json same-site not allowlisted", http.MethodPost, "application/json", "https://sub.evil.example", "same-site", http.StatusForbidden},
		{"post json foreign origin no sec-fetch", http.MethodPost, "application/json", "https://evil.example", "", http.StatusForbidden},
		{"post json same-origin", http.MethodPost, "application/json", "", "same-origin", http.StatusOK},
		{"post json sec-fetch none", http.MethodPost, "application/json", "", "none", http.StatusOK},
		{"post json charset param", http.MethodPost, "application/json; charset=utf-8", "", "same-origin", http.StatusOK},
		{"post json allowlisted origin", http.MethodPost, "application/json", "http://localhost:3000", "cross-site", http.StatusOK},
		{"post json matching host origin", http.MethodPost, "application/json", "http://example.com", "", http.StatusOK},
		{"post json no browser headers", http.MethodPost, "application/json", "", "", http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://example.com/api/scan", strings.NewReader("{}"))
			req.Host = "example.com"
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetch != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetch)
			}
			rec := httptest.NewRecorder()

			CSRFGuard(allowed)(okHandler()).ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantStatus != http.StatusOK && strings.Contains(rec.Body.String(), "reached") {
				t.Fatal("handler ran despite a rejected cross-site request")
			}
		})
	}
}

// A wildcard CORS setting relaxes reads. It must not also switch off the
// CSRF check on writes.
func TestCSRFGuardIgnoresWildcardOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api/scan", strings.NewReader("{}"))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	CSRFGuard([]string{"*"})(okHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
