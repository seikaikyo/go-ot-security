package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/seikaikyo/go-ot-security/internal/store"
)

func TestValidateSnapshotTarget(t *testing.T) {
	assets := []store.Asset{
		{ID: "a1", IP: "10.0.0.5", OpenPorts: []int{502, 80}},
		{ID: "a2", IP: "10.0.0.6", OpenPorts: []int{44818}},
		{ID: "a3", IP: "", OpenPorts: []int{502}},
	}

	cases := []struct {
		name    string
		host    string
		port    int
		wantErr bool
	}{
		{"discovered ip default port", "10.0.0.5", 0, false},
		{"discovered ip explicit modbus port", "10.0.0.5", 502, false},
		{"discovered ip other open port", "10.0.0.5", 80, false},
		{"discovered ip closed port", "10.0.0.5", 22, true},
		{"second asset open port", "10.0.0.6", 44818, false},
		{"second asset modbus default allowed", "10.0.0.6", 502, false},
		{"undiscovered ip", "10.0.0.99", 502, true},
		{"cloud metadata endpoint", "169.254.169.254", 80, true},
		{"loopback not discovered", "127.0.0.1", 502, true},
		{"hostname rejected", "internal.corp", 502, true},
		{"localhost name rejected", "localhost", 502, true},
		{"empty host", "", 502, true},
		{"whitespace padded discovered ip", " 10.0.0.5 ", 502, false},
		{"port out of range", "10.0.0.5", 70000, true},
		{"negative port", "10.0.0.5", -1, true},
		{"blank asset ip is not a wildcard", "0.0.0.0", 502, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSnapshotTarget(assets, tc.host, tc.port)
			if tc.wantErr && err == nil {
				t.Fatalf("host %q port %d was allowed, want denied", tc.host, tc.port)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("host %q port %d was denied: %v", tc.host, tc.port, err)
			}
		})
	}
}

func newTestServer(t *testing.T, assets ...store.Asset) *Server {
	t.Helper()

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(db.Close)

	now := time.Now().Format(time.RFC3339)
	for i := range assets {
		a := assets[i]
		a.FirstSeen, a.LastSeen = now, now
		if err := db.UpsertAsset(&a); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}

	return New(db, nil, Options{
		AuthToken:      testToken,
		AllowedOrigins: []string{"http://localhost:3000"},
	})
}

func snapshotRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/config/snapshot", strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken)
	return req
}

// An undiscovered host must be refused by the allowlist, before any dial.
func TestSnapshotRejectsUndiscoveredHost(t *testing.T) {
	srv := newTestServer(t, store.Asset{ID: "a1", IP: "10.0.0.5", OpenPorts: []int{502}})

	cases := []struct {
		name string
		body string
	}{
		{"foreign rfc1918 host", `{"host":"192.168.9.9","port":502}`},
		{"cloud metadata host", `{"host":"169.254.169.254","port":80}`},
		{"loopback host", `{"host":"127.0.0.1","port":9200}`},
		{"hostname", `{"host":"internal.corp","port":502}`},
		{"discovered host closed port", `{"host":"10.0.0.5","port":22}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			start := time.Now()
			srv.Router().ServeHTTP(rec, snapshotRequest(tc.body))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			// A refusal that happens before the dial cannot be slow.
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("refusal took %s, the request probably reached the network", elapsed)
			}
		})
	}
}

// A failed snapshot against an allowed host must not report why it failed:
// the difference between refused, filtered and timed out is a port-scan
// oracle for the network the scanner sits on.
func TestHandleSnapshotDoesNotLeakError(t *testing.T) {
	// Port 1 on loopback: discovered in the inventory, nothing listening.
	srv := newTestServer(t, store.Asset{ID: "a1", IP: "127.0.0.1", OpenPorts: []int{1}})

	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, snapshotRequest(`{"host":"127.0.0.1","port":1,"count":1}`))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusBadGateway, rec.Body.String())
	}

	body := rec.Body.String()
	if !strings.Contains(body, snapshotFailedMsg) {
		t.Fatalf("body %q does not carry the generic failure message", body)
	}
	for _, leak := range []string{"refused", "connect", "dial", "timeout", "no route", "127.0.0.1:1"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Errorf("response leaks transport detail %q: %s", leak, body)
		}
	}
}

// Every /api route has to sit behind the token. This walks the real router
// so a route added outside the authenticated group fails the test.
func TestAPIRoutesRequireToken(t *testing.T) {
	srv := newTestServer(t, store.Asset{ID: "a1", IP: "10.0.0.5", OpenPorts: []int{502}})

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/assets"},
		{http.MethodGet, "/api/assets/a1"},
		{http.MethodGet, "/api/topology"},
		{http.MethodGet, "/api/stats"},
		{http.MethodGet, "/api/scan/status"},
		{http.MethodGet, "/api/vuln/a1"},
		{http.MethodGet, "/api/compliance"},
		{http.MethodGet, "/api/monitor/status"},
		{http.MethodGet, "/api/alerts"},
		{http.MethodGet, "/api/alerts/stats"},
		{http.MethodGet, "/api/config/snapshots/10.0.0.5"},
		{http.MethodGet, "/api/config/diff/10.0.0.5"},
		{http.MethodGet, "/api/config/devices"},
		{http.MethodPost, "/api/scan"},
		{http.MethodPost, "/api/monitor/start"},
		{http.MethodPost, "/api/monitor/stop"},
		{http.MethodPost, "/api/alerts/1/ack"},
		{http.MethodPost, "/api/config/snapshot"},
		{http.MethodPost, "/api/config/golden"},
	}

	if len(cases) != 19 {
		t.Fatalf("expected the 19 audited endpoints, listed %d", len(cases))
	}

	router := srv.Router()
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://127.0.0.1:8080"+tc.path, strings.NewReader("{}"))
			req.Host = "127.0.0.1:8080"
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, http.StatusUnauthorized, rec.Body.String())
			}
		})
	}
}

func TestAPIRouteServesWithToken(t *testing.T) {
	srv := newTestServer(t, store.Asset{ID: "a1", IP: "10.0.0.5", OpenPorts: []int{502}})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/assets", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()

	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("authenticated response missing the seeded asset: %s", rec.Body.String())
	}
}

// The inventory must not be readable when no token is configured.
func TestUnconfiguredTokenFailsClosed(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	srv := New(db, nil, Options{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/assets", nil)
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}
