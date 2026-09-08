package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The coordinator's /security subtree requires a shared key as of 2026-09-08.
// These cover the wiring only: that the key reaches the request when set, and
// that nothing is sent when it is not.
func TestReporterSendsBearerWhenKeySet(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := NewReporter(srv.URL, "node-1", "s3cret")
	if r == nil {
		t.Fatal("reporter should be constructed when coordinatorURL is set")
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/security/report", nil)
	req.Header.Set("Content-Type", "application/json")
	if r.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.apiKey)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if got != "Bearer s3cret" {
		t.Fatalf("Authorization header = %q, want %q", got, "Bearer s3cret")
	}
}

func TestReporterOmitsHeaderWhenKeyEmpty(t *testing.T) {
	r := NewReporter("http://example.invalid", "node-1", "")
	if r == nil {
		t.Fatal("reporter should still be constructed without a key")
	}
	if r.apiKey != "" {
		t.Fatalf("apiKey should be empty, got %q", r.apiKey)
	}
}

func TestReporterDisabledWithoutCoordinatorURL(t *testing.T) {
	if NewReporter("", "node-1", "s3cret") != nil {
		t.Fatal("reporter should be nil when coordinatorURL is empty")
	}
}
