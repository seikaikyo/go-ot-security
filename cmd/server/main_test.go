package main

import (
	"net"
	"strings"
	"testing"
)

// The scanner holds the full OT inventory and the per-device credential
// findings. No external origin may be trusted out of the box.
func TestDefaultCORSOriginsAreLoopbackOnly(t *testing.T) {
	for _, env := range []string{"", "   ", ",", " , "} {
		origins := resolveCORSOrigins(env)
		if len(origins) == 0 {
			t.Fatalf("env %q produced an empty allowlist", env)
		}
		for _, o := range origins {
			if strings.HasPrefix(o, "https://") {
				t.Errorf("default allowlist contains an external origin: %s", o)
			}
			host := strings.TrimPrefix(strings.TrimPrefix(o, "http://"), "https://")
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host == "localhost" {
				continue
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				t.Errorf("default allowlist origin is not loopback: %s", o)
			}
		}
	}
}

func TestResolveCORSOriginsHonoursEnv(t *testing.T) {
	got := resolveCORSOrigins("https://trace-demo.seikai.dev, http://localhost:3000 ,")
	want := []string{"https://trace-demo.seikai.dev", "http://localhost:3000"}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestResolveListenAddr(t *testing.T) {
	cases := []struct {
		name      string
		flagVal   string
		envListen string
		envPort   string
		want      string
	}{
		{"all empty defaults to loopback", "", "", "", "127.0.0.1:8080"},
		{"port env stays on loopback", "", "", "9000", "127.0.0.1:9000"},
		{"legacy 8443 port env stays on loopback", "", "", "8443", "127.0.0.1:8443"},
		{"bare colon env stays on loopback", "", ":9000", "", "127.0.0.1:9000"},
		{"bare port env stays on loopback", "", "9000", "", "127.0.0.1:9000"},
		{"env host honoured", "", "0.0.0.0:9000", "", "0.0.0.0:9000"},
		{"flag beats env", "127.0.0.1:7000", "0.0.0.0:9000", "8443", "127.0.0.1:7000"},
		{"flag exposes explicitly", "0.0.0.0:8080", "", "", "0.0.0.0:8080"},
		{"env listen beats port", "", "127.0.0.1:7000", "9000", "127.0.0.1:7000"},
		{"whitespace ignored", "  ", "  ", "  ", "127.0.0.1:8080"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveListenAddr(tc.flagVal, tc.envListen, tc.envPort); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"192.168.1.10:8080", false},
		{":8080", false},
		{"garbage", false},
	}

	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			if got := isLoopbackAddr(tc.addr); got != tc.want {
				t.Fatalf("isLoopbackAddr(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestResolveAPIToken(t *testing.T) {
	token, generated, err := resolveAPIToken("operator-supplied")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if generated {
		t.Error("operator token reported as generated")
	}
	if token != "operator-supplied" {
		t.Errorf("token = %q, want the operator value", token)
	}

	a, generatedA, err := resolveAPIToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !generatedA {
		t.Error("minted token not reported as generated")
	}
	if len(a) != 64 {
		t.Errorf("generated token is %d hex chars, want 64 (256 bits)", len(a))
	}

	b, _, err := resolveAPIToken("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == b {
		t.Error("generated token is not random between runs")
	}
}
