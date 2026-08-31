package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/seikaikyo/go-ot-security/internal/agent"
	"github.com/seikaikyo/go-ot-security/internal/server"
	"github.com/seikaikyo/go-ot-security/internal/store"
)

var version = "0.1.0"

// defaultListenAddr keeps the scanner on the loopback interface. The API
// serves the full OT inventory and the per-device default-credential
// findings, so reaching it from the network has to be a deliberate act.
const defaultListenAddr = "127.0.0.1:8080"

func main() {
	listenFlag := flag.String("listen", "",
		"listen address, host:port (default "+defaultListenAddr+"; set a non-loopback host to expose the API on the network)")
	flag.Parse()

	listenAddr := resolveListenAddr(*listenFlag, os.Getenv("OTSEC_LISTEN"), os.Getenv("PORT"))

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "ot-security.db"
	}

	coordinatorURL := os.Getenv("COORDINATOR_URL")
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		nodeID = "ot-security-default"
	}

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	tlsEnabled := certFile != "" && keyFile != ""

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	// API token. Supplied by the operator, or minted once per process and
	// printed to the console so a local run stays usable.
	token, generated, err := resolveAPIToken(os.Getenv("OTSEC_API_TOKEN"))
	if err != nil {
		slog.Error("failed to generate api token", "error", err)
		os.Exit(1)
	}

	// Database
	db, err := store.Open(dbPath)
	if err != nil {
		slog.Error("database open failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Coordinator reporter
	reporter := agent.NewReporter(coordinatorURL, nodeID)
	if reporter != nil {
		slog.Info("coordinator reporter enabled", "url", coordinatorURL, "node_id", nodeID)
	}

	// CORS: only loopback development origins by default. The scanner holds
	// the full OT inventory, so any external origin has to be named
	// explicitly through CORS_ALLOWED_ORIGINS (CSV).
	corsOrigins := resolveCORSOrigins(os.Getenv("CORS_ALLOWED_ORIGINS"))

	// Server
	srv := server.New(db, reporter, server.Options{
		AuthToken:      token,
		AllowedOrigins: corsOrigins,
	})

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   corsOrigins,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Authorization", "X-API-Token"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Health: unauthenticated on purpose so a supervisor or container probe
	// works without holding the API token. It exposes no scan data.
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","app":"go-ot-security","version":"%s"}`, version)
	})

	// Mount all routes
	r.Mount("/", srv.Router())

	httpSrv := &http.Server{
		Addr:         listenAddr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	if !isLoopbackAddr(listenAddr) && !tlsEnabled {
		slog.Warn("listening beyond loopback without TLS: the OT inventory and credential findings cross the network in plaintext",
			"addr", listenAddr, "hint", "set TLS_CERT_FILE and TLS_KEY_FILE")
	}
	if generated {
		printGeneratedToken(token, scheme+"://"+listenAddr)
	}

	go func() {
		slog.Info("OT Security Platform starting", "addr", listenAddr, "version", version, "tls", tlsEnabled)
		slog.Info("open browser", "url", scheme+"://"+listenAddr)

		var err error
		if tlsEnabled {
			err = httpSrv.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	slog.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

// resolveListenAddr picks the listen address, most explicit source first.
// PORT alone keeps working but stays on loopback: an operator who wants the
// API on the network has to say so with -listen or OTSEC_LISTEN.
func resolveListenAddr(flagVal, envListen, envPort string) string {
	if v := strings.TrimSpace(flagVal); v != "" {
		return normalizeAddr(v)
	}
	if v := strings.TrimSpace(envListen); v != "" {
		return normalizeAddr(v)
	}
	if v := strings.TrimSpace(envPort); v != "" {
		return "127.0.0.1:" + v
	}
	return defaultListenAddr
}

// normalizeAddr accepts "8080", ":8080" and "host:port". A bare port or a
// bare colon means loopback, never every interface.
func normalizeAddr(v string) string {
	if !strings.Contains(v, ":") {
		return "127.0.0.1:" + v
	}
	if strings.HasPrefix(v, ":") {
		return "127.0.0.1" + v
	}
	return v
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// resolveCORSOrigins defaults to loopback development origins only.
// 3000 and 5173 are the local frontend dev ports.
func resolveCORSOrigins(env string) []string {
	if v := strings.TrimSpace(env); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{
		"http://localhost:3000",
		"http://127.0.0.1:3000",
		"http://localhost:5173",
		"http://127.0.0.1:5173",
	}
}

// resolveAPIToken returns the operator token, or mints a 256-bit one.
// The second return value reports whether the token was generated.
func resolveAPIToken(env string) (string, bool, error) {
	if v := strings.TrimSpace(env); v != "" {
		return v, false, nil
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", false, err
	}
	return hex.EncodeToString(buf), true, nil
}

// printGeneratedToken writes the one-time token to stderr, outside the JSON
// log stream, so it is readable at the console but easy to keep out of a log
// shipper that only collects stdout.
func printGeneratedToken(token, baseURL string) {
	fmt.Fprintf(os.Stderr, `
================================================================
 API token (generated for this run, not persisted):

   %s

 Use it on every /api request:
   curl -H "Authorization: Bearer %s" %s/api/assets

 Set OTSEC_API_TOKEN to pin your own token instead.
================================================================

`, token, token, baseURL)
}
