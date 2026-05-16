package main

import (
	"fmt"
	"log/slog"
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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8443"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "ot-security.db"
	}

	coordinatorURL := os.Getenv("COORDINATOR_URL")
	nodeID := os.Getenv("NODE_ID")
	if nodeID == "" {
		nodeID = "ot-security-default"
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

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

	// Server
	srv := server.New(db, reporter)

	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// CORS: trace-demo (Vercel) + local dev call the scanner API directly
	// over HTTP/JSON. Override with CORS_ALLOWED_ORIGINS (CSV) if you run
	// the demo against a different frontend origin.
	corsOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if corsOrigins == "" {
		// 5173 is the trace-demo dev port that pairs with dashai-go's
		// debug-mode CORS allowlist (5173-5176). Without it the local
		// stack triggers a "Failed to fetch" on the Scan modal.
		corsOrigins = "http://localhost:3000,http://localhost:5173,https://trace-demo.seikai.dev"
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   strings.Split(corsOrigins, ","),
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Health
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","app":"go-ot-security","version":"%s"}`, version)
	})

	// Mount all routes
	r.Mount("/", srv.Router())

	addr := ":" + port
	httpSrv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("OT Security Platform starting", "addr", addr, "version", version)
		slog.Info("open browser", "url", "http://localhost"+addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-done
	slog.Info("shutting down")
	httpSrv.Shutdown(nil)
}
