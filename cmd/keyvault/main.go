package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"keyvault/internal/database"
	"keyvault/internal/handlers"
	"keyvault/internal/security"
	"keyvault/web"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func durationEnvOr(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("ignoring invalid %s value %q", key, v)
	}
	return fallback
}

func main() {
	addr := flag.String("addr", envOr("KEYVAULT_ADDR", "127.0.0.1:8080"), "listen address")
	dataDir := flag.String("data-dir", envOr("KEYVAULT_DATA_DIR", "data"), "directory for the database file")
	sessionTimeout := flag.Duration("session-timeout", durationEnvOr("KEYVAULT_SESSION_TIMEOUT", 15*time.Minute), "idle session timeout")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}
	dbPath := filepath.Join(*dataDir, "keyvault.db")
	db, err := database.Open(dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := db.Ping(); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.Handle("/", http.FileServer(http.FS(web.FS)))

	auth := security.NewAuth(db)
	sessions := security.NewSessionManager(auth, *sessionTimeout)
	authHandler := &handlers.AuthHandler{Auth: auth, Sessions: sessions}
	mux.HandleFunc("GET /api/auth/status", authHandler.Status)
	mux.HandleFunc("POST /api/auth/setup", authHandler.Setup)
	mux.HandleFunc("POST /api/auth/unlock", authHandler.Unlock)
	mux.HandleFunc("POST /api/auth/lock", authHandler.Lock)
	// Unmatched /api routes still require an unlocked session.
	mux.Handle("/api/", handlers.RequireSession(sessions, http.NotFoundHandler()))

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("KeyVault listening on http://%s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
