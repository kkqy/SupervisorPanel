package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"supervisorpanel/internal/config"
	"supervisorpanel/internal/db"
	"supervisorpanel/internal/server"
	"supervisorpanel/internal/supervisor"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if len(os.Args) > 1 && os.Args[1] == "init-admin" {
		initAdminCmd(os.Args[2:])
		return
	}
	serveCmd()
}

func serveCmd() {
	cfg := config.Load()
	if err := os.MkdirAll(cfg.ProjectsDir, 0o755); err != nil {
		log.Fatalf("create projects dir failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o755); err != nil {
		log.Fatalf("create db dir failed: %v", err)
	}

	store, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db failed: %v", err)
	}
	defer store.Close()
	_ = store.CleanupExpiredSessions()

	sup := supervisor.New(cfg.SupervisorConfDir, cfg.SupervisorctlBin)
	srv, err := server.New(cfg, store, sup)
	if err != nil {
		log.Fatalf("init server failed: %v", err)
	}

	httpServer := &http.Server{
		Addr:         cfg.Addr,
		Handler:      srv.Routes(),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Printf("SupervisorPanel listening on %s", cfg.Addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http serve failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	_ = httpServer.Close()
}

func initAdminCmd(args []string) {
	fs := flag.NewFlagSet("init-admin", flag.ExitOnError)
	dbPath := fs.String("db", "./data/supervisor-panel.db", "sqlite db path")
	username := fs.String("username", "", "admin username")
	password := fs.String("password", "", "admin password")
	_ = fs.Parse(args)

	if *username == "" || *password == "" {
		log.Fatal("username and password are required")
	}
	store, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db failed: %v", err)
	}
	defer store.Close()

	cfg := config.Load()
	srv, err := server.New(cfg, store, supervisor.New(cfg.SupervisorConfDir, cfg.SupervisorctlBin))
	if err != nil {
		log.Fatalf("init server failed: %v", err)
	}
	if err := srv.InitAdmin(*username, *password); err != nil {
		log.Fatalf("init admin failed: %v", err)
	}
	log.Printf("admin '%s' initialized", *username)
}
