package localui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"monicheck/internal/localruntime"
	"monicheck/internal/model"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	address string
	runtime *localruntime.Runtime
}

func New(address string, runtime *localruntime.Runtime) *Server {
	return &Server{address: address, runtime: runtime}
}
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	assets, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return err
	}
	mux.Handle("/ui/static/", http.StripPrefix("/ui/static/", http.FileServer(http.FS(assets))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/ui/static/", http.StatusFound) })
	mux.HandleFunc("/api/v1/local/report", s.report)
	mux.HandleFunc("/api/v1/local/status", s.status)
	server := &http.Server{Addr: s.address, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	export, err := s.runtime.LatestReport(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(export.Content))
}
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	statuses := s.runtime.Engine.ConnectorStatuses()
	views := make([]connectorStatusView, 0, len(statuses))
	for _, status := range statuses {
		views = append(views, connectorStatusView{ConnectorStatus: status, Group: localruntime.ConnectorGroup(status.ID)})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"connectors": views})
}

type connectorStatusView struct {
	model.ConnectorStatus
	Group string `json:"group"`
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
		next.ServeHTTP(w, r)
	})
}
