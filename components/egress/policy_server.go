package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/dnsproxy"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
)

// startPolicyServer launches a lightweight HTTP API for updating the egress policy at runtime.
// Supported endpoints:
//   - GET  /policy : returns the currently enforced policy (null when allow-all).
//   - POST /policy : replace the policy; empty body clears restrictions (allow-all).
func startPolicyServer(ctx context.Context, proxy *dnsproxy.Proxy, addr string, token string) error {
	mux := http.NewServeMux()
	handler := &policyServer{proxy: proxy, token: token}
	mux.HandleFunc("/policy", handler.handlePolicy)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	handler.server = srv

	// Shutdown listener when context ends.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("policy server shutdown error: %v", err)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-time.After(200 * time.Millisecond):
		// assume healthy start; keep logging future errors
		go func() {
			if err := <-errCh; err != nil {
				log.Printf("policy server error: %v", err)
			}
		}()
		return nil
	}
}

type policyServer struct {
	proxy  *dnsproxy.Proxy
	server *http.Server
	token  string
}

func (s *policyServer) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleGet(w)
	case http.MethodPost, http.MethodPut:
		s.handlePost(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *policyServer) handleGet(w http.ResponseWriter) {
	current := s.proxy.CurrentPolicy()
	mode := "enforcing"
	if current == nil {
		mode = "allow_all"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":   mode,
		"policy": current,
	})
}

func (s *policyServer) handlePost(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
		return
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		s.proxy.UpdatePolicy(nil)
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
			"mode":   "allow_all",
			"reason": "policy cleared",
		})
		return
	}

	pol, err := policy.ParsePolicy(raw)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid policy: %v", err), http.StatusBadRequest)
		return
	}
	s.proxy.UpdatePolicy(pol)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"mode":   "enforcing",
	})
}

func (s *policyServer) authorize(r *http.Request) bool {
	if s.token == "" {
		return true
	}
	provided := r.Header.Get(policy.EgressAuthTokenHeader)
	if provided == "" {
		return false
	}
	if len(provided) != len(s.token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.token)) == 1
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
