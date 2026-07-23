// Package api exposes the HTTP transport for the fingerprint engine.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"banner-fingerprint/internal/fingerprint"
)

const (
	// DefaultMaxBodyBytes is deliberately larger than a typical scan batch but
	// still bounds memory usage for untrusted requests.
	DefaultMaxBodyBytes int64 = 4 << 20
	// DefaultMaxBatchSize prevents one request monopolising the server.
	DefaultMaxBatchSize = 1000
)

// Config controls request limits. Zero values select the documented defaults.
type Config struct {
	MaxBodyBytes int64
	MaxBatchSize int
}

// Handler serves health and fingerprint requests.
type Handler struct {
	engine       *fingerprint.Engine
	maxBodyBytes int64
	maxBatchSize int
}

// NewHandler builds the HTTP API. A nil engine is allowed so the health
// endpoint can accurately report an unready process, although production
// startup should fail before serving when rules cannot be loaded.
func NewHandler(engine *fingerprint.Engine, cfg Config) http.Handler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxBatchSize <= 0 {
		cfg.MaxBatchSize = DefaultMaxBatchSize
	}

	h := &Handler{
		engine:       engine,
		maxBodyBytes: cfg.MaxBodyBytes,
		maxBatchSize: cfg.MaxBatchSize,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/fingerprint", h.fingerprint)
	return recoverer(mux)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.engine == nil || h.engine.Len() == 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unhealthy",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"rules":  h.engine.Len(),
	})
}

func (h *Handler) fingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.engine == nil || h.engine.Len() == 0 {
		writeError(w, http.StatusServiceUnavailable, "fingerprint engine is not ready")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.maxBodyBytes)
	defer r.Body.Close()

	var targets []fingerprint.Target
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&targets); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
			return
		}
		writeError(w, http.StatusBadRequest, "request body must be a JSON array")
		return
	}
	if targets == nil {
		writeError(w, http.StatusBadRequest, "request body must be a JSON array")
		return
	}

	// A valid request contains exactly one JSON value. This catches accidental
	// concatenation and makes the API behaviour deterministic.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds limit")
			return
		}
		writeError(w, http.StatusBadRequest, "request body must contain exactly one JSON array")
		return
	}
	if len(targets) > h.maxBatchSize {
		writeError(w, http.StatusRequestEntityTooLarge, "batch exceeds record limit")
		return
	}

	writeJSON(w, http.StatusOK, h.engine.IdentifyBatch(targets))
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
