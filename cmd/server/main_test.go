package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunHealthcheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/health" {
			t.Errorf("request = %s %s, want GET /health", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	if err := runHealthcheck([]string{"-url", server.URL + "/health", "-timeout", "1s"}); err != nil {
		t.Fatalf("runHealthcheck: %v", err)
	}
}

func TestRunHealthcheckRejectsUnhealthyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"unhealthy"}`))
	}))
	defer server.Close()

	err := runHealthcheck([]string{"-url", server.URL, "-timeout", "1s"})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("error = %v, want 503 error", err)
	}
}

func TestPositiveIntEnvironmentParsing(t *testing.T) {
	t.Setenv("TEST_POSITIVE_INT", "42")
	got, err := positiveIntEnv("TEST_POSITIVE_INT", 1)
	if err != nil || got != 42 {
		t.Fatalf("positiveIntEnv = %d, %v; want 42, nil", got, err)
	}
	t.Setenv("TEST_POSITIVE_INT", "0")
	if _, err := positiveIntEnv("TEST_POSITIVE_INT", 1); err == nil {
		t.Fatal("positiveIntEnv accepted zero")
	}
}
