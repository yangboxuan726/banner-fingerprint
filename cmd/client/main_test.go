package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"banner-fingerprint/internal/fingerprint"
)

func writeInput(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	return path
}

func TestRunPostsBatchAndPrintsIndentedResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/fingerprint" {
			t.Errorf("request = %s %s, want POST /fingerprint", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}
		var targets []fingerprint.Target
		if err := json.NewDecoder(r.Body).Decode(&targets); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(targets) != 1 || targets[0].IP != "192.0.2.10" {
			t.Errorf("targets = %+v", targets)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]fingerprint.Result{{
			IP:         "192.0.2.10",
			Port:       22,
			Protocol:   "SSH",
			Product:    "OpenSSH",
			Version:    "9.3",
			Confidence: 0.95,
		}})
	}))
	defer server.Close()

	input := writeInput(t, `[{"ip":"192.0.2.10","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}]`)
	var output bytes.Buffer
	err := run([]string{"-input", input, "-server", server.URL, "-timeout", "2s"}, &output)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(output.String(), "\n  {") || !strings.Contains(output.String(), `"protocol": "SSH"`) {
		t.Fatalf("output is not the expected indented JSON: %s", output.String())
	}
}

func TestRunReportsNonSuccessResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"batch exceeds record limit"}`, http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()

	input := writeInput(t, `[]`)
	err := run([]string{"-input", input, "-server", server.URL}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "413") ||
		!strings.Contains(err.Error(), "batch exceeds record limit") {
		t.Fatalf("error = %v, want status and server message", err)
	}
}

func TestRunRejectsInvalidLocalInputBeforeRequest(t *testing.T) {
	input := writeInput(t, `{"ip":"192.0.2.10"}`)
	err := run([]string{"-input", input}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "decode input") {
		t.Fatalf("error = %v, want decode input error", err)
	}
}

func TestDecodeTargetsRejectsNullAndTrailingJSON(t *testing.T) {
	for _, input := range []string{`null`, `[] []`} {
		if _, err := decodeTargets([]byte(input)); err == nil {
			t.Errorf("decodeTargets(%q) unexpectedly succeeded", input)
		}
	}
}
