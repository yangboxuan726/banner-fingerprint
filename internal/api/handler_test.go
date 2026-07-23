package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"banner-fingerprint/internal/fingerprint"
)

func testEngine(t *testing.T) *fingerprint.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	const rules = `{
		"version": 1,
		"rules": [
			{
				"protocol": "SSH",
				"product": "OpenSSH",
				"pattern": "^SSH-[0-9.]+-OpenSSH_(?P<version>[0-9.p]+)",
				"confidence": 0.95
			}
		]
	}`
	if err := os.WriteFile(path, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	engine, err := fingerprint.Load(path)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return engine
}

func performRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestHealth(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{})
	response := performRequest(handler, http.MethodGet, "/health", "")

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body)
	}
	var body struct {
		Status string `json:"status"`
		Rules  int    `json:"rules"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "ok" || body.Rules != 1 {
		t.Fatalf("response = %+v, want status=ok rules=1", body)
	}
}

func TestHealthReportsUnreadyEngine(t *testing.T) {
	handler := NewHandler(nil, Config{})
	response := performRequest(handler, http.MethodGet, "/health", "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestFingerprintBatchPreservesOrderAndUnknown(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{})
	body := `[
		{"ip":"192.0.2.1","port":2222,"banner":"SSH-2.0-OpenSSH_9.3p1"},
		{"ip":"192.0.2.2","port":9999,"banner":"not a known service"}
	]`
	response := performRequest(handler, http.MethodPost, "/fingerprint", body)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusOK, response.Body)
	}
	var results []fingerprint.Result
	if err := json.Unmarshal(response.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("result count = %d, want 2", len(results))
	}
	if results[0].IP != "192.0.2.1" || results[0].Protocol != "SSH" ||
		results[0].Product != "OpenSSH" || results[0].Version != "9.3p1" {
		t.Errorf("first result = %+v", results[0])
	}
	if results[1].IP != "192.0.2.2" || results[1].Protocol != "unknown" ||
		results[1].Product != "" || results[1].Version != "" ||
		results[1].Confidence != 0 {
		t.Errorf("unknown result = %+v", results[1])
	}
}

func TestFingerprintRejectsInvalidJSON(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{})
	for _, body := range []string{
		`{"ip":"192.0.2.1"}`,
		`[{"ip":`,
		`null`,
		`[] []`,
	} {
		response := performRequest(handler, http.MethodPost, "/fingerprint", body)
		if response.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want %d", body, response.Code, http.StatusBadRequest)
		}
		if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
			t.Errorf("body %q: Content-Type = %q, want application/json", body, contentType)
		}
	}
}

func TestMethodsAreRestricted(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{})
	tests := []struct {
		path  string
		allow string
	}{
		{path: "/health", allow: http.MethodGet},
		{path: "/fingerprint", allow: http.MethodPost},
	}
	for _, test := range tests {
		response := performRequest(handler, http.MethodPut, test.path, "")
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want %d", test.path, response.Code, http.StatusMethodNotAllowed)
		}
		if got := response.Header().Get("Allow"); got != test.allow {
			t.Errorf("%s: Allow = %q, want %q", test.path, got, test.allow)
		}
	}
}

func TestFingerprintRejectsOversizedBatch(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{MaxBatchSize: 1})
	response := performRequest(handler, http.MethodPost, "/fingerprint",
		`[{"ip":"192.0.2.1"},{"ip":"192.0.2.2"}]`)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusRequestEntityTooLarge, response.Body)
	}
}

func TestFingerprintRejectsOversizedBody(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{MaxBodyBytes: 8})
	response := performRequest(handler, http.MethodPost, "/fingerprint",
		`[{"ip":"192.0.2.1"}]`)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, http.StatusRequestEntityTooLarge, response.Body)
	}
}

func TestFingerprintEmptyBatchReturnsArray(t *testing.T) {
	handler := NewHandler(testEngine(t), Config{})
	response := performRequest(handler, http.MethodPost, "/fingerprint", `[]`)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(response.Body.String()); got != "[]" {
		t.Fatalf("body = %q, want []", got)
	}
}
