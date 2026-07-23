package fingerprint

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadProductionRules(t *testing.T) *Engine {
	t.Helper()
	engine, err := Load(filepath.Join("..", "..", "rules", "rules.json"))
	if err != nil {
		t.Fatalf("Load production rules: %v", err)
	}
	return engine
}

func TestProductionRulesRecogniseSampleBanners(t *testing.T) {
	t.Parallel()

	engine := loadProductionRules(t)
	tests := []struct {
		name   string
		target Target
		want   Result
	}{
		{
			name:   "OpenSSH Ubuntu",
			target: Target{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
			want:   Result{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		},
		{
			name:   "nginx",
			target: Target{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"},
			want:   Result{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		},
		{
			name:   "Apache",
			target: Target{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"},
			want:   Result{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.9},
		},
		{
			name:   "MySQL 8 binary handshake",
			target: Target{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"},
			want:   Result{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9},
		},
		{
			name:   "Redis error",
			target: Target{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"},
			want:   Result{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		},
		{
			name:   "ProFTPD",
			target: Target{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"},
			want:   Result{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		},
		{
			name:   "Jetty",
			target: Target{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"},
			want:   Result{IP: "1.2.3.10", Port: 8080, Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.85},
		},
		{
			name:   "OpenSSH Debian",
			target: Target{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"},
			want:   Result{IP: "1.2.3.11", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95},
		},
		{
			name:   "nginx Ubuntu",
			target: Target{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"},
			want:   Result{IP: "1.2.3.12", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.9},
		},
		{
			name:   "Apache Ubuntu",
			target: Target{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"},
			want:   Result{IP: "1.2.3.13", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.9},
		},
		{
			name:   "MySQL 5 binary handshake",
			target: Target{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"},
			want:   Result{IP: "1.2.3.14", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", Confidence: 0.9},
		},
		{
			name:   "Redis pong",
			target: Target{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"},
			want:   Result{IP: "1.2.3.15", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		},
		{
			name:   "vsFTPd",
			target: Target{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"},
			want:   Result{IP: "1.2.3.16", Port: 21, Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5", Confidence: 0.9},
		},
		{
			name:   "nginx non-standard port",
			target: Target{IP: "1.2.3.17", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"},
			want:   Result{IP: "1.2.3.17", Port: 8443, Protocol: "HTTP", Product: "nginx", Version: "1.25.3", Confidence: 0.9},
		},
		{
			name:   "SSH 1.99",
			target: Target{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"},
			want:   Result{IP: "1.2.3.18", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "4.3", Confidence: 0.95},
		},
		{
			name:   "libssh",
			target: Target{IP: "1.2.3.18-libssh", Port: 2222, Banner: "SSH-2.0-libssh_0.10.5"},
			want:   Result{IP: "1.2.3.18-libssh", Port: 2222, Protocol: "SSH", Product: "libssh", Version: "0.10.5", Confidence: 0.9},
		},
		{
			name:   "OpenSSH non-OS suffix is not an OS hint",
			target: Target{IP: "1.2.3.18-hpn", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 hpn14v15"},
			want:   Result{IP: "1.2.3.18-hpn", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", Confidence: 0.95},
		},
		{
			name:   "HTTP build metadata is not an OS hint",
			target: Target{IP: "1.2.3.18-build", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.26.3 (build 123)"},
			want:   Result{IP: "1.2.3.18-build", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.26.3", Confidence: 0.9},
		},
		{
			name:   "TLS handshake",
			target: Target{IP: "1.2.3.19", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"},
			want:   Result{IP: "1.2.3.19", Port: 9999, Protocol: "TLS", Confidence: 0.6},
		},
		{
			name:   "Microsoft IIS",
			target: Target{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"},
			want:   Result{IP: "1.2.3.20", Port: 8888, Protocol: "HTTP", Product: "Microsoft-IIS", Version: "10.0", Confidence: 0.9},
		},
		{
			name:   "Redis noauth",
			target: Target{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."},
			want:   Result{IP: "1.2.3.21", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		},
		{
			name:   "Pure FTPd",
			target: Target{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"},
			want:   Result{IP: "1.2.3.22", Port: 21, Protocol: "FTP", Product: "Pure-FTPd", Confidence: 0.8},
		},
		{
			name:   "unknown banner",
			target: Target{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"},
			want:   Result{IP: "1.2.3.23", Port: 12345, Protocol: "unknown"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := engine.Identify(tt.target)
			if got != tt.want {
				t.Fatalf("Identify() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIdentifyBatchPreservesOrderAndUnknowns(t *testing.T) {
	t.Parallel()

	engine := loadProductionRules(t)
	targets := []Target{
		{IP: "first", Port: 12345, Banner: ""},
		{IP: "second", Port: 80, Banner: "HTTP/1.1 204 No Content\r\n"},
		{IP: "third", Port: 22, Banner: "not ssh"},
	}

	got := engine.IdentifyBatch(targets)
	if len(got) != len(targets) {
		t.Fatalf("IdentifyBatch() returned %d results, want %d", len(got), len(targets))
	}
	for i := range targets {
		if got[i].IP != targets[i].IP || got[i].Port != targets[i].Port {
			t.Errorf("result %d lost input identity: got %#v, input %#v", i, got[i], targets[i])
		}
	}
	if got[0].Protocol != "unknown" || got[1].Protocol != "HTTP" || got[2].Protocol != "unknown" {
		t.Fatalf("unexpected batch protocols: %#v", got)
	}
}

func TestIdentifyIsPortIndependentForStrongSignatures(t *testing.T) {
	t.Parallel()

	engine := loadProductionRules(t)
	tests := []Target{
		{Port: 65022, Banner: "SSH-2.0-OpenSSH_9.8"},
		{Port: 60080, Banner: "HTTP/1.1 200 OK\nserver: nginx/1.27.0"},
		{Port: 63306, Banner: "\n8.4.0\x00"},
		{Port: 66379, Banner: "-NOAUTH Authentication required."},
		{Port: 60021, Banner: "220 ProFTPD 1.3.8 Server"},
	}
	wantProtocols := []string{"SSH", "HTTP", "MySQL", "Redis", "FTP"}

	for i, target := range tests {
		got := engine.Identify(target)
		if got.Protocol != wantProtocols[i] {
			t.Errorf("Identify(%q on %d).Protocol = %q, want %q", target.Banner, target.Port, got.Protocol, wantProtocols[i])
		}
	}
}

func TestKnownProductsRemainIdentifiableWithoutVersions(t *testing.T) {
	t.Parallel()

	engine := loadProductionRules(t)
	tests := []struct {
		banner  string
		product string
	}{
		{banner: "HTTP/1.1 200 OK\r\nServer: Jetty", product: "Jetty"},
		{banner: "220 ProFTPD Server ready", product: "ProFTPD"},
		{banner: "220 Welcome to vsFTPd", product: "vsFTPd"},
		{banner: "220 Welcome to Pure-FTPd", product: "Pure-FTPd"},
	}
	for _, tt := range tests {
		got := engine.Identify(Target{Port: 65000, Banner: tt.banner})
		if got.Product != tt.product || got.Version != "" {
			t.Errorf("Identify(%q) = %#v, want product %q without a version", tt.banner, got, tt.product)
		}
	}
}

func TestNilEngineAndArbitraryBannerReturnSafely(t *testing.T) {
	t.Parallel()

	target := Target{IP: "::1", Port: -1, Banner: string([]byte{0xff, 0xfe, 0x00, 0x01})}
	var engine *Engine
	got := engine.Identify(target)
	want := Result{IP: "::1", Port: -1, Protocol: "unknown"}
	if got != want {
		t.Fatalf("nil Engine Identify() = %#v, want %#v", got, want)
	}
	if engine.Len() != 0 {
		t.Fatalf("nil Engine Len() = %d, want 0", engine.Len())
	}
}

func TestRulesAreFirstMatchWins(t *testing.T) {
	t.Parallel()

	engine := loadRulesText(t, `{
		"version": 1,
		"rules": [
			{"id":"generic-first","protocol":"HTTP","product":"generic","pattern":"nginx","confidence":0.4},
			{"id":"specific-second","protocol":"HTTP","product":"nginx","pattern":"nginx/(?P<version>[0-9.]+)","confidence":0.9}
		]
	}`)
	got := engine.Identify(Target{Banner: "nginx/1.24.0"})
	if got.Product != "generic" || got.Version != "" || got.Confidence != 0.4 {
		t.Fatalf("Identify() did not honor first-match ordering: %#v", got)
	}
}

func TestLoadRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		document    string
		wantErrPart string
	}{
		{name: "malformed JSON", document: `{`, wantErrPart: "parse rules"},
		{name: "trailing document", document: `{"version":1,"rules":[{"protocol":"X","pattern":"x","confidence":1}]} {}`, wantErrPart: "unexpected data"},
		{name: "unknown field", document: `{"version":1,"rules":[],"typo":true}`, wantErrPart: "unknown field"},
		{name: "unsupported schema", document: `{"version":2,"rules":[{"protocol":"X","pattern":"x","confidence":1}]}`, wantErrPart: "unsupported schema"},
		{name: "no rules", document: `{"version":1,"rules":[]}`, wantErrPart: "contains no rules"},
		{name: "empty protocol", document: `{"version":1,"rules":[{"protocol":" ","pattern":"x","confidence":1}]}`, wantErrPart: "empty protocol"},
		{name: "empty pattern", document: `{"version":1,"rules":[{"protocol":"X","pattern":"","confidence":1}]}`, wantErrPart: "empty pattern"},
		{name: "invalid regexp", document: `{"version":1,"rules":[{"protocol":"X","pattern":"(","confidence":1}]}`, wantErrPart: "invalid pattern"},
		{name: "negative confidence", document: `{"version":1,"rules":[{"protocol":"X","pattern":"x","confidence":-0.1}]}`, wantErrPart: "outside [0,1]"},
		{name: "confidence over one", document: `{"version":1,"rules":[{"protocol":"X","pattern":"x","confidence":1.1}]}`, wantErrPart: "outside [0,1]"},
		{name: "invalid low port", document: `{"version":1,"rules":[{"protocol":"X","pattern":"x","ports":[0],"confidence":1}]}`, wantErrPart: "invalid port"},
		{name: "invalid high port", document: `{"version":1,"rules":[{"protocol":"X","pattern":"x","ports":[65536],"confidence":1}]}`, wantErrPart: "invalid port"},
		{name: "duplicate id", document: `{"version":1,"rules":[{"id":"same","protocol":"X","pattern":"x","confidence":1},{"id":"same","protocol":"Y","pattern":"y","confidence":1}]}`, wantErrPart: "duplicate rule id"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeRulesText(t, tt.document)
			_, err := Load(path)
			if err == nil {
				t.Fatal("Load() error = nil, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("Load() error = %q, want it to contain %q", err, tt.wantErrPart)
			}
		})
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil || !strings.Contains(err.Error(), "read rules") {
		t.Fatalf("Load(missing) error = %v, want read rules error", err)
	}
}

func TestLoadAcceptsConfidenceBoundsAndStaticDefaults(t *testing.T) {
	t.Parallel()

	engine := loadRulesText(t, `{
		"version": 1,
		"rules": [
			{
				"id": "static",
				"protocol": "TEST",
				"product": "Static Product",
				"version": "static-version",
				"os_hint": "Static OS",
				"pattern": "(?P<version>captured-version)",
				"confidence": 0
			}
		]
	}`)
	got := engine.Identify(Target{Banner: "captured-version"})
	want := Result{
		Protocol: "TEST", Product: "Static Product", Version: "captured-version",
		OSHint: "Static OS", Confidence: 0,
	}
	if got != want {
		t.Fatalf("Identify() = %#v, want %#v", got, want)
	}
}

func TestLoadAcceptsOriginalUnversionedSchema(t *testing.T) {
	t.Parallel()

	engine := loadRulesText(t, `{
		"rules": [
			{"protocol":"TEST","product":"compatible","pattern":"match","confidence":1}
		]
	}`)
	got := engine.Identify(Target{Banner: "match"})
	if got.Protocol != "TEST" || got.Product != "compatible" {
		t.Fatalf("Identify() with unversioned rules = %#v", got)
	}
}

func loadRulesText(t *testing.T, document string) *Engine {
	t.Helper()
	engine, err := Load(writeRulesText(t, document))
	if err != nil {
		t.Fatalf("Load temporary rules: %v", err)
	}
	return engine
}

func writeRulesText(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("rules-%s.json", strings.ReplaceAll(t.Name(), "/", "-")))
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write temporary rules: %v", err)
	}
	return path
}

func FuzzIdentifyNeverPanics(f *testing.F) {
	engine, err := Load(filepath.Join("..", "..", "rules", "rules.json"))
	if err != nil {
		f.Fatalf("Load production rules: %v", err)
	}
	f.Add(0, "")
	f.Add(22, "SSH-2.0-OpenSSH_9.8")
	f.Add(3306, "J\x00\x00\x00\n8.0.32\x00")
	f.Add(6379, string([]byte{0xff, 0x00, 0xfe}))

	f.Fuzz(func(t *testing.T, port int, banner string) {
		result := engine.Identify(Target{IP: "fuzz", Port: port, Banner: banner})
		if result.Confidence < 0 || result.Confidence > 1 {
			t.Fatalf("confidence %g is outside [0,1]", result.Confidence)
		}
		if result.Protocol == "" {
			t.Fatal("protocol must never be empty")
		}
	})
}
