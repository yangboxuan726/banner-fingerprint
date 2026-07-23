// Package fingerprint holds the data-driven banner recognition engine.
//
// The engine loads signatures from an external JSON file (rules.json) at runtime,
// so recognition rules stay fully decoupled from program code: operators can add
// or tune signatures by editing data, never by recompiling.
package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// Target is one raw scan record fed into the engine.
type Target struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Result is the identification output for a single target.
// Unrecognised targets return Protocol == "unknown" (never an error).
type Result struct {
	IP         string  `json:"ip"`
	Port       int     `json:"port"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version"`
	OSHint     string  `json:"os_hint"`
	Confidence float64 `json:"confidence"`
}

// Rule is one data-driven signature loaded from rules.json.
//
// Pattern is a Go regular expression. Optional named capture groups
// "product", "version" and "os_hint" are lifted into the Result and override
// the corresponding static defaults. Ports, when non-empty, restrict the rule
// to those ports (reduces false positives for generic banners such as a bare
// "220 " greeting).
type Rule struct {
	ID         string  `json:"id,omitempty"`
	Protocol   string  `json:"protocol"`
	Product    string  `json:"product"`
	Version    string  `json:"version,omitempty"`
	OSHint     string  `json:"os_hint,omitempty"`
	Pattern    string  `json:"pattern"`
	Ports      []int   `json:"ports,omitempty"`
	Confidence float64 `json:"confidence"`

	re *regexp.Regexp
}

// Engine matches targets against an ordered set of rules (first match wins).
type Engine struct {
	rules []Rule
}

// Load reads and compiles the rule file at path.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules %q: %w", path, err)
	}
	var doc struct {
		Version     int    `json:"version"`
		Description string `json:"description,omitempty"`
		Rules       []Rule `json:"rules"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse rules %q: %w", path, err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("parse rules %q: %w", path, err)
	}
	// A missing version is accepted as the original v1 schema for backwards
	// compatibility with small operator-authored rule files.
	if doc.Version != 0 && doc.Version != 1 {
		return nil, fmt.Errorf("rules %q has unsupported schema version %d (want 1)", path, doc.Version)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("rules %q contains no rules", path)
	}

	ids := make(map[string]struct{}, len(doc.Rules))
	for i := range doc.Rules {
		rule := &doc.Rules[i]
		label := ruleLabel(i, rule.ID)

		rule.Protocol = strings.TrimSpace(rule.Protocol)
		if rule.Protocol == "" {
			return nil, fmt.Errorf("%s has an empty protocol", label)
		}
		if rule.Pattern == "" {
			return nil, fmt.Errorf("%s has an empty pattern", label)
		}
		if rule.Confidence < 0 || rule.Confidence > 1 {
			return nil, fmt.Errorf("%s has confidence %g outside [0,1]", label, rule.Confidence)
		}
		if rule.ID != "" {
			if _, exists := ids[rule.ID]; exists {
				return nil, fmt.Errorf("rules %q contains duplicate rule id %q", path, rule.ID)
			}
			ids[rule.ID] = struct{}{}
		}
		for _, port := range rule.Ports {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("%s has invalid port %d", label, port)
			}
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s (%s) has an invalid pattern: %w", label, rule.Protocol, err)
		}
		rule.re = re
	}
	return &Engine{rules: doc.Rules}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("unexpected data after the rules document")
	}
	return err
}

func ruleLabel(index int, id string) string {
	if id == "" {
		return fmt.Sprintf("rule #%d", index)
	}
	return fmt.Sprintf("rule #%d (%s)", index, id)
}

// Len returns the number of loaded rules.
func (e *Engine) Len() int {
	if e == nil {
		return 0
	}
	return len(e.rules)
}

func portMatches(r *Rule, port int) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Identify returns the best match for a single target. It never panics and
// always returns a Result; unmatched targets have Protocol == "unknown".
func (e *Engine) Identify(t Target) Result {
	res := Result{IP: t.IP, Port: t.Port, Protocol: "unknown"}
	if e == nil {
		return res
	}

	for i := range e.rules {
		r := &e.rules[i]
		if r.re == nil || !portMatches(r, t.Port) {
			continue
		}
		m := r.re.FindStringSubmatch(t.Banner)
		if m == nil {
			continue
		}
		res.Protocol = r.Protocol
		res.Product = r.Product
		res.Version = r.Version
		res.OSHint = r.OSHint
		res.Confidence = r.Confidence
		for gi, name := range r.re.SubexpNames() {
			if name == "" || gi >= len(m) || m[gi] == "" {
				continue
			}
			switch name {
			case "product":
				res.Product = m[gi]
			case "version":
				res.Version = m[gi]
			case "os_hint":
				res.OSHint = m[gi]
			}
		}
		return res
	}
	return res
}

// IdentifyBatch identifies a slice of targets. Each record is isolated so a
// pathological banner can never crash the whole batch (defence in depth on top
// of Go's already non-panicking regexp engine).
func (e *Engine) IdentifyBatch(targets []Target) []Result {
	out := make([]Result, 0, len(targets))
	for _, t := range targets {
		out = append(out, e.identifySafe(t))
	}
	return out
}

func (e *Engine) identifySafe(t Target) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res = Result{IP: t.IP, Port: t.Port, Protocol: "unknown"}
		}
	}()
	return e.Identify(t)
}
