package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"banner-fingerprint/internal/fingerprint"
)

const defaultServerURL = "http://127.0.0.1:8080"

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "client: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("banner-fingerprint-client", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "path to a JSON array of scan records (required)")
	serverURL := flags.String(
		"server",
		envOrDefault("SERVER_URL", defaultServerURL),
		"fingerprint server base URL",
	)
	timeout := flags.Duration("timeout", 15*time.Second, "HTTP request timeout")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse flags: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}
	if *inputPath == "" {
		return fmt.Errorf("-input is required")
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout must be positive")
	}

	input, err := os.ReadFile(*inputPath)
	if err != nil {
		return fmt.Errorf("read input %q: %w", *inputPath, err)
	}
	targets, err := decodeTargets(input)
	if err != nil {
		return fmt.Errorf("decode input %q: %w", *inputPath, err)
	}
	payload, err := json.Marshal(targets)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	endpoint := strings.TrimRight(*serverURL, "/")
	if !strings.HasSuffix(endpoint, "/fingerprint") {
		endpoint += "/fingerprint"
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer response.Body.Close()

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		if readErr != nil {
			return fmt.Errorf("server returned %s (response body could not be read: %v)", response.Status, readErr)
		}
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("server returned %s: %s", response.Status, message)
	}

	var results []fingerprint.Result
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16<<20))
	if err := decoder.Decode(&results); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	if results == nil {
		return fmt.Errorf("decode server response: expected a JSON array")
	}
	if len(results) != len(targets) {
		return fmt.Errorf("server returned %d results for %d records", len(results), len(targets))
	}

	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("write results: %w", err)
	}
	return nil
}

func decodeTargets(input []byte) ([]fingerprint.Target, error) {
	var targets []fingerprint.Target
	decoder := json.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(&targets); err != nil {
		return nil, err
	}
	if targets == nil {
		return nil, errors.New("expected a JSON array")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("expected exactly one JSON array")
	}
	return targets, nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
