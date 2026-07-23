package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"banner-fingerprint/internal/api"
	"banner-fingerprint/internal/fingerprint"
)

const (
	defaultAddress        = ":8080"
	defaultRulesFile      = "rules/rules.json"
	defaultHealthcheckURL = "http://127.0.0.1:8080/health"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		err = runHealthcheck(os.Args[2:])
	} else {
		err = runServer()
	}
	if err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func runServer() error {
	maxBodyBytes, err := positiveInt64Env("MAX_BODY_BYTES", api.DefaultMaxBodyBytes)
	if err != nil {
		return err
	}
	maxBatchSize, err := positiveIntEnv("MAX_BATCH_SIZE", api.DefaultMaxBatchSize)
	if err != nil {
		return err
	}

	rulesFile := envOrDefault("RULES_FILE", defaultRulesFile)
	engine, err := fingerprint.Load(rulesFile)
	if err != nil {
		return fmt.Errorf("initialise fingerprint engine: %w", err)
	}

	server := &http.Server{
		Addr: envOrDefault("ADDR", defaultAddress),
		Handler: api.NewHandler(engine, api.Config{
			MaxBodyBytes: maxBodyBytes,
			MaxBatchSize: maxBatchSize,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	signalContext, stopSignals := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopSignals()

	serverError := make(chan error, 1)
	go func() {
		log.Printf("server listening on %s with %d rules", server.Addr, engine.Len())
		serverError <- server.ListenAndServe()
	}()

	select {
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-signalContext.Done():
		log.Printf("shutdown signal received")
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		_ = server.Close()
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-serverError; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP during shutdown: %w", err)
	}
	return nil
}

func runHealthcheck(args []string) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	url := flags.String(
		"url",
		envOrDefault("HEALTHCHECK_URL", defaultHealthcheckURL),
		"health endpoint URL",
	)
	timeout := flags.Duration("timeout", 2*time.Second, "request timeout")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse healthcheck flags: %w", err)
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("healthcheck accepts no positional arguments")
	}
	if *timeout <= 0 {
		return fmt.Errorf("healthcheck timeout must be positive")
	}

	request, err := http.NewRequest(http.MethodGet, *url, nil)
	if err != nil {
		return fmt.Errorf("build healthcheck request: %w", err)
	}
	client := &http.Client{
		Timeout: *timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request health endpoint: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	var health struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&health); err != nil {
		return fmt.Errorf("decode health response: %w", err)
	}
	if health.Status != "ok" {
		return fmt.Errorf("health endpoint reported status %q", health.Status)
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func positiveIntEnv(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}

func positiveInt64Env(key string, fallback int64) (int64, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return parsed, nil
}
