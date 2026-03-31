package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withFetchHTTPClient(t *testing.T, client *http.Client) {
	t.Helper()

	previous := fetchHTTPClient
	fetchHTTPClient = client
	t.Cleanup(func() {
		fetchHTTPClient = previous
	})
}

func TestFetchSourceToFileStreamsHTTPBodyToDisk(t *testing.T) {
	data := bytes.Repeat([]byte("chunk-"), 1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for offset := 0; offset < len(data); offset += 257 {
			end := offset + 257
			if end > len(data) {
				end = len(data)
			}
			if _, err := w.Write(data[offset:end]); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}))
	defer server.Close()

	outputPath := filepath.Join(t.TempDir(), "download", "artifact.enc")
	source := fetchSource{
		kind:        "provider_piece_url",
		description: "provider_piece_url:test",
		location:    server.URL,
	}

	written, err := fetchSourceToFile(context.Background(), source, outputPath)
	if err != nil {
		t.Fatalf("fetchSourceToFile: %v", err)
	}
	if written != int64(len(data)) {
		t.Fatalf("expected %d bytes, got %d", len(data), written)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("streamed output mismatch")
	}
}

func TestFetchSourceTimeoutUsesConfiguredClientDeadline(t *testing.T) {
	withFetchHTTPClient(t, &http.Client{Timeout: 50 * time.Millisecond})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("too slow"))
	}))
	defer server.Close()

	source := fetchSource{
		kind:        "piece_gateway",
		description: "piece_gateway:slow",
		location:    server.URL,
	}

	start := time.Now()
	_, err := fetchSourceToFile(context.Background(), source, filepath.Join(t.TempDir(), "slow.enc"))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "FWSS_FETCH_FAILED") {
		t.Fatalf("expected fetch failure classification, got %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("expected timeout to fail quickly, elapsed=%v", elapsed)
	}
}

func TestFetchSourceReturnsHTTPStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer server.Close()

	source := fetchSource{
		kind:        "provider_piece_url",
		description: "provider_piece_url:bad-gateway",
		location:    server.URL,
	}

	_, err := fetchSourceToFile(context.Background(), source, filepath.Join(t.TempDir(), "bad.enc"))
	if err == nil {
		t.Fatalf("expected HTTP status error")
	}
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("expected HTTP 502 in error, got %v", err)
	}
}
