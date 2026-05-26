package launcher

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStartBindsOnlyIPv4Localhost(t *testing.T) {
	server := startTestServer(t)
	if !strings.HasPrefix(server.Addr, "127.0.0.1:") {
		t.Fatalf("launcher bound non-localhost address: %s", server.Addr)
	}
}

func TestServesOnlyAllowedStaticFiles(t *testing.T) {
	server := startTestServer(t)

	for _, path := range []string{"/", "/index.html", "/style.css", "/app.mjs", "/core.mjs", "/README.md"} {
		res := get(t, server.URL+strings.TrimPrefix(path, "/"))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, res.StatusCode)
		}
		_ = res.Body.Close()
	}

	res := get(t, server.URL+"core.test.mjs")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("core.test.mjs status = %d, want 404", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestAllowsHeadForStaticFiles(t *testing.T) {
	server := startTestServer(t)

	res, err := http.Head(server.URL + "index.html")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", res.StatusCode)
	}
}

func TestRejectsTraversalAndLocalFiles(t *testing.T) {
	server := startTestServer(t)

	for _, path := range []string{"%2e%2e/go.mod", "..%2fgo.mod", "%2e%2e%2fREADME.md"} {
		res := get(t, server.URL+path)
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("traversal %s status = %d, want 403", path, res.StatusCode)
		}
		_ = res.Body.Close()
	}

	res := get(t, server.URL+"go.mod")
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("go.mod status = %d, want 404", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestRejectsMalformedPaths(t *testing.T) {
	server := startTestServer(t)

	for _, path := range []string{"%00", "foo%5cbar"} {
		res := get(t, server.URL+path)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("malformed path %s status = %d, want 400", path, res.StatusCode)
		}
		_ = res.Body.Close()
	}
}

func TestRejectsUploadMethods(t *testing.T) {
	server := startTestServer(t)

	req, err := http.NewRequest(http.MethodPost, server.URL+"index.html", strings.NewReader("ignored"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", res.StatusCode)
	}
}

func TestStaticRootCandidatesPreferMacOSAppResources(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join(testToolRoot(t), "..", ".."))
	executablePath := filepath.Join(repoRoot, "dist", "Launcher.app", "Contents", "MacOS", "Qave Recovery Tool")
	candidates := staticRootCandidates(executablePath)

	wantFirst := filepath.Join(repoRoot, "dist", "Launcher.app", "Contents", "Resources", "recovery-tool")
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(candidates))
	}
	if filepath.Clean(candidates[0]) != filepath.Clean(wantFirst) {
		t.Fatalf("first candidate = %s, want %s", candidates[0], wantFirst)
	}
}

func startTestServer(t *testing.T) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	server, err := Start(ctx, Config{
		Root:        testToolRoot(t),
		OpenBrowser: false,
		IdleTimeout: time.Hour,
	})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = server.Shutdown(context.Background())
	})
	return server
}

func testToolRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", "..", "tools", "qave-recovery-tool-v1"))
	absRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	return absRoot
}

func get(t *testing.T, target string) *http.Response {
	t.Helper()
	res, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	return res
}
