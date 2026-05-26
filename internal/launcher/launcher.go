package launcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var allowedStaticFiles = map[string]string{
	"index.html":            "text/html; charset=utf-8",
	"style.css":             "text/css; charset=utf-8",
	"app.mjs":               "text/javascript; charset=utf-8",
	"core.mjs":              "text/javascript; charset=utf-8",
	"README.md":             "text/markdown; charset=utf-8",
	"RELEASE-MANIFEST.json": "application/json; charset=utf-8",
}

var requiredStaticFiles = []string{
	"index.html",
	"style.css",
	"app.mjs",
	"core.mjs",
	"README.md",
}

const defaultIdleTimeout = 6 * time.Hour

type BrowserOpener func(targetURL string) error

type Config struct {
	Root          string
	OpenBrowser   bool
	BrowserOpener BrowserOpener
	IdleTimeout   time.Duration
	Stdout        io.Writer
}

type Server struct {
	URL  string
	Addr string
	Root string

	httpServer *http.Server
	listener   net.Listener
	done       chan error
	once       sync.Once
}

func ResolveStaticRoot(explicitRoot string, executablePath string) (string, error) {
	if strings.TrimSpace(explicitRoot) != "" {
		return validateStaticRoot(explicitRoot)
	}

	if strings.TrimSpace(executablePath) == "" {
		path, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve executable path: %w", err)
		}
		executablePath = path
	}

	for _, candidate := range staticRootCandidates(executablePath) {
		root, err := validateStaticRoot(candidate)
		if err == nil {
			return root, nil
		}
	}

	return "", errors.New("recovery tool static files were not found next to this launcher")
}

func staticRootCandidates(executablePath string) []string {
	executableDir := filepath.Dir(executablePath)
	return []string{
		filepath.Join(executableDir, "..", "Resources", "recovery-tool"),
		filepath.Join(executableDir, "recovery-tool"),
	}
}

func Start(ctx context.Context, cfg Config) (*Server, error) {
	root, err := validateStaticRoot(cfg.Root)
	if err != nil {
		return nil, err
	}

	listenConfig := &net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start localhost listener: %w", err)
	}

	launcherServer := &Server{
		URL:      fmt.Sprintf("http://%s/", listener.Addr().String()),
		Addr:     listener.Addr().String(),
		Root:     root,
		listener: listener,
		done:     make(chan error, 1),
	}

	activity := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case activity <- struct{}{}:
		default:
		}
		serveAllowedStaticFile(root, w, r)
	})

	launcherServer.httpServer = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		err := launcherServer.httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		launcherServer.done <- err
		close(launcherServer.done)
	}()

	idleTimeout := cfg.IdleTimeout
	if idleTimeout > 0 {
		go launcherServer.shutdownAfterIdle(idleTimeout, activity)
	}

	go func() {
		<-ctx.Done()
		_ = launcherServer.Shutdown(context.Background())
	}()

	if cfg.OpenBrowser {
		opener := cfg.BrowserOpener
		if opener == nil {
			opener = OpenBrowser
		}
		if err := opener(launcherServer.URL); err != nil {
			_ = launcherServer.Shutdown(context.Background())
			return nil, fmt.Errorf("open browser: %w", err)
		}
	}

	if cfg.Stdout != nil {
		_, _ = fmt.Fprintf(cfg.Stdout, "Qave Recovery Tool is running at %s\n", launcherServer.URL)
	}

	return launcherServer, nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		err = s.httpServer.Shutdown(ctx)
	})
	return err
}

func (s *Server) Wait() error {
	err, ok := <-s.done
	if !ok {
		return nil
	}
	return err
}

func (s *Server) shutdownAfterIdle(idleTimeout time.Duration, activity <-chan struct{}) {
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(idleTimeout)
		case <-timer.C:
			_ = s.Shutdown(context.Background())
			return
		case <-s.done:
			return
		}
	}
}

func validateStaticRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return "", errors.New("static root is required")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve static root: %w", err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return "", fmt.Errorf("read static root: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("static root must be a directory")
	}
	for _, name := range requiredStaticFiles {
		path := filepath.Join(absRoot, name)
		info, err := os.Lstat(path)
		if err != nil {
			return "", fmt.Errorf("static root is missing %s: %w", name, err)
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("static root entry %s must be a regular file", name)
		}
	}
	return absRoot, nil
}

func serveAllowedStaticFile(root string, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name, status := resolveRequestFile(r.URL)
	if status != http.StatusOK {
		http.Error(w, http.StatusText(status), status)
		return
	}

	contentType := allowedStaticFiles[name]
	filePath := filepath.Join(root, name)
	absFilePath, err := filepath.Abs(filePath)
	if err != nil || !pathWithinRoot(root, absFilePath) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	info, err := os.Lstat(absFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "could not read file", http.StatusInternalServerError)
		return
	}
	if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	file, err := os.Open(absFilePath)
	if err != nil {
		http.Error(w, "could not read file", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, info.ModTime(), file)
}

func resolveRequestFile(requestURL *url.URL) (string, int) {
	decodedPath, err := url.PathUnescape(requestURL.EscapedPath())
	if err != nil || strings.Contains(decodedPath, "\x00") || strings.Contains(decodedPath, "\\") {
		return "", http.StatusBadRequest
	}
	if decodedPath == "/" || decodedPath == "" {
		return "index.html", http.StatusOK
	}
	if strings.Contains(decodedPath, "..") {
		return "", http.StatusForbidden
	}
	name := strings.TrimPrefix(decodedPath, "/")
	if name == "" {
		return "index.html", http.StatusOK
	}
	if strings.Contains(name, "/") {
		return "", http.StatusNotFound
	}
	if _, ok := allowedStaticFiles[name]; !ok {
		return "", http.StatusNotFound
	}
	return name, http.StatusOK
}

func pathWithinRoot(root string, candidate string) bool {
	cleanRoot := filepath.Clean(root)
	cleanCandidate := filepath.Clean(candidate)
	if cleanCandidate == cleanRoot {
		return false
	}
	prefix := cleanRoot + string(os.PathSeparator)
	return strings.HasPrefix(cleanCandidate, prefix)
}
