package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	loopbackSessionTTL     = 5 * time.Minute
	loopbackCallbackWindow = 5 * time.Second
)

type loopbackCallback struct {
	SessionID  string    `json:"session_id"`
	Address    string    `json:"address"`
	Signature  string    `json:"signature"`
	ReceivedAt time.Time `json:"-"`
}

type loopbackSession struct {
	ID             string
	MapID          string
	VaultOwner     string
	VaultStateHash string
	Challenge      string
	ExpiresAt      time.Time

	mu       sync.Mutex
	consumed bool
	resultCh chan loopbackCallback
}

type loopbackBridge struct {
	listener net.Listener
	server   *http.Server
	baseURL  string
	session  *loopbackSession
	nowFn    func() time.Time
}

var openBrowserURL = defaultOpenBrowser

func startLoopbackBridge(doc recoveryMapDocument, challenge string, now time.Time, ttl time.Duration) (*loopbackBridge, error) {
	session, err := newLoopbackSession(doc, challenge, now, ttl)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	bridge := &loopbackBridge{
		listener: listener,
		baseURL:  "http://" + listener.Addr().String(),
		session:  session,
		nowFn: func() time.Time {
			return now.UTC()
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", bridge.handleRoot)
	mux.HandleFunc("/sign", bridge.handleSign)
	mux.HandleFunc("/callback", bridge.handleCallback)
	bridge.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = bridge.server.Serve(listener)
	}()

	return bridge, nil
}

func newLoopbackSession(doc recoveryMapDocument, challenge string, now time.Time, ttl time.Duration) (*loopbackSession, error) {
	sessionID, err := generateLoopbackSessionID()
	if err != nil {
		return nil, err
	}
	return &loopbackSession{
		ID:             sessionID,
		MapID:          doc.Header.MapID,
		VaultOwner:     normalizeAddress(doc.Header.VaultOwner),
		VaultStateHash: doc.Header.VaultStateHash,
		Challenge:      challenge,
		ExpiresAt:      now.UTC().Add(ttl),
		resultCh:       make(chan loopbackCallback, 1),
	}, nil
}

func generateLoopbackSessionID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *loopbackSession) signURL(baseURL string) string {
	return baseURL + "/sign?session=" + url.QueryEscape(s.ID)
}

func (s *loopbackSession) consumeCallback(cb loopbackCallback, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if cb.SessionID != s.ID {
		return errors.New("invalid session")
	}
	if now.UTC().After(s.ExpiresAt.UTC()) {
		return errors.New("session expired")
	}
	if s.consumed {
		return errors.New("session already consumed")
	}
	if strings.TrimSpace(cb.Address) == "" || strings.TrimSpace(cb.Signature) == "" {
		return errors.New("address and signature are required")
	}

	s.consumed = true
	cb.ReceivedAt = now.UTC()
	s.resultCh <- cb
	return nil
}

func (s *loopbackSession) expired(now time.Time) bool {
	return now.UTC().After(s.ExpiresAt.UTC())
}

func (b *loopbackBridge) SignURL() string {
	return b.session.signURL(b.baseURL)
}

func (b *loopbackBridge) WaitForCallback(timeout time.Duration) (loopbackCallback, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case cb := <-b.session.resultCh:
		return cb, nil
	case <-timer.C:
		return loopbackCallback{}, newCLIError("SIGNATURE_REJECTED", "timed out waiting for MetaMask signature callback")
	}
}

func (b *loopbackBridge) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), loopbackCallbackWindow)
	defer cancel()
	return b.server.Shutdown(ctx)
}

func (b *loopbackBridge) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, b.SignURL(), http.StatusTemporaryRedirect)
}

func (b *loopbackBridge) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("session") != b.session.ID {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}
	if b.session.expired(b.nowFn()) {
		http.Error(w, "session expired", http.StatusGone)
		return
	}

	payload, err := json.Marshal(map[string]string{
		"session_id":       b.session.ID,
		"map_id":           b.session.MapID,
		"vault_owner":      b.session.VaultOwner,
		"vault_state_hash": b.session.VaultStateHash,
		"challenge":        b.session.Challenge,
		"callback_url":     b.baseURL + "/callback",
	})
	if err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
		return
	}

	pageData := struct {
		MapID           string
		VaultOwner      string
		VaultStateHash  string
		Challenge       string
		SessionDataJSON template.JS
	}{
		MapID:           b.session.MapID,
		VaultOwner:      b.session.VaultOwner,
		VaultStateHash:  b.session.VaultStateHash,
		Challenge:       b.session.Challenge,
		SessionDataJSON: template.JS(payload),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := loopbackSignPageTemplate.Execute(w, pageData); err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
		return
	}
}

func (b *loopbackBridge) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req loopbackCallback
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json body", http.StatusBadRequest)
		return
	}

	switch err := b.session.consumeCallback(req, b.nowFn()); {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":         true,
			"session_id": b.session.ID,
		})
	case strings.Contains(err.Error(), "invalid session"):
		http.Error(w, "invalid session", http.StatusNotFound)
	case strings.Contains(err.Error(), "expired"):
		http.Error(w, "session expired", http.StatusGone)
	case strings.Contains(err.Error(), "consumed"):
		http.Error(w, "session already consumed", http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func defaultOpenBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	return cmd.Start()
}

var loopbackSignPageTemplate = template.Must(template.New("sign").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Qave Recovery Unlock</title>
  <style>
    body { font-family: sans-serif; background: #101318; color: #e7edf6; margin: 0; padding: 24px; }
    main { max-width: 860px; margin: 0 auto; }
    .card { background: #171c24; border: 1px solid #2d3745; border-radius: 14px; padding: 16px 18px; margin-bottom: 16px; }
    .label { color: #9fb0c7; font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .value { margin-top: 6px; word-break: break-word; }
    pre { white-space: pre-wrap; word-break: break-word; background: #0f1319; border: 1px solid #2a3340; border-radius: 10px; padding: 12px; }
    button { background: #e7edf6; color: #101318; border: 1px solid transparent; border-radius: 999px; padding: 10px 16px; cursor: pointer; margin-right: 10px; transition: background-color .18s ease, color .18s ease, border-color .18s ease, box-shadow .18s ease, transform .18s ease, filter .18s ease; }
    button[disabled] { opacity: .55; cursor: not-allowed; }
    button.sign-waiting { animation: signButtonBreath 1.8s ease-in-out infinite; background: #f4f8fe; color: #08111d; border-color: rgba(255, 255, 255, 0.34); box-shadow: 0 10px 24px rgba(7, 14, 26, 0.18), inset 0 1px 0 rgba(255, 255, 255, 0.24), 0 0 0 0 rgba(231, 237, 246, 0.20); filter: brightness(1.03) saturate(1.03); }
    #sign-hint { min-height: 20px; margin-top: 10px; color: #cbd8ea; opacity: 0; transition: opacity .18s ease; }
    #sign-hint[data-active="true"] { opacity: 1; }
    #status { min-height: 24px; margin-top: 12px; color: #ffd18a; }
    @keyframes signButtonBreath {
      0%, 100% { transform: scale(1); border-color: rgba(255, 255, 255, 0.28); box-shadow: 0 8px 18px rgba(7, 14, 26, 0.14), inset 0 1px 0 rgba(255, 255, 255, 0.18), 0 0 0 0 rgba(231, 237, 246, 0.12); background-color: #eef4fc; filter: brightness(1.01) saturate(1.01); }
      50% { transform: scale(1.02); border-color: rgba(255, 255, 255, 0.52); box-shadow: 0 14px 30px rgba(7, 14, 26, 0.24), inset 0 1px 0 rgba(255, 255, 255, 0.34), 0 0 0 10px rgba(231, 237, 246, 0.08); background-color: #ffffff; filter: brightness(1.1) saturate(1.06); }
    }
  </style>
</head>
<body>
  <main>
    <h1>Qave Recovery Unlock</h1>
    <div class="card">
      <div class="label">Map ID</div>
      <div class="value">{{ .MapID }}</div>
    </div>
    <div class="card">
      <div class="label">Vault Owner</div>
      <div class="value">{{ .VaultOwner }}</div>
    </div>
    <div class="card">
      <div class="label">Vault State Hash</div>
      <div class="value">{{ .VaultStateHash }}</div>
    </div>
    <div class="card">
      <div class="label">Challenge</div>
      <pre id="challenge">{{ .Challenge }}</pre>
    </div>
    <div class="card">
      <button id="connect">Connect MetaMask</button>
      <button id="sign" disabled>Sign Challenge</button>
      <div id="sign-hint" data-active="false">Click Sign Challenge to continue</div>
      <div id="status"></div>
    </div>
  </main>

  <script id="session-data" type="application/json">{{ .SessionDataJSON }}</script>
  <script>
    let data = null;
    try {
      const rawSessionData = document.getElementById("session-data");
      const rawText = rawSessionData && typeof rawSessionData.textContent === "string"
        ? rawSessionData.textContent
        : "{}";
      const parsed = JSON.parse(rawText);
      data = parsed && typeof parsed === "object" ? parsed : {};
    } catch (err) {
      data = {};
    }

    const status = document.getElementById("status");
    const connectBtn = document.getElementById("connect");
    const signBtn = document.getElementById("sign");
    const signHint = document.getElementById("sign-hint");
    let currentAccount = null;
    let currentSignature = null;
    let statusPhase = "unconnected";
    let statusMessage = "Please connect MetaMask to continue.";
    let errorMessage = null;

    function hasText(value) {
      return typeof value === "string" && value.length > 0;
    }

    function renderStatus() {
      const parts = [];
      if (statusPhase === "submitted") {
        parts.push("Submitted");
      } else if (statusPhase === "signing") {
        parts.push("Signing");
      } else if (statusPhase === "connected") {
        parts.push("Connected");
      } else {
        parts.push("Not connected");
      }

      if (hasText(statusMessage)) {
        parts.push(statusMessage);
      }
      if (hasText(errorMessage)) {
        parts.push("Error: " + errorMessage);
      }

      status.textContent = parts.join(" | ");
      signBtn.disabled = statusPhase !== "connected";
      const waitingForClick = statusPhase === "connected" && !currentSignature;
      signBtn.classList.toggle("sign-waiting", waitingForClick);
      signHint.setAttribute("data-active", waitingForClick ? "true" : "false");
    }

    function setStatusPhase(nextPhase, nextMessage, nextError) {
      statusPhase = nextPhase;
      statusMessage = hasText(nextMessage) ? nextMessage : "";
      errorMessage = hasText(nextError) ? nextError : null;
      renderStatus();
    }

    async function ensureProvider() {
      if (!window.ethereum) {
        setStatusPhase("unconnected", "MetaMask extension not found.", "METAMASK_NOT_FOUND");
        throw new Error("METAMASK_NOT_FOUND");
      }
      return window.ethereum;
    }

    renderStatus();

    connectBtn.addEventListener("click", async () => {
      try {
        const ethereum = await ensureProvider();
        const accounts = await ethereum.request({ method: "eth_requestAccounts" });
        if (!Array.isArray(accounts) || accounts.length === 0 || !hasText(String(accounts[0] || ""))) {
          currentAccount = null;
          setStatusPhase("unconnected", "", "MetaMask did not return any connected account.");
          return;
        }

        currentAccount = String(accounts[0]).toLowerCase();
        currentSignature = null;
        setStatusPhase("connected", "Connected: " + currentAccount, null);
      } catch (err) {
        const message = err && typeof err.message === "string" ? err.message : "Unable to connect MetaMask.";
        if (message.indexOf("4001") >= 0) {
          currentAccount = null;
          setStatusPhase("unconnected", "", "User rejected wallet connection.");
          return;
        }
        setStatusPhase("unconnected", "", message);
      }
    });

    signBtn.addEventListener("click", async () => {
      try {
        const ethereum = await ensureProvider();
        if (!hasText(currentAccount)) {
          setStatusPhase("unconnected", "Please connect MetaMask first.", null);
          return;
        }
        if (!hasText(data && typeof data.challenge === "string" ? data.challenge : "")) {
          setStatusPhase("connected", "", "Challenge is missing.");
          return;
        }
        if (!hasText(data && typeof data.callback_url === "string" ? data.callback_url : "")) {
          setStatusPhase("connected", "", "Callback URL is missing.");
          return;
        }
        if (!hasText(data && typeof data.session_id === "string" ? data.session_id : "")) {
          setStatusPhase("connected", "", "Session is missing.");
          return;
        }

        setStatusPhase("signing", "Waiting for personal_sign...", null);
        const signature = await ethereum.request({
          method: "personal_sign",
          params: [data.challenge, currentAccount]
        });
        if (!hasText(signature)) {
          currentSignature = null;
          setStatusPhase("connected", "", "MetaMask returned an empty signature.");
          return;
        }
        currentSignature = signature;

        const res = await fetch(data.callback_url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: data.session_id,
            address: currentAccount,
            signature: currentSignature
          })
        });

        if (!res.ok) {
          const text = await res.text();
          const failureReason = hasText(text) ? text : "callback failed";
          setStatusPhase("connected", "", "Failed to submit signature callback: " + failureReason);
          return;
        }

        setStatusPhase("submitted", "Signed / Submitted. You can return to the terminal.", null);
      } catch (err) {
        const message = err && typeof err.message === "string" ? err.message : "Signature failed.";
        if (message.indexOf("4001") >= 0) {
          setStatusPhase(hasText(currentAccount) ? "connected" : "unconnected", "", "User rejected the signature request.");
          return;
        }
        setStatusPhase(hasText(currentAccount) ? "connected" : "unconnected", "", message);
      }
    });
  </script>
</body>
</html>`))
