package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoopbackSessionConsumeOnceAndExpire(t *testing.T) {
	now := time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC)
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "map-test",
			VaultOwner:     "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
			VaultStateHash: "deadbeef",
		},
	}

	session, err := newLoopbackSession(doc, "challenge", now, time.Minute)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	err = session.consumeCallback(loopbackCallback{
		SessionID: session.ID,
		Address:   doc.Header.VaultOwner,
		Signature: "0xabc",
	}, now)
	if err != nil {
		t.Fatalf("consume callback: %v", err)
	}

	err = session.consumeCallback(loopbackCallback{
		SessionID: session.ID,
		Address:   doc.Header.VaultOwner,
		Signature: "0xdef",
	}, now)
	if err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("expected consumed error, got %v", err)
	}

	expiredSession, err := newLoopbackSession(doc, "challenge", now, time.Second)
	if err != nil {
		t.Fatalf("new expired session: %v", err)
	}
	err = expiredSession.consumeCallback(loopbackCallback{
		SessionID: expiredSession.ID,
		Address:   doc.Header.VaultOwner,
		Signature: "0xabc",
	}, now.Add(2*time.Second))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestLoopbackCallbackValidation(t *testing.T) {
	now := time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC)
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "map-test",
			VaultOwner:     "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
			VaultStateHash: "deadbeef",
		},
	}

	session, err := newLoopbackSession(doc, "challenge", now, time.Minute)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	bridge := &loopbackBridge{
		baseURL: "http://127.0.0.1:18080",
		session: session,
		nowFn: func() time.Time {
			return now
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewBufferString(`{"session_id":"","address":"","signature":""}`))
	req.Header.Set("Content-Type", "application/json")
	bridge.handleCallback(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected not found for bad session, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	body, _ := json.Marshal(loopbackCallback{
		SessionID: session.ID,
		Address:   doc.Header.VaultOwner,
		Signature: "0xabc",
	})
	req = httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	bridge.handleCallback(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected callback success, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoopbackSignPageRendersForValidSession(t *testing.T) {
	now := time.Date(2026, 3, 21, 8, 0, 0, 0, time.UTC)
	doc := recoveryMapDocument{
		Header: recoveryMapHeader{
			MapID:          "map-test",
			VaultOwner:     "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
			VaultStateHash: "deadbeef",
		},
	}

	session, err := newLoopbackSession(doc, "challenge", now, time.Minute)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	bridge := &loopbackBridge{
		baseURL: "http://127.0.0.1:18080",
		session: session,
		nowFn: func() time.Time {
			return now
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sign?session="+session.ID, nil)
	bridge.handleSign(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected sign page success, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Qave Recovery Unlock") || !strings.Contains(body, session.Challenge) {
		t.Fatalf("expected sign page content, got body=%s", rec.Body.String())
	}
	if !strings.Contains(body, `<script id="session-data" type="application/json">{"callback_url":"http://127.0.0.1:18080/callback"`) {
		t.Fatalf("expected raw session json in page, got body=%s", body)
	}
	for _, required := range []string{
		"Please connect MetaMask to continue.",
		"Please connect MetaMask first.",
		"Click Sign Challenge to continue",
		"sign-waiting",
		"transition: background-color .18s ease, color .18s ease, border-color .18s ease, box-shadow .18s ease, transform .18s ease, filter .18s ease;",
		"border-color: rgba(255, 255, 255, 0.52);",
		"0 14px 30px rgba(7, 14, 26, 0.24)",
		"0 0 0 10px rgba(231, 237, 246, 0.08)",
		"background-color: #ffffff;",
		"filter: brightness(1.1) saturate(1.06);",
		`statusPhase === "connected" && !currentSignature`,
		`setStatusPhase("signing", "Waiting for personal_sign...", null);`,
		"MetaMask extension not found.",
		"Array.isArray(accounts)",
		"accounts.length === 0",
		"typeof value === \"string\" && value.length > 0",
		"User rejected wallet connection.",
		"MetaMask did not return any connected account.",
		"Failed to submit signature callback:",
		"Connected: ",
		"Signed / Submitted. You can return to the terminal.",
	} {
		if !strings.Contains(rec.Body.String(), required) {
			t.Fatalf("expected sign page guard/content %q, got body=%s", required, rec.Body.String())
		}
	}
}
