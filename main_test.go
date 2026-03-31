package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRunHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := run([]string{"--help"}, &stdout, &stderr, strings.NewReader(""), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "Qave Recovery Tool") {
		t.Fatalf("help output missing title: %s", output)
	}
	if !strings.Contains(output, "restore-all <map.qrm> --signer <metamask|manual>") {
		t.Fatalf("help output missing restore-all usage: %s", output)
	}
}

func TestRunVersion(t *testing.T) {
	originalVersion := cliVersion
	originalCommit := cliCommit
	originalBuildDate := cliBuildDate
	cliVersion = "v1.2.3"
	cliCommit = "abc1234"
	cliBuildDate = "2026-03-31T12:00:00Z"
	defer func() {
		cliVersion = originalVersion
		cliCommit = originalCommit
		cliBuildDate = originalBuildDate
	}()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := run([]string{"version"}, &stdout, &stderr, strings.NewReader(""), time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	output := stdout.String()
	if !strings.Contains(output, "qave-recovery-cli v1.2.3") {
		t.Fatalf("version output missing version: %s", output)
	}
	if !strings.Contains(output, "commit=abc1234") {
		t.Fatalf("version output missing commit: %s", output)
	}
	if !strings.Contains(output, "build_date=2026-03-31T12:00:00Z") {
		t.Fatalf("version output missing build date: %s", output)
	}
}
