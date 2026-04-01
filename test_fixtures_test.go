package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	fixtureSourceRoot             = "/tmp/qave-recovery-cli-fixtures"
	fixtureFetchLegacySourcePath  = fixtureSourceRoot + "/fetch-legacy.enc"
	fixtureFetchSessionSourcePath = fixtureSourceRoot + "/fetch-session.enc"
	fixtureFetchPerExportSource   = fixtureSourceRoot + "/fetch-per-export.enc"
	fixtureRestoreSingleSource    = fixtureSourceRoot + "/restore-single.enc"
	fixtureRestoreMultiSourceOne  = fixtureSourceRoot + "/restore-multi-1.enc"
	fixtureRestoreMultiSourceTwo  = fixtureSourceRoot + "/restore-multi-2.enc"
	fixtureRestoreTraversalSource = fixtureSourceRoot + "/restore-traversal.enc"
)

func loadFixtureDoc(t *testing.T, name string) recoveryMapDocument {
	t.Helper()
	doc, err := loadRecoveryMap(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load fixture %s: %v", name, err)
	}
	return doc
}

func copyFixtureQRM(t *testing.T, dir string, fixtureName string, targetName string) string {
	t.Helper()
	return copyFixtureFile(t, fixtureName, filepath.Join(dir, targetName))
}

func copyFixtureFile(t *testing.T, fixtureName string, targetPath string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixtureName))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixtureName, err)
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", targetPath, err)
	}
	if err := os.WriteFile(targetPath, raw, 0o600); err != nil {
		t.Fatalf("write %s: %v", targetPath, err)
	}
	return targetPath
}

func installFixtureBlob(t *testing.T, fixtureName string, targetPath string) {
	t.Helper()
	_ = copyFixtureFile(t, fixtureName, targetPath)
}
