package shellguard_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/jonchun/shellguard"
	"github.com/jonchun/shellguard/manifest"
)

func TestNewWithDefaults(t *testing.T) {
	core, err := shellguard.New(shellguard.Config{})
	if err != nil {
		t.Fatalf("New() with defaults: %v", err)
	}
	if core == nil {
		t.Fatal("New() returned nil core")
	}
}

func TestNewWithCustomManifests(t *testing.T) {
	core, err := shellguard.New(shellguard.Config{
		Manifests: map[string]*manifest.Manifest{
			"ls": {Name: "ls", Description: "list"},
		},
	})
	if err != nil {
		t.Fatalf("New() with custom manifests: %v", err)
	}
	if core == nil {
		t.Fatal("New() returned nil core")
	}
}

func TestNewWithLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	core, err := shellguard.New(shellguard.Config{Logger: logger})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_ = core
}
