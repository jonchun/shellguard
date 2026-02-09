package shellguard_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jonchun/shellguard"
)

func TestNew_WithConfigFile(t *testing.T) {
	content := "timeout: 60\nmax_output_bytes: 131072\n"
	dir := t.TempDir()
	configDir := filepath.Join(dir, "shellguard")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", dir)

	core, err := shellguard.New(shellguard.Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if got, want := core.DefaultTimeout, 60; got != want {
		t.Fatalf("DefaultTimeout = %d, want %d", got, want)
	}
	if got, want := core.MaxOutputBytes, 131072; got != want {
		t.Fatalf("MaxOutputBytes = %d, want %d", got, want)
	}
}

func TestNew_NoConfigFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	core, err := shellguard.New(shellguard.Config{})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if got, want := core.DefaultTimeout, 30; got != want {
		t.Fatalf("DefaultTimeout = %d, want %d", got, want)
	}
}
