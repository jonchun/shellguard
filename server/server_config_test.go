package server

import (
	"testing"

	"github.com/jonchun/shellguard/output"
)

func TestNewCore_DefaultValues(t *testing.T) {
	core := NewCore(basicRegistry(), newFakeRunner(), nil)

	if got, want := core.DefaultTimeout, 30; got != want {
		t.Fatalf("DefaultTimeout = %d, want %d", got, want)
	}
	if got, want := core.MaxOutputBytes, output.DefaultMaxBytes; got != want {
		t.Fatalf("MaxOutputBytes = %d, want %d", got, want)
	}
	if got, want := core.MaxDownloadBytes, maxDownloadBytes; got != want {
		t.Fatalf("MaxDownloadBytes = %d, want %d", got, want)
	}
	if got, want := core.DownloadDir, defaultDownloadDir; got != want {
		t.Fatalf("DownloadDir = %q, want %q", got, want)
	}
	if got, want := core.MaxSleepSeconds, 15; got != want {
		t.Fatalf("MaxSleepSeconds = %d, want %d", got, want)
	}
}

func TestNewCore_WithOptions(t *testing.T) {
	core := NewCore(basicRegistry(), newFakeRunner(), nil,
		WithDefaultTimeout(60),
		WithMaxOutputBytes(1024),
		WithMaxDownloadBytes(100),
		WithDownloadDir("/custom/dir"),
		WithMaxSleepSeconds(30),
	)

	if got, want := core.DefaultTimeout, 60; got != want {
		t.Fatalf("DefaultTimeout = %d, want %d", got, want)
	}
	if got, want := core.MaxOutputBytes, 1024; got != want {
		t.Fatalf("MaxOutputBytes = %d, want %d", got, want)
	}
	if got, want := core.MaxDownloadBytes, 100; got != want {
		t.Fatalf("MaxDownloadBytes = %d, want %d", got, want)
	}
	if got, want := core.DownloadDir, "/custom/dir"; got != want {
		t.Fatalf("DownloadDir = %q, want %q", got, want)
	}
	if got, want := core.MaxSleepSeconds, 30; got != want {
		t.Fatalf("MaxSleepSeconds = %d, want %d", got, want)
	}
}
