package output

import (
	"strings"
	"testing"
)

func TestTruncateOutputSmallPassThrough(t *testing.T) {
	res := TruncateOutput("hello", "", 0, 42)
	if res.Stdout != "hello" {
		t.Fatalf("Stdout = %q, want hello", res.Stdout)
	}
	if res.Truncated {
		t.Fatal("Truncated should be false")
	}
	if got, want := res.TotalBytes, 5; got != want {
		t.Fatalf("TotalBytes = %d, want %d", got, want)
	}
}

func TestTruncateOutputLargeBounded(t *testing.T) {
	data := strings.Repeat("x", 100_000)
	res := TruncateOutput(data, "", 0, 1)
	if !res.Truncated {
		t.Fatal("expected truncation")
	}
	if !strings.Contains(res.Stdout, "TRUNCATED") {
		t.Fatal("expected truncation marker")
	}
	if got := len([]byte(res.Stdout)); got > DefaultMaxBytes {
		t.Fatalf("stdout bytes = %d, exceeds %d", got, DefaultMaxBytes)
	}
}

func TestTruncateOutputPreservesHeadAndTail(t *testing.T) {
	data := "START\n" + strings.Repeat("x", 100000) + "\nEND"
	res := TruncateOutput(data, "", 0, 1)
	if !strings.Contains(res.Stdout, "START") {
		t.Fatal("expected head content")
	}
	if !strings.Contains(res.Stdout, "END") {
		t.Fatal("expected tail content")
	}
}

func TestTruncateOutputUnicodeSafe(t *testing.T) {
	data := strings.Repeat("😀", 20000)
	res := TruncateOutput(data, "", 0, 1)
	if !res.Truncated {
		t.Fatal("expected truncation")
	}
	_ = []byte(res.Stdout)
}

func TestTruncateOutputEdgeMaxBytes(t *testing.T) {
	resZero := TruncateOutput("hello", "", 0, 1, 0)
	if !resZero.Truncated {
		t.Fatal("maxBytes=0 should truncate")
	}
	if got := len([]byte(resZero.Stdout)); got != 0 {
		t.Fatalf("len(stdout) = %d, want 0", got)
	}

	resOne := TruncateOutput("hello", "", 0, 1, 1)
	if !resOne.Truncated {
		t.Fatal("maxBytes=1 should truncate")
	}
	if got := len([]byte(resOne.Stdout)); got > 1 {
		t.Fatalf("len(stdout) = %d, want <= 1", got)
	}
}

func TestTruncateOutputTotalBytesAndMetadata(t *testing.T) {
	data := strings.Repeat("😀", 100)
	res := TruncateOutput(data, "err", 255, 999)
	if got, want := res.TotalBytes, 403; got != want {
		t.Fatalf("TotalBytes = %d, want %d", got, want)
	}
	if res.ExitCode != 255 || res.RuntimeMs != 999 {
		t.Fatal("metadata not preserved")
	}
}
