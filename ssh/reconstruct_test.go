package ssh

import (
	"strings"
	"testing"

	"github.com/jonchun/shellguard/parser"
)

func TestShellQuoteBasic(t *testing.T) {
	if got, want := ShellQuote("/var/log/syslog"), "/var/log/syslog"; got != want {
		t.Fatalf("ShellQuote path = %q, want %q", got, want)
	}
	if got, want := ShellQuote(""), "''"; got != want {
		t.Fatalf("ShellQuote empty = %q, want %q", got, want)
	}
	if got := ShellQuote("hello world"); got != "'hello world'" {
		t.Fatalf("ShellQuote spaces = %q", got)
	}
}

func TestShellQuoteSingleQuoteEscaping(t *testing.T) {
	got := ShellQuote("it's")
	if !strings.Contains(got, "'\"'\"'") {
		t.Fatalf("expected embedded quote escaping, got %q", got)
	}
}

func TestReconstructCommandSimpleAndPipeline(t *testing.T) {
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls", Args: []string{"/tmp"}}}}
	if got, want := ReconstructCommand(p, false, false), "ls /tmp"; got != want {
		t.Fatalf("Reconstruct simple = %q, want %q", got, want)
	}

	p2 := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "grep", Args: []string{"error", "/var/log/syslog"}},
		{Command: "head", Args: []string{"-n", "20"}, Operator: "|"},
	}}
	if got, want := ReconstructCommand(p2, false, false), "grep error /var/log/syslog | head -n 20"; got != want {
		t.Fatalf("Reconstruct pipeline = %q, want %q", got, want)
	}
}

func TestReconstructCommandQuotesMetacharacters(t *testing.T) {
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "grep", Args: []string{"foo; rm -rf /", "$(id)", "`whoami`", "*.log", "/var/log/syslog"}}}}
	got := ReconstructCommand(p, false, false)
	for _, needle := range []string{"'foo; rm -rf /'", "'$(id)'", "'`whoami`'", "'*.log'"} {
		if !strings.Contains(got, needle) {
			t.Fatalf("expected %q in %q", needle, got)
		}
	}
}

func TestReconstructCommandPrefixes(t *testing.T) {
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "psql", Args: []string{"-c", "SELECT 1"}}}}
	got := ReconstructCommand(p, true, true)
	if !strings.HasPrefix(got, "PATH=$HOME/.shellguard/bin:$PATH PGOPTIONS='-c default_transaction_read_only=on' ") {
		t.Fatalf("unexpected prefix order: %q", got)
	}
}

func TestReconstructCommandEmptyPipeline(t *testing.T) {
	p := &parser.Pipeline{}
	if got := ReconstructCommand(p, false, false); got != "" {
		t.Fatalf("expected empty command, got %q", got)
	}
}
