package parser

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, input string) *Pipeline {
	t.Helper()
	p, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v", input, err)
	}
	return p
}

func mustParseErr(t *testing.T, input string, contains string) {
	t.Helper()
	_, err := Parse(input)
	if err == nil {
		t.Fatalf("Parse(%q) expected error, got nil", input)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("Parse(%q) error = %q, want substring %q", input, err.Error(), contains)
	}
}

func TestParseSimpleCommand(t *testing.T) {
	p := mustParse(t, `find /var/log -name "*.log"`)
	if got, want := len(p.Segments), 1; got != want {
		t.Fatalf("len(Segments) = %d, want %d", got, want)
	}
	if got, want := p.Segments[0].Command, "find"; got != want {
		t.Fatalf("Command = %q, want %q", got, want)
	}
	if got, want := p.Segments[0].Args[2], "*.log"; got != want {
		t.Fatalf("third arg = %q, want %q", got, want)
	}
	if got := p.Segments[0].Operator; got != "" {
		t.Fatalf("Operator = %q, want empty", got)
	}
}

func TestParsePipelines(t *testing.T) {
	p := mustParse(t, "ls /tmp | grep error && echo done || echo fail")
	if got, want := len(p.Segments), 4; got != want {
		t.Fatalf("len(Segments) = %d, want %d", got, want)
	}
	if got, want := p.Segments[1].Operator, "|"; got != want {
		t.Fatalf("segment[1].Operator = %q, want %q", got, want)
	}
	if got, want := p.Segments[2].Operator, "&&"; got != want {
		t.Fatalf("segment[2].Operator = %q, want %q", got, want)
	}
	if got, want := p.Segments[3].Operator, "||"; got != want {
		t.Fatalf("segment[3].Operator = %q, want %q", got, want)
	}
}

func TestParsePathBasedCommands(t *testing.T) {
	for _, tc := range []string{"/bin/ls /tmp", "./evil /tmp", "../bin/evil /tmp"} {
		p := mustParse(t, tc)
		if p.Segments[0].Command == "" {
			t.Fatalf("Parse(%q) returned empty command", tc)
		}
	}
}

func TestParseDangerousButSyntacticallySimpleCommands(t *testing.T) {
	for _, tc := range []string{"eval ls", "source /tmp/evil.sh", ". /tmp/evil.sh"} {
		p := mustParse(t, tc)
		if p.Segments[0].Command == "" {
			t.Fatalf("Parse(%q) returned empty command", tc)
		}
	}
}

func TestParseRejectsEmptyOrWhitespace(t *testing.T) {
	mustParseErr(t, "", "Empty command")
	mustParseErr(t, "   ", "Empty command")
}

func TestParseRejectsSemicolonsAndNewlines(t *testing.T) {
	mustParseErr(t, "ls /tmp; rm -rf /", "Semicolons")
	mustParseErr(t, "ls /tmp\nrm -rf /", "Semicolons")
	mustParseErr(t, "; ls /tmp", "parse error")
}

func TestParseRejectsBackgroundAndAssignments(t *testing.T) {
	mustParseErr(t, "sleep 10 &", "Background execution")
	mustParseErr(t, "PATH=/evil ls", "Variable assignments")
	mustParseErr(t, "FOO=bar", "Variable assignments")
}

func TestParseRejectsRedirections(t *testing.T) {
	for _, tc := range []string{
		"grep error /var/log/syslog > /tmp/out",
		"echo data >> /tmp/out",
		"ls /nonexistent 2> /tmp/errors",
		"cat < /etc/passwd",
		"cat << EOF\nhello\nEOF",
		"cat <<< 'hello'",
		"ls 2>&1",
	} {
		mustParseErr(t, tc, "Redirections")
	}
}

func TestParseRejectsExpansionsAndSubstitutions(t *testing.T) {
	mustParseErr(t, "echo $HOME", "will not expand")
	mustParseErr(t, "echo ${HOME:-/root}", "will not expand")
	mustParseErr(t, "echo $(whoami)", "Command substitution")
	mustParseErr(t, "echo `whoami`", "Command substitution")
	mustParseErr(t, "diff <(ls /tmp) <(ls /var)", "Process substitution")
	mustParseErr(t, "echo $((1+2))", "Arithmetic expansion")
	mustParseErr(t, "echo {a,b,c}", "Brace expansion")
}

func TestParseRejectsControlFlow(t *testing.T) {
	cases := []string{
		"if true; then echo yes; fi",
		"while true; do echo loop; done",
		"for i in 1 2 3; do echo $i; done",
		"case x in y) echo z;; esac",
		"until false; do echo loop; done",
		"select x in 1 2 3; do echo $x; done",
		"coproc cat",
		"time ls",
		"{ ls; echo done; }",
		"[[ -f /etc/passwd ]]",
		"(( x++ ))",
		"foo() { echo bar; }",
	}
	for _, tc := range cases {
		mustParseErr(t, tc, "not allowed")
	}
}
