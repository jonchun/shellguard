package ssh

import (
	"strings"
	"testing"

	"github.com/jonchun/shellguard/parser"
)

// isSafe replicates the unexported isSafeShellToken check for use in test assertions.
func isSafe(token string) bool {
	for _, r := range token {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '_' || r == '@' || r == '%' || r == '+' || r == '=' || r == ':' ||
			r == ',' || r == '.' || r == '/' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func addSeedCorpus(f *testing.F) {
	f.Helper()

	// Normal tokens
	f.Add("hello")
	f.Add("/var/log/syslog")
	f.Add("file.txt")
	f.Add("simple-name")
	f.Add("path/to/file.log")
	f.Add("key=value")
	f.Add("user@host")

	// Shell metacharacters (injection attempts)
	f.Add("; rm -rf /")
	f.Add("$(whoami)")
	f.Add("`id`")
	f.Add("| cat /etc/passwd")
	f.Add("> /tmp/evil")
	f.Add("< /etc/shadow")
	f.Add("& background")
	f.Add("&& echo pwned")
	f.Add("|| true")
	f.Add("$(cat /etc/passwd)")
	f.Add("!!")
	f.Add("~root")
	f.Add("*")
	f.Add("?")
	f.Add("[abc]")
	f.Add("{a,b}")
	f.Add("$HOME")
	f.Add("${PATH}")
	f.Add("\\n")

	// Quote-related
	f.Add("it's")
	f.Add("\"double\"")
	f.Add("'single'")
	f.Add("\"'mixed'\"")
	f.Add("''''")
	f.Add("'")
	f.Add("''")
	f.Add("'''")
	f.Add("he said \"hello\"")
	f.Add("it's a 'test'")
	f.Add("'\"'\"'")

	// Whitespace and special characters
	f.Add("")
	f.Add(" ")
	f.Add("  ")
	f.Add("\t")
	f.Add("\n")
	f.Add("\r\n")
	f.Add("\x00")
	f.Add("a\x00b")
	f.Add("hello world")
	f.Add("  leading")
	f.Add("trailing  ")

	// Unicode
	f.Add("日本語")
	f.Add("emoji: \U0001F600")
	f.Add("caf\u00e9")
	f.Add("\u00fc\u00f6\u00e4")
	f.Add("\U0001F4A9")
	f.Add("mix\u00e9d-safe_and.unsafe!")

	// Long and repeated special characters
	f.Add(strings.Repeat("'", 100))
	f.Add(strings.Repeat("\"", 100))
	f.Add(strings.Repeat("; ", 50))
	f.Add(strings.Repeat("$()", 30))
	f.Add(strings.Repeat("a", 1000))
	f.Add(strings.Repeat("'\"'\"'", 20))
}

func FuzzShellQuote(f *testing.F) {
	addSeedCorpus(f)

	f.Fuzz(func(t *testing.T, token string) {
		result := ShellQuote(token)

		// Output must never be empty.
		if result == "" {
			t.Fatal("ShellQuote returned empty string")
		}

		// Empty input must produce ''.
		if token == "" {
			if result != "''" {
				t.Fatalf("ShellQuote(\"\") = %q, want \"''\"", result)
			}
			return
		}

		// Safe tokens must pass through unchanged.
		if isSafe(token) {
			if result != token {
				t.Fatalf("safe token %q was not passed through: got %q", token, result)
			}
			return
		}

		// Unsafe tokens must be wrapped in single quotes.
		if !strings.HasPrefix(result, "'") {
			t.Fatalf("unsafe token %q: result %q does not start with single quote", token, result)
		}
		if !strings.HasSuffix(result, "'") {
			t.Fatalf("unsafe token %q: result %q does not end with single quote", token, result)
		}

		// If the token contains a single quote, the output must contain the escape sequence.
		if strings.Contains(token, "'") {
			if !strings.Contains(result, "'\"'\"'") {
				t.Fatalf("token containing single quote %q: result %q missing escape sequence '\"'\"'", token, result)
			}
		}
	})
}

func FuzzShellQuoteIdempotent(f *testing.F) {
	addSeedCorpus(f)

	f.Fuzz(func(t *testing.T, token string) {
		first := ShellQuote(token)
		second := ShellQuote(first)

		// Double-quoting must not panic (verified by reaching here) and must produce valid output.
		if second == "" {
			t.Fatal("ShellQuote(ShellQuote(x)) returned empty string")
		}

		// The double-quoted result must still be properly quoted (starts and ends with ').
		// The first result of a non-empty safe token is the token itself, which is safe,
		// so the second call also returns it unchanged. For unsafe tokens, the first result
		// is single-quoted, which is itself unsafe (contains quotes), so the second result
		// wraps it again.
		if first != token {
			// First result was quoted (unsafe token), so second must also be quoted.
			if !strings.HasPrefix(second, "'") || !strings.HasSuffix(second, "'") {
				t.Fatalf("double-quoted result %q is not properly wrapped in single quotes", second)
			}
		}
	})
}

// shellQuoteStructureValid walks the output of ShellQuote and verifies that every
// character is within a valid quoting context (single-quoted or double-quoted),
// simulating how a POSIX shell would parse the token. ShellQuote produces output
// in the form 'foo' with embedded single quotes escaped as '"'"' (end single-quote
// context, enter double-quote context to emit a literal ', resume single-quote context).
// This function returns true if the quoting structure is sound and no characters are
// left unquoted (which would allow shell metacharacter injection).
func shellQuoteStructureValid(s string) bool {
	// State machine: walk through the string tracking quoting context.
	// States: unquoted, single-quoted, double-quoted.
	type state int
	const (
		unquoted state = iota
		singleQuoted
		doubleQuoted
	)

	st := unquoted
	hasContent := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch st {
		case unquoted:
			switch ch {
			case '\'':
				st = singleQuoted
			case '"':
				st = doubleQuoted
			default:
				// A literal character outside any quoting context means a shell
				// metacharacter could be interpreted — this is the injection vector.
				return false
			}
		case singleQuoted:
			if ch == '\'' {
				st = unquoted
			} else {
				hasContent = true
				// Everything inside single quotes is literal — safe.
			}
		case doubleQuoted:
			if ch == '"' {
				st = unquoted
			} else {
				hasContent = true
				// Inside double quotes, most things are literal.
				// The escape pattern '"'"' only puts a single quote here,
				// so we just need to confirm we return to a quoted context.
			}
		}
	}

	// Must end in unquoted state (all quotes closed).
	if st != unquoted {
		return false
	}

	// For non-empty tokens there should be some content; for empty tokens
	// the result is '' which has no content between the quotes — that is fine.
	_ = hasContent
	return true
}

func FuzzShellQuoteNoShellSpecials(f *testing.F) {
	addSeedCorpus(f)

	f.Fuzz(func(t *testing.T, token string) {
		result := ShellQuote(token)

		// For safe tokens, the output is the token itself (no quotes), which by definition
		// contains only safe characters [a-zA-Z0-9_@%+=:,./-]. No metacharacter injection.
		if isSafe(token) {
			return
		}

		// For empty token, result is '' which is a valid empty single-quoted string.
		if token == "" {
			if result != "''" {
				t.Fatalf("empty token: got %q, want \"''\"", result)
			}
			return
		}

		// For unsafe tokens, verify the quoting structure using a shell-parsing state machine.
		// This ensures no characters appear outside a quoting context, which would allow
		// shell metacharacter injection.
		if !shellQuoteStructureValid(result) {
			t.Fatalf("token %q: result %q has invalid quoting structure (unquoted characters or unbalanced quotes)", token, result)
		}

		// Additionally verify that the result starts and ends with a single quote.
		// ShellQuote wraps unsafe tokens as '...' with the escape pattern for embedded quotes.
		if !strings.HasPrefix(result, "'") {
			t.Fatalf("token %q: result %q does not start with single quote", token, result)
		}
		if !strings.HasSuffix(result, "'") {
			t.Fatalf("token %q: result %q does not end with single quote", token, result)
		}
	})
}

func FuzzReconstructCommand(f *testing.F) {
	f.Add("ls", "-la", "/tmp")
	f.Add("grep", "pattern", "file.txt")
	f.Add("echo", "hello world", "")
	f.Add("cat", "/etc/passwd", "")
	f.Add("cmd", "arg with spaces", "'quoted'")
	f.Add("rm", "-rf", "; echo pwned")
	f.Add("psql", "-c", "SELECT 1")
	f.Add("awk", "{print $1}", "data.csv")
	f.Add("", "", "")
	f.Add("日本語", "$(whoami)", "`id`")

	f.Fuzz(func(t *testing.T, command, arg1, arg2 string) {
		// Nil pipeline must return empty string.
		result := ReconstructCommand(nil, false, false)
		if result != "" {
			t.Fatalf("ReconstructCommand(nil, ...) = %q, want \"\"", result)
		}

		// Empty segments must return empty string.
		emptyPipeline := &parser.Pipeline{Segments: []parser.PipelineSegment{}}
		result = ReconstructCommand(emptyPipeline, false, false)
		if result != "" {
			t.Fatalf("ReconstructCommand(empty, ...) = %q, want \"\"", result)
		}

		// Build a pipeline from fuzz inputs.
		args := make([]string, 0, 2)
		if arg1 != "" {
			args = append(args, arg1)
		}
		if arg2 != "" {
			args = append(args, arg2)
		}

		pipeline := &parser.Pipeline{
			Segments: []parser.PipelineSegment{
				{
					Command: command,
					Args:    args,
				},
			},
		}

		// Must not panic.
		result = ReconstructCommand(pipeline, false, false)

		// Output must contain the command (possibly quoted).
		if command != "" {
			quotedCmd := ShellQuote(command)
			if !strings.Contains(result, quotedCmd) {
				t.Fatalf("result %q does not contain quoted command %q (original: %q)", result, quotedCmd, command)
			}
		}

		// Test with isPSQL and toolkitPath flags.
		resultWithFlags := ReconstructCommand(pipeline, true, true)
		if !strings.Contains(resultWithFlags, "PATH=$HOME/.shellguard/bin:$PATH") {
			t.Fatal("toolkitPath=true but PATH prefix missing")
		}
		if !strings.Contains(resultWithFlags, "PGOPTIONS=") {
			t.Fatal("isPSQL=true but PGOPTIONS prefix missing")
		}
	})
}
