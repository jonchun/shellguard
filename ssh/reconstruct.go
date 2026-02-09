package ssh

import (
	"strings"

	"github.com/jonchun/shellguard/parser"
)

func ShellQuote(token string) string {
	if token == "" {
		return "''"
	}
	if isSafeShellToken(token) {
		return token
	}
	return "'" + strings.ReplaceAll(token, "'", "'\"'\"'") + "'"
}

func ReconstructCommand(pipeline *parser.Pipeline, isPSQL bool, toolkitPath bool) string {
	if pipeline == nil || len(pipeline.Segments) == 0 {
		return ""
	}

	parts := make([]string, 0, len(pipeline.Segments)*2)
	for _, segment := range pipeline.Segments {
		if segment.Operator != "" {
			parts = append(parts, segment.Operator)
		}
		tokens := make([]string, 0, len(segment.Args)+1)
		tokens = append(tokens, ShellQuote(segment.Command))
		for _, arg := range segment.Args {
			tokens = append(tokens, ShellQuote(arg))
		}
		parts = append(parts, strings.Join(tokens, " "))
	}

	command := strings.Join(parts, " ")

	prefixes := make([]string, 0, 2)
	if toolkitPath {
		prefixes = append(prefixes, "PATH=$HOME/.shellguard/bin:$PATH")
	}
	if isPSQL {
		prefixes = append(prefixes, "PGOPTIONS='-c default_transaction_read_only=on'")
	}
	if len(prefixes) > 0 {
		command = strings.Join(prefixes, " ") + " " + command
	}

	return command
}

func isSafeShellToken(token string) bool {
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
