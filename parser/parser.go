// Package parser turns shell input into a validated AST of pipeline segments.
package parser

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Input size limits.
const (
	MaxCommandLength  = 65536 // 64KB max total command length
	MaxPipeSegments   = 32    // max pipeline segments (|, &&, ||)
	MaxArgsPerSegment = 1024  // max arguments per command segment
)

type PipelineSegment struct {
	Command  string
	Args     []string
	Operator string
}

type Pipeline struct {
	Segments []PipelineSegment
}

type ParseError struct {
	Message string
}

func (e *ParseError) Error() string {
	return e.Message
}

func Parse(command string) (*Pipeline, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil, &ParseError{Message: "Empty command."}
	}
	if len(trimmed) > MaxCommandLength {
		return nil, &ParseError{Message: fmt.Sprintf("Command too long (%d bytes, max %d).", len(trimmed), MaxCommandLength)}
	}

	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := p.Parse(strings.NewReader(trimmed), "")
	if err != nil {
		return nil, &ParseError{Message: fmt.Sprintf("parse error: %v", err)}
	}

	if len(file.Stmts) == 0 {
		return nil, &ParseError{Message: "No commands found in input."}
	}
	if len(file.Stmts) > 1 {
		return nil, &ParseError{Message: "Semicolons are not allowed. Use && or || for conditional chaining."}
	}

	segments := make([]PipelineSegment, 0, 4)
	if err := walkStmt(file.Stmts[0], &segments, ""); err != nil {
		return nil, err
	}
	if len(segments) == 0 {
		return nil, &ParseError{Message: "No commands found in input."}
	}
	if len(segments) > MaxPipeSegments {
		return nil, &ParseError{Message: fmt.Sprintf("Too many pipeline segments (%d, max %d).", len(segments), MaxPipeSegments)}
	}

	return &Pipeline{Segments: segments}, nil
}

func walkStmt(stmt *syntax.Stmt, segments *[]PipelineSegment, operator string) error {
	if stmt.Background {
		return &ParseError{Message: "Background execution is not allowed."}
	}
	if len(stmt.Redirs) > 0 {
		return &ParseError{Message: "Redirections are not supported. stderr is captured separately."}
	}
	if stmt.Cmd == nil {
		return &ParseError{Message: "Unsupported shell construct."}
	}
	return walkCommand(stmt.Cmd, segments, operator)
}

func walkCommand(cmd syntax.Command, segments *[]PipelineSegment, operator string) error {
	switch c := cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Assigns) > 0 {
			return &ParseError{Message: "Variable assignments are not allowed."}
		}
		if len(c.Args) == 0 {
			return &ParseError{Message: "Empty command."}
		}
		if len(c.Args) > MaxArgsPerSegment {
			return &ParseError{Message: fmt.Sprintf("Too many arguments (%d, max %d).", len(c.Args), MaxArgsPerSegment)}
		}

		words := make([]string, 0, len(c.Args))
		for _, arg := range c.Args {
			word, err := wordToString(arg)
			if err != nil {
				return err
			}
			if word != "" {
				words = append(words, word)
			}
		}
		if len(words) == 0 {
			return &ParseError{Message: "Empty command."}
		}

		*segments = append(*segments, PipelineSegment{
			Command:  words[0],
			Args:     words[1:],
			Operator: operator,
		})
		return nil

	case *syntax.BinaryCmd:
		op := c.Op.String()
		if op != "|" && op != "&&" && op != "||" {
			return &ParseError{Message: fmt.Sprintf("Unsupported operator: %s", op)}
		}
		if err := walkStmt(c.X, segments, operator); err != nil {
			return err
		}
		return walkStmt(c.Y, segments, op)

	case *syntax.Subshell:
		return &ParseError{Message: "Subshells are not allowed."}
	case *syntax.Block:
		return &ParseError{Message: "Block expressions are not allowed."}
	case *syntax.IfClause:
		return &ParseError{Message: "Control flow (if) is not allowed."}
	case *syntax.WhileClause:
		return &ParseError{Message: "Control flow (while) is not allowed."}
	case *syntax.ForClause:
		return &ParseError{Message: "Control flow (for/select/until) is not allowed."}
	case *syntax.CaseClause:
		return &ParseError{Message: "Control flow (case) is not allowed."}
	case *syntax.ArithmCmd:
		return &ParseError{Message: "Arithmetic commands are not allowed."}
	case *syntax.TestClause:
		return &ParseError{Message: "Test clauses are not allowed."}
	case *syntax.DeclClause:
		return &ParseError{Message: "Variable assignments are not allowed."}
	case *syntax.LetClause:
		return &ParseError{Message: "Let clauses are not allowed."}
	case *syntax.FuncDecl:
		return &ParseError{Message: "Function definitions are not allowed."}
	case *syntax.CoprocClause:
		return &ParseError{Message: "Coprocesses are not allowed."}
	case *syntax.TimeClause:
		return &ParseError{Message: "Time clauses are not allowed."}
	default:
		return &ParseError{Message: fmt.Sprintf("Unsupported shell construct: %T", c)}
	}
}

func checkWordParts(parts []syntax.WordPart) error {
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.ParamExp:
			return &ParseError{Message: "Variable expansion will not expand. Use absolute paths."}
		case *syntax.CmdSubst:
			return &ParseError{Message: "Command substitution is not allowed."}
		case *syntax.ProcSubst:
			return &ParseError{Message: "Process substitution is not allowed."}
		case *syntax.ArithmExp:
			return &ParseError{Message: "Arithmetic expansion is not allowed."}
		case *syntax.ExtGlob:
			return &ParseError{Message: "Extended glob patterns are not allowed."}
		case *syntax.BraceExp:
			return &ParseError{Message: "Brace expansion is not allowed."}
		case *syntax.DblQuoted:
			if err := checkWordParts(p.Parts); err != nil {
				return err
			}
		}
	}
	return nil
}

func wordToString(w *syntax.Word) (string, error) {
	if err := checkWordParts(w.Parts); err != nil {
		return "", err
	}

	var b strings.Builder
	_ = syntax.NewPrinter().Print(&b, w)
	word := b.String()
	if strings.ContainsAny(word, "{}") && !isWrappedInQuotes(word) {
		return "", &ParseError{Message: "Brace expansion is not allowed."}
	}
	if len(word) >= 2 {
		if word[0] == '\'' && word[len(word)-1] == '\'' {
			return word[1 : len(word)-1], nil
		}
		if word[0] == '"' && word[len(word)-1] == '"' {
			return word[1 : len(word)-1], nil
		}
	}
	return word, nil
}

func isWrappedInQuotes(word string) bool {
	if len(word) < 2 {
		return false
	}
	if word[0] == '\'' && word[len(word)-1] == '\'' {
		return true
	}
	if word[0] == '"' && word[len(word)-1] == '"' {
		return true
	}
	return false
}
