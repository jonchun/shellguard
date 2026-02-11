// Package output truncates command results with head/tail preservation.
package output

import (
	"fmt"
)

const (
	DefaultMaxBytes  = 65536
	DefaultHeadBytes = 48 * 1024
	DefaultTailBytes = 16 * 1024
)

type CommandResult struct {
	Host       string `json:"host"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	ExitCode   int    `json:"exit_code"`
	RuntimeMs  int    `json:"runtime_ms"`
	Truncated  bool   `json:"truncated"`
	TotalBytes int    `json:"total_bytes"`
}

func TruncateOutput(stdout, stderr string, exitCode, runtimeMs int, maxBytes ...int) CommandResult {
	limit := DefaultMaxBytes
	if len(maxBytes) > 0 {
		limit = maxBytes[0]
	}

	totalStdout := len([]byte(stdout))
	totalStderr := len([]byte(stderr))
	totalBytes := totalStdout + totalStderr

	outStdout, truncOut := truncateString(stdout, limit)
	outStderr, truncErr := truncateString(stderr, limit)

	return CommandResult{
		Stdout:     outStdout,
		Stderr:     outStderr,
		ExitCode:   exitCode,
		RuntimeMs:  runtimeMs,
		Truncated:  truncOut || truncErr,
		TotalBytes: totalBytes,
	}
}

func truncateString(data string, maxBytes int) (string, bool) {
	dataBytes := []byte(data)
	total := len(dataBytes)

	if total <= maxBytes {
		return data, false
	}

	if maxBytes <= 0 {
		return "", true
	}

	separator := fmt.Sprintf("\n... [TRUNCATED: %d bytes total. Refine your query to narrow results.] ...\n", total)
	sepBytes := []byte(separator)

	if maxBytes <= len(sepBytes) {
		return string(sepBytes[:maxBytes]), true
	}

	contentBudget := maxBytes - len(sepBytes)
	headSize := 0
	tailSize := 0

	if maxBytes == DefaultMaxBytes {
		headSize = min(DefaultHeadBytes, contentBudget)
		tailSize = min(DefaultTailBytes, contentBudget-headSize)
	} else {
		headSize = int(float64(contentBudget) * 0.75)
		tailSize = contentBudget - headSize
	}

	headBytes := dataBytes[:headSize]
	var tailBytes []byte
	if tailSize > 0 {
		tailBytes = dataBytes[len(dataBytes)-tailSize:]
	}

	combined := append(append(headBytes, sepBytes...), tailBytes...)
	return string(combined), true
}
