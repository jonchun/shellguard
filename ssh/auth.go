package ssh

import (
	"net"
	"os"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigners connects to the running ssh-agent via SSH_AUTH_SOCK,
// fetches all available signers, and returns them. The agent connection
// is closed before returning — the signers are self-contained.
//
// Returns nil (never an error) when:
//   - SSH_AUTH_SOCK is not set
//   - The agent socket is unreachable
//   - The agent has no keys loaded
func agentSigners() []gossh.Signer {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) == 0 {
		return nil
	}
	return signers
}

// buildAuthMethods constructs the SSH auth method chain in priority order:
//  1. Explicit identity file (if provided and valid)
//  2. ssh-agent signers (via SSH_AUTH_SOCK)
//
// Invalid identity files are silently skipped (non-fatal).
// All failures are non-fatal; an empty slice means no auth methods available.
func buildAuthMethods(identityFile string) []gossh.AuthMethod {
	var methods []gossh.AuthMethod

	// Priority 1: explicit identity file.
	if identityFile != "" {
		key, err := os.ReadFile(identityFile)
		if err == nil {
			signer, err := gossh.ParsePrivateKey(key)
			if err == nil {
				methods = append(methods, gossh.PublicKeys(signer))
			}
		}
	}

	// Priority 2: ssh-agent.
	if signers := agentSigners(); len(signers) > 0 {
		methods = append(methods, gossh.PublicKeys(signers...))
	}

	return methods
}
