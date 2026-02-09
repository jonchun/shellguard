package ssh

import (
	"net"
	"os"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigners connects to the running ssh-agent via SSH_AUTH_SOCK and
// returns the available signers. The returned signers hold a reference
// to the agent client, so the caller must keep the connection open
// until signing is complete (i.e., until after the SSH handshake).
// The returned cleanup function closes the agent connection and must
// be called by the caller when the signers are no longer needed.
//
// Returns (nil, no-op) when:
//   - SSH_AUTH_SOCK is not set
//   - The agent socket is unreachable
//   - The agent has no keys loaded
func agentSigners() ([]gossh.Signer, func()) {
	noop := func() {}

	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, noop
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, noop
	}

	signers, err := agent.NewClient(conn).Signers()
	if err != nil || len(signers) == 0 {
		_ = conn.Close()
		return nil, noop
	}

	cleanup := func() { _ = conn.Close() }
	return signers, cleanup
}

// buildAuthMethods constructs the SSH auth method chain in priority order:
//  1. Explicit identity file (if provided and valid)
//  2. ssh-agent signers (via SSH_AUTH_SOCK)
//
// The returned cleanup function closes any resources (e.g., the agent
// socket connection) and must be called after the SSH handshake completes.
//
// Invalid identity files are silently skipped (non-fatal).
// All failures are non-fatal; an empty slice means no auth methods available.
func buildAuthMethods(identityFile string) ([]gossh.AuthMethod, func()) {
	var methods []gossh.AuthMethod
	agentCleanup := func() {}

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
	signers, cleanup := agentSigners()
	if len(signers) > 0 {
		methods = append(methods, gossh.PublicKeys(signers...))
		agentCleanup = cleanup
	} else {
		cleanup()
	}

	return methods, agentCleanup
}
