package ssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// defaultKeyPaths returns the standard SSH private key file paths to try,
// in order of preference: ed25519 > ecdsa > rsa.
// id_dsa is intentionally excluded (deprecated, insecure).
// Returns nil if the user's home directory cannot be determined.
func defaultKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	sshDir := filepath.Join(home, ".ssh")
	return []string{
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(sshDir, "id_ecdsa"),
		filepath.Join(sshDir, "id_rsa"),
	}
}

// loadPrivateKey attempts to load and parse a private key from the given path.
// Returns nil if the file doesn't exist, can't be read, or can't be parsed
// (including passphrase-protected keys). All failures are silent by design.
func loadPrivateKey(path string) gossh.Signer {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		return nil
	}
	return signer
}

// normalizePath returns an absolute, cleaned version of path for use in
// deduplication. Falls back to filepath.Clean if Abs fails.
func normalizePath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

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

// buildAuthMethods constructs the SSH authentication methods chain.
// It uses defaultKeyPaths() for fallback key discovery.
//
// Priority order:
//  1. Explicit identity_file parameter (fatal if specified but fails to load/parse)
//  2. ssh-agent signers (via SSH_AUTH_SOCK, silent failures)
//  3. Default key paths from ~/.ssh/ (silent failures)
//
// The returned cleanup function closes any resources (e.g., the agent
// socket connection) and must be called after the SSH handshake completes.
//
// Deduplication ensures the same key path is not loaded twice.
func buildAuthMethods(params ConnectionParams) ([]gossh.AuthMethod, func(), error) {
	return buildAuthMethodsWithDefaults(params, defaultKeyPaths())
}

// buildAuthMethodsWithDefaults is the internal implementation that accepts
// an explicit list of default key paths, enabling testability without
// depending on the filesystem layout of the test machine.
func buildAuthMethodsWithDefaults(params ConnectionParams, defaults []string) ([]gossh.AuthMethod, func(), error) {
	var methods []gossh.AuthMethod
	agentCleanup := func() {}
	tried := make(map[string]struct{})

	// Priority 1: Explicit identity file — errors are fatal.
	if params.IdentityFile != "" {
		normPath := normalizePath(params.IdentityFile)
		tried[normPath] = struct{}{}

		key, err := os.ReadFile(params.IdentityFile)
		if err != nil {
			return nil, agentCleanup, fmt.Errorf("read identity file: %w", err)
		}
		signer, err := gossh.ParsePrivateKey(key)
		if err != nil {
			return nil, agentCleanup, fmt.Errorf("parse identity key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}

	// Priority 2: ssh-agent.
	signers, cleanup := agentSigners()
	if len(signers) > 0 {
		methods = append(methods, gossh.PublicKeys(signers...))
		agentCleanup = cleanup
	} else {
		cleanup()
	}

	// Priority 3: Default key paths — errors are silently skipped.
	for _, path := range defaults {
		normPath := normalizePath(path)
		if _, ok := tried[normPath]; ok {
			continue
		}
		tried[normPath] = struct{}{}

		if signer := loadPrivateKey(path); signer != nil {
			methods = append(methods, gossh.PublicKeys(signer))
		}
	}

	return methods, agentCleanup, nil
}
