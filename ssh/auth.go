package ssh

import (
	"fmt"
	"os"
	"path/filepath"

	gossh "golang.org/x/crypto/ssh"
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

// buildAuthMethods constructs the SSH authentication methods chain.
// It uses defaultKeyPaths() for fallback key discovery.
//
// Priority order:
//  1. Explicit identity_file parameter (fatal if specified but fails to load/parse)
//  2. Default key paths from ~/.ssh/ (silent failures)
//
// Deduplication ensures the same key path is not loaded twice.
func buildAuthMethods(params ConnectionParams) ([]gossh.AuthMethod, error) {
	return buildAuthMethodsWithDefaults(params, defaultKeyPaths())
}

// buildAuthMethodsWithDefaults is the internal implementation that accepts
// an explicit list of default key paths, enabling testability without
// depending on the filesystem layout of the test machine.
func buildAuthMethodsWithDefaults(params ConnectionParams, defaults []string) ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod
	tried := make(map[string]struct{})

	// Priority 1: Explicit identity file — errors are fatal.
	if params.IdentityFile != "" {
		normPath := normalizePath(params.IdentityFile)
		tried[normPath] = struct{}{}

		key, err := os.ReadFile(params.IdentityFile)
		if err != nil {
			return nil, fmt.Errorf("read identity file: %w", err)
		}
		signer, err := gossh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse identity key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}

	// Priority 4: Default key paths — errors are silently skipped.
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

	return methods, nil
}
