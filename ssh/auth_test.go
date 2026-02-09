package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// --- agentSigners tests ---

func TestAgentSigners_NoAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	signers, cleanup := agentSigners()
	defer cleanup()
	if signers != nil {
		t.Fatalf("expected nil signers when SSH_AUTH_SOCK is empty, got %d", len(signers))
	}
}

func TestAgentSigners_UnreachableSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/shellguard-test-nonexistent.sock")
	signers, cleanup := agentSigners()
	defer cleanup()
	if signers != nil {
		t.Fatalf("expected nil signers for unreachable socket, got %d", len(signers))
	}
}

func TestAgentSigners_EmptyAgent(t *testing.T) {
	sockPath := startTestAgentEmpty(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	signers, cleanup := agentSigners()
	defer cleanup()
	if signers != nil {
		t.Fatalf("expected nil signers from empty agent, got %d", len(signers))
	}
}

func TestAgentSigners_WithLoadedKey(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	signers, cleanup := agentSigners()
	defer cleanup()
	if signers == nil {
		t.Fatal("expected non-nil signers from agent with loaded key")
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
}

func TestAgentSigners_CanSignBeforeCleanup(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	signers, cleanup := agentSigners()
	defer cleanup()
	if signers == nil {
		t.Fatal("expected non-nil signers")
	}

	// Verify the signer can actually produce a signature while the
	// agent connection is still open.
	data := []byte("test data to sign")
	sig, err := signers[0].Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if sig == nil {
		t.Fatal("expected non-nil signature")
	}
}

func TestAgentSigners_CannotSignAfterCleanup(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	signers, cleanup := agentSigners()
	if signers == nil {
		t.Fatal("expected non-nil signers")
	}

	// Close the connection, then try to sign — should fail.
	cleanup()

	data := []byte("test data to sign")
	_, err := signers[0].Sign(rand.Reader, data)
	if err == nil {
		t.Fatal("expected Sign() to fail after cleanup, but it succeeded")
	}
}

// --- defaultKeyPaths tests ---

func TestDefaultKeyPathsNonEmpty(t *testing.T) {
	if _, err := os.UserHomeDir(); err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}
	paths := defaultKeyPaths()
	if len(paths) == 0 {
		t.Fatal("defaultKeyPaths() returned empty slice")
	}
}

func TestDefaultKeyPathsAllInSSHDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}
	sshDir := filepath.Join(home, ".ssh")
	for _, p := range defaultKeyPaths() {
		if !strings.HasPrefix(p, sshDir) {
			t.Errorf("path %q does not start with %q", p, sshDir)
		}
	}
}

func TestDefaultKeyPathsNoEmptyStrings(t *testing.T) {
	for _, p := range defaultKeyPaths() {
		if p == "" {
			t.Error("defaultKeyPaths() contains empty string")
		}
	}
}

func TestDefaultKeyPathsNoDSA(t *testing.T) {
	for _, p := range defaultKeyPaths() {
		if filepath.Base(p) == "id_dsa" {
			t.Errorf("defaultKeyPaths() contains deprecated DSA key path: %q", p)
		}
	}
}

func TestDefaultKeyPathsExpectedOrder(t *testing.T) {
	paths := defaultKeyPaths()
	if len(paths) != 3 {
		t.Fatalf("expected 3 default key paths, got %d", len(paths))
	}

	expectedBases := []string{"id_ed25519", "id_ecdsa", "id_rsa"}
	for i, p := range paths {
		base := filepath.Base(p)
		if base != expectedBases[i] {
			t.Errorf("path[%d] base = %q, want %q", i, base, expectedBases[i])
		}
	}
}

// --- loadPrivateKey tests ---

func TestLoadPrivateKeyMissingFile(t *testing.T) {
	signer := loadPrivateKey("/nonexistent/path/id_ed25519")
	if signer != nil {
		t.Fatal("expected nil signer for missing file")
	}
}

func TestLoadPrivateKeyInvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := writeTestKey(t, dir, "bad_key", []byte("not a valid key"))
	signer := loadPrivateKey(path)
	if signer != nil {
		t.Fatal("expected nil signer for invalid key content")
	}
}

func TestLoadPrivateKeyValidKey(t *testing.T) {
	dir := t.TempDir()
	path := writeTestKey(t, dir, "id_ed25519", generateTestKeyPEM(t))
	signer := loadPrivateKey(path)
	if signer == nil {
		t.Fatal("expected non-nil signer for valid key")
	}
}

// --- normalizePath tests ---

func TestNormalizePathAbsolute(t *testing.T) {
	input := filepath.Join(string(os.PathSeparator), "home", "user", ".ssh", "id_rsa")
	expected, err := filepath.Abs(input)
	if err != nil {
		t.Skipf("cannot build absolute path: %v", err)
	}
	result := normalizePath(input)
	if result != expected {
		t.Errorf("normalizePath(%s) = %q, want %q", input, result, expected)
	}
}

func TestNormalizePathRelative(t *testing.T) {
	result := normalizePath("relative/path")
	if !filepath.IsAbs(result) {
		t.Errorf("normalizePath(relative/path) = %q, expected absolute path", result)
	}
}

// --- buildAuthMethods tests ---

func TestBuildAuthMethodsNoIdentityFileNoDefaults(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods, cleanup, err := buildAuthMethods(ConnectionParams{Host: "example.com"})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethods() error = %v", err)
	}
	_ = methods
}

func TestBuildAuthMethodsExplicitIdentitySuccess(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir, "explicit_key", generateTestKeyPEM(t))

	methods, cleanup, err := buildAuthMethods(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethods() error = %v", err)
	}
	if len(methods) == 0 {
		t.Fatal("expected at least one auth method for explicit key")
	}
}

func TestBuildAuthMethodsExplicitIdentityFileMissing(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	_, cleanup, err := buildAuthMethods(ConnectionParams{
		Host:         "example.com",
		IdentityFile: "/nonexistent/key",
	})
	defer cleanup()
	if err == nil {
		t.Fatal("expected error for missing explicit identity file")
	}
	if !strings.Contains(err.Error(), "read identity file") {
		t.Errorf("error = %q, want it to contain 'read identity file'", err.Error())
	}
}

func TestBuildAuthMethodsExplicitIdentityFileInvalid(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir, "bad_key", []byte("not a valid key"))

	_, cleanup, err := buildAuthMethods(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	})
	defer cleanup()
	if err == nil {
		t.Fatal("expected error for invalid explicit identity file")
	}
	if !strings.Contains(err.Error(), "parse identity key") {
		t.Errorf("error = %q, want it to contain 'parse identity key'", err.Error())
	}
}

func TestBuildAuthMethodsDeduplication(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	keyPEM := generateTestKeyPEM(t)
	keyPath := writeTestKey(t, dir, "id_ed25519", keyPEM)

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	}, []string{keyPath})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 1 {
		t.Errorf("expected 1 auth method (dedup), got %d", len(methods))
	}
}

func TestBuildAuthMethodsDefaultKeysLoaded(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	keyPEM := generateTestKeyPEM(t)
	ed25519Path := writeTestKey(t, dir, "id_ed25519", keyPEM)
	rsaPath := writeTestKey(t, dir, "id_rsa", keyPEM)

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{ed25519Path, rsaPath})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 auth methods from defaults, got %d", len(methods))
	}
}

func TestBuildAuthMethodsDefaultKeysMissingSkipped(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{"/nonexistent/id_ed25519", "/nonexistent/id_rsa"})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected 0 auth methods for missing defaults, got %d", len(methods))
	}
}

func TestBuildAuthMethodsDefaultKeysInvalidSkipped(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	badPath := writeTestKey(t, dir, "id_ed25519", []byte("garbage"))

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{badPath})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected 0 auth methods for invalid defaults, got %d", len(methods))
	}
}

func TestBuildAuthMethodsExplicitPlusDefaults(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	keyPEM := generateTestKeyPEM(t)
	explicitPath := writeTestKey(t, dir, "explicit_key", keyPEM)

	defaultKeyPEM := generateTestKeyPEM(t)
	defaultPath := writeTestKey(t, dir, "id_ed25519", defaultKeyPEM)

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host:         "example.com",
		IdentityFile: explicitPath,
	}, []string{defaultPath})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 auth methods (explicit + default), got %d", len(methods))
	}
}

func TestBuildAuthMethodsAgentOnly(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, nil)
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method (agent), got %d", len(methods))
	}
}

func TestBuildAuthMethodsExplicitPlusAgent(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir, "explicit_key", generateTestKeyPEM(t))

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	}, nil)
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("expected 2 auth methods (explicit + agent), got %d", len(methods))
	}
}

// --- buildAuthMethods passphrase tests ---

func TestBuildAuthMethodsExplicitPassphraseProtected(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir, "id_ed25519_enc", generatePassphraseProtectedKeyPEM(t))

	_, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	}, nil)
	defer cleanup()
	if err == nil {
		t.Fatal("expected error for passphrase-protected explicit identity file")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "ssh-add") {
		t.Errorf("error = %q, want it to contain 'ssh-add'", errMsg)
	}
	if !strings.Contains(errMsg, "ssh-agent") {
		t.Errorf("error = %q, want it to contain 'ssh-agent'", errMsg)
	}
}

func TestBuildAuthMethodsDefaultPassphraseProtectedSkipped(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := t.TempDir()
	encPath := writeTestKey(t, dir, "id_ed25519", generatePassphraseProtectedKeyPEM(t))

	methods, cleanup, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{encPath})
	defer cleanup()
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v, want nil (silent skip)", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected 0 auth methods for passphrase-protected defaults, got %d", len(methods))
	}
}

// --- test helpers ---

// generateTestKeyPEM creates a valid ed25519 private key in PEM format for testing.
func generateTestKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// generatePassphraseProtectedKeyPEM creates a passphrase-protected ed25519
// private key in PEM format for testing.
func generatePassphraseProtectedKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	block, err := gossh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("marshal passphrase-protected key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// writeTestKey writes a PEM key to a temp file and returns its path.
func writeTestKey(t *testing.T, dir string, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write test key %s: %v", path, err)
	}
	return path
}

// startTestAgentEmpty starts an ssh-agent with no keys and returns the socket path.
func startTestAgentEmpty(t *testing.T) string {
	t.Helper()
	return startTestAgentKeyring(t, agent.NewKeyring())
}

// startTestAgentWithKey starts an ssh-agent with one ed25519 key loaded.
func startTestAgentWithKey(t *testing.T) string {
	t.Helper()
	keyring := agent.NewKeyring()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: privKey}); err != nil {
		t.Fatalf("add key to agent: %v", err)
	}
	return startTestAgentKeyring(t, keyring)
}

// startTestAgentKeyring starts an ssh-agent serving the given keyring.
func startTestAgentKeyring(t *testing.T, keyring agent.Agent) string {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(keyring, conn)
				_ = conn.Close()
			}()
		}
	}()

	return sockPath
}
