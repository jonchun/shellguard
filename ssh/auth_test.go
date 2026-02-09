package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

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

// writeTestKey writes a PEM key to a temp file and returns its path.
func writeTestKey(t *testing.T, dir string, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("write test key %s: %v", path, err)
	}
	return path
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
	// When no explicit key and no default keys exist on disk,
	// buildAuthMethods should return an empty (but non-nil) slice and no error.
	methods, err := buildAuthMethods(ConnectionParams{Host: "example.com"})
	if err != nil {
		t.Fatalf("buildAuthMethods() error = %v", err)
	}
	// Methods may or may not be empty depending on whether default keys
	// exist on the test machine. We just verify no error occurred.
	_ = methods
}

func TestBuildAuthMethodsExplicitIdentitySuccess(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir, "explicit_key", generateTestKeyPEM(t))

	methods, err := buildAuthMethods(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	})
	if err != nil {
		t.Fatalf("buildAuthMethods() error = %v", err)
	}
	if len(methods) == 0 {
		t.Fatal("expected at least one auth method for explicit key")
	}
}

func TestBuildAuthMethodsExplicitIdentityFileMissing(t *testing.T) {
	_, err := buildAuthMethods(ConnectionParams{
		Host:         "example.com",
		IdentityFile: "/nonexistent/key",
	})
	if err == nil {
		t.Fatal("expected error for missing explicit identity file")
	}
	if !strings.Contains(err.Error(), "read identity file") {
		t.Errorf("error = %q, want it to contain 'read identity file'", err.Error())
	}
}

func TestBuildAuthMethodsExplicitIdentityFileInvalid(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeTestKey(t, dir, "bad_key", []byte("not a valid key"))

	_, err := buildAuthMethods(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	})
	if err == nil {
		t.Fatal("expected error for invalid explicit identity file")
	}
	if !strings.Contains(err.Error(), "parse identity key") {
		t.Errorf("error = %q, want it to contain 'parse identity key'", err.Error())
	}
}

func TestBuildAuthMethodsDeduplication(t *testing.T) {
	// Create a temp dir that mimics ~/.ssh/ with a known key
	dir := t.TempDir()
	keyPEM := generateTestKeyPEM(t)
	keyPath := writeTestKey(t, dir, "id_ed25519", keyPEM)

	// buildAuthMethods with explicit key pointing to the same path
	// should load the key only once.
	methods, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host:         "example.com",
		IdentityFile: keyPath,
	}, []string{keyPath})
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	// The explicit key should produce 1 method. The default path is the same
	// file, so deduplication should prevent a second method.
	if len(methods) != 1 {
		t.Errorf("expected 1 auth method (dedup), got %d", len(methods))
	}
}

func TestBuildAuthMethodsDefaultKeysLoaded(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateTestKeyPEM(t)
	ed25519Path := writeTestKey(t, dir, "id_ed25519", keyPEM)
	rsaPath := writeTestKey(t, dir, "id_rsa", keyPEM)

	methods, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{ed25519Path, rsaPath})
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 auth methods from defaults, got %d", len(methods))
	}
}

func TestBuildAuthMethodsDefaultKeysMissingSkipped(t *testing.T) {
	methods, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{"/nonexistent/id_ed25519", "/nonexistent/id_rsa"})
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected 0 auth methods for missing defaults, got %d", len(methods))
	}
}

func TestBuildAuthMethodsDefaultKeysInvalidSkipped(t *testing.T) {
	dir := t.TempDir()
	badPath := writeTestKey(t, dir, "id_ed25519", []byte("garbage"))

	methods, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host: "example.com",
	}, []string{badPath})
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	if len(methods) != 0 {
		t.Errorf("expected 0 auth methods for invalid defaults, got %d", len(methods))
	}
}

func TestBuildAuthMethodsExplicitPlusDefaults(t *testing.T) {
	dir := t.TempDir()
	keyPEM := generateTestKeyPEM(t)
	explicitPath := writeTestKey(t, dir, "explicit_key", keyPEM)

	// Generate a different key for the default
	defaultKeyPEM := generateTestKeyPEM(t)
	defaultPath := writeTestKey(t, dir, "id_ed25519", defaultKeyPEM)

	methods, err := buildAuthMethodsWithDefaults(ConnectionParams{
		Host:         "example.com",
		IdentityFile: explicitPath,
	}, []string{defaultPath})
	if err != nil {
		t.Fatalf("buildAuthMethodsWithDefaults() error = %v", err)
	}
	// Explicit key (1) + default key (1) = 2
	if len(methods) != 2 {
		t.Errorf("expected 2 auth methods (explicit + default), got %d", len(methods))
	}
}
