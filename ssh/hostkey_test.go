package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// generateTestKey creates a random ed25519 SSH public key for testing.
func generateTestKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	sshPub, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("gossh.NewPublicKey() error = %v", err)
	}
	return sshPub
}

// writeKnownHostsEntry writes a known_hosts entry for the given hostname and key.
func writeKnownHostsEntry(t *testing.T, path string, hostname string, key gossh.PublicKey) {
	t.Helper()
	normalized := knownhosts.Normalize(hostname)
	line := knownhosts.Line([]string{normalized}, key)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("opening known_hosts for writing: %v", err)
	}
	if _, err := fmt.Fprintln(f, line); err != nil {
		_ = f.Close()
		t.Fatalf("writing known_hosts entry: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing known_hosts: %v", err)
	}
}

// --- ValidHostKeyMode ---

func TestValidHostKeyMode_ValidModes(t *testing.T) {
	for _, mode := range []string{"accept-new", "strict", "off"} {
		if got := ValidHostKeyMode(mode); !got {
			t.Errorf("ValidHostKeyMode(%q) = false, want true", mode)
		}
	}
}

func TestValidHostKeyMode_InvalidModes(t *testing.T) {
	for _, mode := range []string{"none", "yes", "", "ACCEPT-NEW"} {
		if got := ValidHostKeyMode(mode); got {
			t.Errorf("ValidHostKeyMode(%q) = true, want false", mode)
		}
	}
}

// --- buildHostKeyCallback ---

func TestBuildHostKeyCallback_OffMode(t *testing.T) {
	cb, err := buildHostKeyCallback(HostKeyOff, "")
	if err != nil {
		t.Fatalf("buildHostKeyCallback(off) error = %v", err)
	}
	if cb == nil {
		t.Fatal("expected non-nil callback")
	}

	key := generateTestKey(t)
	if err := cb("10.0.0.1:22", testTCPAddr(), key); err != nil {
		t.Fatalf("off-mode callback returned error = %v", err)
	}
}

func TestBuildHostKeyCallback_AcceptNewDefault(t *testing.T) {
	// With a temp dir known_hosts path, buildHostKeyCallback should return a
	// callback without error. The file does not need to exist for accept-new.
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback(accept-new) error = %v", err)
	}
	if cb == nil {
		t.Fatal("expected non-nil callback")
	}
}

func TestBuildHostKeyCallback_StrictMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	missingPath := filepath.Join(tmpDir, "nonexistent_known_hosts")

	_, err := buildHostKeyCallback(HostKeyStrict, missingPath)
	if err == nil {
		t.Fatal("expected error for strict mode with missing known_hosts")
	}
	if !strings.Contains(err.Error(), "strict host key verification requires known_hosts file") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestBuildHostKeyCallback_StrictWithFile(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	key := generateTestKey(t)
	writeKnownHostsEntry(t, khPath, "10.0.0.1:22", key)

	cb, err := buildHostKeyCallback(HostKeyStrict, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback(strict) error = %v", err)
	}
	if cb == nil {
		t.Fatal("expected non-nil callback")
	}
}

// --- TOFU mode (accept-new) ---

func TestTOFU_FirstConnect_AcceptsAndWrites(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback() error = %v", err)
	}

	key := generateTestKey(t)
	hostname := "10.0.0.1:22"

	if err := cb(hostname, testTCPAddr(), key); err != nil {
		t.Fatalf("TOFU first connect returned error = %v", err)
	}

	// Verify known_hosts file was created and contains the key.
	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("reading known_hosts: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("known_hosts file is empty after first connect")
	}

	// Verify the entry is parseable and the key is recognized.
	checker, err := knownhosts.New(khPath)
	if err != nil {
		t.Fatalf("known_hosts not parseable after first connect: %v", err)
	}
	if err := checker(hostname, testTCPAddr(), key); err != nil {
		t.Fatalf("key not recognized after TOFU write: %v", err)
	}
}

func TestTOFU_KnownHost_Accepts(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	key := generateTestKey(t)
	hostname := "10.0.0.1:22"

	// Pre-populate known_hosts.
	writeKnownHostsEntry(t, khPath, hostname, key)

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback() error = %v", err)
	}

	if err := cb(hostname, testTCPAddr(), key); err != nil {
		t.Fatalf("TOFU known host returned error = %v", err)
	}
}

func TestTOFU_KeyChanged_Rejects(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	originalKey := generateTestKey(t)
	hostname := "10.0.0.1:22"

	// Pre-populate with original key.
	writeKnownHostsEntry(t, khPath, hostname, originalKey)

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback() error = %v", err)
	}

	// Connect with a different key.
	differentKey := generateTestKey(t)
	err = cb(hostname, testTCPAddr(), differentKey)
	if err == nil {
		t.Fatal("expected error for changed host key")
	}

	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError, got %T: %v", err, err)
	}
	if !strings.Contains(hostKeyErr.Message, "HOST KEY VERIFICATION FAILED") {
		t.Fatalf("unexpected error message: %s", hostKeyErr.Message)
	}
}

func TestTOFU_MissingKnownHostsFile(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	// File does not exist yet.
	if _, err := os.Stat(khPath); !os.IsNotExist(err) {
		t.Fatal("expected known_hosts to not exist initially")
	}

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback() error = %v", err)
	}

	key := generateTestKey(t)
	hostname := "10.0.0.2:22"

	if err := cb(hostname, testTCPAddr(), key); err != nil {
		t.Fatalf("TOFU with missing file returned error = %v", err)
	}

	// File should now exist.
	if _, err := os.Stat(khPath); err != nil {
		t.Fatalf("known_hosts file was not created: %v", err)
	}
}

func TestTOFU_CreatesParentDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	nestedDir := filepath.Join(tmpDir, "deep", "nested", ".ssh")
	khPath := filepath.Join(nestedDir, "known_hosts")

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback() error = %v", err)
	}

	key := generateTestKey(t)
	hostname := "10.0.0.3:22"

	if err := cb(hostname, testTCPAddr(), key); err != nil {
		t.Fatalf("TOFU create parent dir returned error = %v", err)
	}

	// Verify directory was created with 0700 permissions.
	info, err := os.Stat(nestedDir)
	if err != nil {
		t.Fatalf("parent directory not created: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0700); got != want {
		t.Errorf("parent directory permissions = %o, want %o", got, want)
	}
}

// --- Strict mode ---

func TestStrict_KnownHost_Accepts(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	key := generateTestKey(t)
	hostname := "10.0.0.1:22"

	writeKnownHostsEntry(t, khPath, hostname, key)

	cb, err := buildHostKeyCallback(HostKeyStrict, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback(strict) error = %v", err)
	}

	if err := cb(hostname, testTCPAddr(), key); err != nil {
		t.Fatalf("strict known host returned error = %v", err)
	}
}

func TestStrict_UnknownHost_Rejects(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	// Create a known_hosts file with one host.
	knownKey := generateTestKey(t)
	writeKnownHostsEntry(t, khPath, "10.0.0.99:22", knownKey)

	cb, err := buildHostKeyCallback(HostKeyStrict, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback(strict) error = %v", err)
	}

	// Try to connect to a different, unknown host.
	unknownKey := generateTestKey(t)
	hostname := "10.0.0.1:22"

	if err := cb(hostname, testTCPAddr(), unknownKey); err == nil {
		t.Fatal("expected error for unknown host in strict mode")
	}
}

// --- File operations ---

func TestAppendKnownHost_CreatesFile(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	key := generateTestKey(t)
	if err := appendKnownHost(khPath, "10.0.0.1:22", key); err != nil {
		t.Fatalf("appendKnownHost() error = %v", err)
	}

	info, err := os.Stat(khPath)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0600); got != want {
		t.Errorf("file permissions = %o, want %o", got, want)
	}
}

func TestAppendKnownHost_AppendsToExisting(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	if err := appendKnownHost(khPath, "10.0.0.1:22", key1); err != nil {
		t.Fatalf("appendKnownHost(key1) error = %v", err)
	}
	if err := appendKnownHost(khPath, "10.0.0.2:22", key2); err != nil {
		t.Fatalf("appendKnownHost(key2) error = %v", err)
	}

	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("reading known_hosts: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if got, want := len(lines), 2; got != want {
		t.Fatalf("known_hosts line count = %d, want %d", got, want)
	}

	// Verify both entries are parseable and recognized.
	checker, err := knownhosts.New(khPath)
	if err != nil {
		t.Fatalf("knownhosts.New() error = %v", err)
	}
	if err := checker("10.0.0.1:22", testTCPAddr(), key1); err != nil {
		t.Errorf("key1 not found after append: %v", err)
	}
	if err := checker("10.0.0.2:22", testTCPAddr(), key2); err != nil {
		t.Errorf("key2 not found after append: %v", err)
	}
}

func TestAppendKnownHost_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	key := generateTestKey(t)
	if err := appendKnownHost(khPath, "10.0.0.1:22", key); err != nil {
		t.Fatalf("appendKnownHost() error = %v", err)
	}

	info, err := os.Stat(khPath)
	if err != nil {
		t.Fatalf("stat known_hosts: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0600); got != want {
		t.Fatalf("file permissions = %o, want %o", got, want)
	}
}

// --- Thread safety ---

func TestTOFU_ConcurrentConnections(t *testing.T) {
	tmpDir := t.TempDir()
	khPath := filepath.Join(tmpDir, "known_hosts")

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khPath)
	if err != nil {
		t.Fatalf("buildHostKeyCallback() error = %v", err)
	}

	const numGoroutines = 20
	keys := make([]gossh.PublicKey, numGoroutines)
	for i := range keys {
		keys[i] = generateTestKey(t)
	}

	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			hostname := fmt.Sprintf("10.0.%d.%d:22", idx/256, idx%256)
			errs[idx] = cb(hostname, testTCPAddr(), keys[idx])
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d returned error: %v", i, err)
		}
	}

	// Verify all entries are in the known_hosts file.
	checker, err := knownhosts.New(khPath)
	if err != nil {
		t.Fatalf("knownhosts.New() after concurrent writes: %v", err)
	}
	for i := 0; i < numGoroutines; i++ {
		hostname := fmt.Sprintf("10.0.%d.%d:22", i/256, i%256)
		if err := checker(hostname, testTCPAddr(), keys[i]); err != nil {
			t.Errorf("host %s key not found after concurrent write: %v", hostname, err)
		}
	}
}

// --- HostKeyError ---

func TestHostKeyError_ImplementsError(t *testing.T) {
	hke := &HostKeyError{Message: "host key changed"}

	// Verify it implements the error interface.
	var err error = hke
	if got, want := err.Error(), "host key changed"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

// --- Functional options ---

func TestWithHostKeyChecking(t *testing.T) {
	m := NewSSHManager(nil, WithHostKeyChecking(HostKeyStrict))
	d, ok := m.dialer.(*XCryptoDialer)
	if !ok {
		t.Fatal("expected default dialer to be *XCryptoDialer")
	}
	if got, want := d.HostKeyMode, HostKeyStrict; got != want {
		t.Fatalf("HostKeyMode = %q, want %q", got, want)
	}
}

func TestWithKnownHostsFile(t *testing.T) {
	m := NewSSHManager(nil, WithKnownHostsFile("/custom/path/known_hosts"))
	d, ok := m.dialer.(*XCryptoDialer)
	if !ok {
		t.Fatal("expected default dialer to be *XCryptoDialer")
	}
	if got, want := d.KnownHostsFile, "/custom/path/known_hosts"; got != want {
		t.Fatalf("KnownHostsFile = %q, want %q", got, want)
	}
}

func TestHostKeyMode_Default(t *testing.T) {
	d := &XCryptoDialer{}
	if got, want := d.hostKeyMode(), HostKeyAcceptNew; got != want {
		t.Fatalf("hostKeyMode() = %q, want %q", got, want)
	}
}

// --- isRetriable ---

func TestIsRetriable_HostKeyError(t *testing.T) {
	err := &HostKeyError{Message: "host key changed"}
	if isRetriable(err) {
		t.Fatal("HostKeyError should not be retriable")
	}
}
