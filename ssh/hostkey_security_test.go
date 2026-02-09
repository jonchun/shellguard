package ssh

// Security tests for SSH host key verification (TOFU, strict, off modes).
//
// Each test targets a specific threat model: MITM detection, strict-mode
// enforcement, file permission hardening, and retry-loop prevention.
//
// Naming: TestSec_<Category>_<Specific>

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testTCPAddr returns a *net.TCPAddr suitable for host key callback tests.
func testTCPAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}

// --- MITM Detection ---

func TestSec_TOFU_MITMKeyChange(t *testing.T) {
	// Threat: attacker intercepts connection and presents a different host key.
	// After TOFU accepts key A, a second connection with key B must be rejected
	// with a HostKeyError containing actionable diagnostics.
	keyA := generateTestKey(t)
	keyB := generateTestKey(t)

	khFile := filepath.Join(t.TempDir(), ".ssh", "known_hosts")
	hostname := "evil.example.com:22"

	// First connection: TOFU accepts key A.
	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	if err := cb(hostname, testTCPAddr(), keyA); err != nil {
		t.Fatalf("first connect (TOFU accept) should succeed: %v", err)
	}

	// Second connection: different key B — must fail.
	cb2, err := buildHostKeyCallback(HostKeyAcceptNew, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback for second connect: %v", err)
	}
	err = cb2(hostname, testTCPAddr(), keyB)
	if err == nil {
		t.Fatalf("expected error for changed host key, got nil")
	}

	// 1. Must be *HostKeyError, not a generic error.
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("error type = %T, want *HostKeyError", err)
	}

	msg := hostKeyErr.Message

	// 2. Contains "HOST KEY VERIFICATION FAILED".
	if !strings.Contains(msg, "HOST KEY VERIFICATION FAILED") {
		t.Errorf("message missing 'HOST KEY VERIFICATION FAILED': %s", msg)
	}

	// 3. Contains the hostname.
	if !strings.Contains(msg, hostname) {
		t.Errorf("message missing hostname %q: %s", hostname, msg)
	}

	// 4. Mentions "man-in-the-middle".
	if !strings.Contains(msg, "man-in-the-middle") {
		t.Errorf("message missing 'man-in-the-middle': %s", msg)
	}

	// 5. Mentions the known_hosts file path.
	if !strings.Contains(msg, khFile) {
		t.Errorf("message missing known_hosts path %q: %s", khFile, msg)
	}
}

// --- Key Change Message Content ---

func TestSec_TOFU_KeyChangeMessageContent(t *testing.T) {
	// Verify the MITM error message contains all required parts for user
	// guidance: hostname, known_hosts reference, and MITM warning.
	keyA := generateTestKey(t)
	keyB := generateTestKey(t)

	tmpDir := t.TempDir()
	khFile := filepath.Join(tmpDir, "known_hosts")
	hostname := "prodserver.internal:2222"

	// Seed with key A.
	writeKnownHostsEntry(t, khFile, hostname, keyA)

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	err = cb(hostname, testTCPAddr(), keyB)
	if err == nil {
		t.Fatalf("expected MITM error, got nil")
	}

	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("error type = %T, want *HostKeyError", err)
	}

	msg := hostKeyErr.Message

	required := []struct {
		label  string
		substr string
	}{
		{"hostname", hostname},
		{"known_hosts file path", khFile},
		{"MITM warning", "man-in-the-middle"},
	}
	for _, req := range required {
		if !strings.Contains(msg, req.substr) {
			t.Errorf("message missing %s (%q): %s", req.label, req.substr, msg)
		}
	}
}

// --- Strict Mode Security ---

func TestSec_Strict_RejectsUnknownHost(t *testing.T) {
	// Strict mode must never accept an unknown host, even with a valid key.
	// The known_hosts file exists but has no entry for this host.
	khFile := filepath.Join(t.TempDir(), "known_hosts")
	otherKey := generateTestKey(t)
	writeKnownHostsEntry(t, khFile, "other.example.com:22", otherKey)

	cb, err := buildHostKeyCallback(HostKeyStrict, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	unknownKey := generateTestKey(t)
	err = cb("unknown.example.com:22", testTCPAddr(), unknownKey)
	if err == nil {
		t.Fatalf("strict mode accepted unknown host, want rejection")
	}
}

func TestSec_Strict_RejectsChangedKey(t *testing.T) {
	// Strict mode must reject a host whose key has changed.
	keyA := generateTestKey(t)
	keyB := generateTestKey(t)

	khFile := filepath.Join(t.TempDir(), "known_hosts")
	hostname := "strict-host.example.com:22"

	// Seed known_hosts with key A.
	writeKnownHostsEntry(t, khFile, hostname, keyA)

	cb, err := buildHostKeyCallback(HostKeyStrict, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	// Connect with key B — must fail.
	err = cb(hostname, testTCPAddr(), keyB)
	if err == nil {
		t.Fatalf("strict mode accepted changed key, want rejection")
	}
}

// --- File Permissions ---

func TestSec_KnownHostsFilePermissions(t *testing.T) {
	// After TOFU creates known_hosts, verify file mode is exactly 0600.
	khFile := filepath.Join(t.TempDir(), "newdir", "known_hosts")
	key := generateTestKey(t)

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	if err := cb("perm-test.example.com:22", testTCPAddr(), key); err != nil {
		t.Fatalf("TOFU accept failed: %v", err)
	}

	info, err := os.Stat(khFile)
	if err != nil {
		t.Fatalf("stat known_hosts: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0600); got != want {
		t.Errorf("known_hosts permissions = %04o, want %04o", got, want)
	}
}

func TestSec_KnownHostsParentDirPermissions(t *testing.T) {
	// After TOFU creates the parent directory, verify mode is 0700.
	tmpDir := t.TempDir()
	parentDir := filepath.Join(tmpDir, "newsshdir")
	khFile := filepath.Join(parentDir, "known_hosts")
	key := generateTestKey(t)

	cb, err := buildHostKeyCallback(HostKeyAcceptNew, khFile)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	if err := cb("dirperm-test.example.com:22", testTCPAddr(), key); err != nil {
		t.Fatalf("TOFU accept failed: %v", err)
	}

	info, err := os.Stat(parentDir)
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0700); got != want {
		t.Errorf("parent dir permissions = %04o, want %04o", got, want)
	}
}

// --- Off Mode Warning ---

func TestSec_OffMode_AcceptsAnyKey(t *testing.T) {
	// Off mode accepts literally any key without checking. Two different
	// keys for the same host must both be accepted.
	keyA := generateTestKey(t)
	keyB := generateTestKey(t)

	cb, err := buildHostKeyCallback(HostKeyOff, "")
	if err != nil {
		t.Fatalf("buildHostKeyCallback(off): %v", err)
	}

	hostname := "insecure.example.com:22"

	if err := cb(hostname, testTCPAddr(), keyA); err != nil {
		t.Errorf("off mode rejected key A: %v", err)
	}
	if err := cb(hostname, testTCPAddr(), keyB); err != nil {
		t.Errorf("off mode rejected key B: %v", err)
	}
}

// --- Non-Retriable ---

func TestSec_HostKeyError_NotRetriable(t *testing.T) {
	// A HostKeyError must never be retried. Retrying a MITM detection
	// would allow an attacker to race against a legitimate reconnect.
	err := &HostKeyError{Message: "HOST KEY VERIFICATION FAILED for evil.com:22"}

	if got := isRetriable(err); got {
		t.Fatalf("isRetriable(*HostKeyError) = true, want false")
	}

	// Also verify when wrapped with errors.Join.
	wrapped := errors.Join(errors.New("connect failed"), err)
	if got := isRetriable(wrapped); got {
		t.Fatalf("isRetriable(wrapped *HostKeyError) = true, want false")
	}
}
