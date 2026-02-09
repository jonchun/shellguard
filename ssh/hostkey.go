package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyMode controls how SSH host keys are verified.
type HostKeyMode string

const (
	// HostKeyAcceptNew accepts unknown hosts on first connect (TOFU),
	// writes their key to known_hosts, and rejects key changes.
	HostKeyAcceptNew HostKeyMode = "accept-new"

	// HostKeyStrict requires the host key to already exist in known_hosts.
	HostKeyStrict HostKeyMode = "strict"

	// HostKeyOff disables host key verification entirely.
	HostKeyOff HostKeyMode = "off"
)

var validHostKeyModes = map[HostKeyMode]struct{}{
	HostKeyAcceptNew: {},
	HostKeyStrict:    {},
	HostKeyOff:       {},
}

// ValidHostKeyMode reports whether mode is a recognized host key verification mode.
func ValidHostKeyMode(mode string) bool {
	_, ok := validHostKeyModes[HostKeyMode(mode)]
	return ok
}

// HostKeyError is a user-facing error for host key verification failures.
type HostKeyError struct {
	Message string
}

func (e *HostKeyError) Error() string {
	return e.Message
}

func defaultKnownHostsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("~", ".ssh", "known_hosts")
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// buildHostKeyCallback returns a gossh.HostKeyCallback for the given mode.
func buildHostKeyCallback(mode HostKeyMode, knownHostsFile string) (gossh.HostKeyCallback, error) {
	if mode == HostKeyOff {
		return gossh.InsecureIgnoreHostKey(), nil
	}

	if knownHostsFile == "" {
		knownHostsFile = defaultKnownHostsPath()
	}

	if mode == HostKeyStrict {
		if _, err := os.Stat(knownHostsFile); err != nil {
			return nil, fmt.Errorf("strict host key verification requires known_hosts file: %w", err)
		}
		cb, err := knownhosts.New(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("loading known_hosts: %w", err)
		}
		return cb, nil
	}

	// HostKeyAcceptNew (TOFU)
	return tofuCallback(knownHostsFile)
}

// tofuCallback returns a host key callback that trusts unknown hosts on first
// connect (writing them to knownHostsFile) and rejects key changes.
func tofuCallback(knownHostsFile string) (gossh.HostKeyCallback, error) {
	var mu sync.Mutex

	cb := func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		// Try to verify against the existing known_hosts file.
		var verifyErr error
		if _, statErr := os.Stat(knownHostsFile); statErr == nil {
			checker, err := knownhosts.New(knownHostsFile)
			if err != nil {
				return fmt.Errorf("loading known_hosts: %w", err)
			}
			verifyErr = checker(hostname, remote, key)
		} else {
			// File doesn't exist: treat as unknown host (empty Want).
			verifyErr = &knownhosts.KeyError{}
		}

		if verifyErr == nil {
			// Key matches an existing entry.
			return nil
		}

		var keyErr *knownhosts.KeyError
		if errors.As(verifyErr, &keyErr) {
			if len(keyErr.Want) > 0 {
				// Key has changed — possible MITM.
				return &HostKeyError{
					Message: fmt.Sprintf(
						"HOST KEY VERIFICATION FAILED for %s: the host key has changed since the last connection; this could indicate a man-in-the-middle attack; if the key change is expected, remove the old entry from %s",
						hostname, knownHostsFile,
					),
				}
			}

			// Host not known — accept and record.
			mu.Lock()
			defer mu.Unlock()
			return appendKnownHost(knownHostsFile, hostname, key)
		}

		return fmt.Errorf("host key verification: %w", verifyErr)
	}

	return cb, nil
}

// appendKnownHost writes a new host key entry to the known_hosts file,
// creating the file and parent directory if necessary.
func appendKnownHost(knownHostsFile string, hostname string, key gossh.PublicKey) error {
	dir := filepath.Dir(knownHostsFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating known_hosts directory: %w", err)
	}

	normalized := knownhosts.Normalize(hostname)
	line := knownhosts.Line([]string{normalized}, key)

	f, err := os.OpenFile(knownHostsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("opening known_hosts: %w", err)
	}

	_, writeErr := fmt.Fprintln(f, line)
	closeErr := f.Close()

	if writeErr != nil {
		return fmt.Errorf("writing known_hosts entry: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing known_hosts: %w", closeErr)
	}
	return nil
}
