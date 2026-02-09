package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh/agent"
)

func TestAgentSigners_NoAuthSock(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	signers := agentSigners()
	if signers != nil {
		t.Fatalf("expected nil signers when SSH_AUTH_SOCK is empty, got %d", len(signers))
	}
}

func TestAgentSigners_UnreachableSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/tmp/shellguard-test-nonexistent.sock")
	signers := agentSigners()
	if signers != nil {
		t.Fatalf("expected nil signers for unreachable socket, got %d", len(signers))
	}
}

func TestAgentSigners_EmptyAgent(t *testing.T) {
	sockPath := startTestAgentEmpty(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	signers := agentSigners()
	if signers != nil {
		t.Fatalf("expected nil signers from empty agent, got %d", len(signers))
	}
}

func TestAgentSigners_WithLoadedKey(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	signers := agentSigners()
	if signers == nil {
		t.Fatal("expected non-nil signers from agent with loaded key")
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}
}

func TestBuildAuthMethods_NoSources(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods := buildAuthMethods("")
	if len(methods) != 0 {
		t.Fatalf("expected 0 auth methods, got %d", len(methods))
	}
}

func TestBuildAuthMethods_IdentityFileOnly(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	keyFile := writeTestKeyFile(t)

	methods := buildAuthMethods(keyFile)
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method (identity file), got %d", len(methods))
	}
}

func TestBuildAuthMethods_AgentOnly(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	methods := buildAuthMethods("")
	if len(methods) != 1 {
		t.Fatalf("expected 1 auth method (agent), got %d", len(methods))
	}
}

func TestBuildAuthMethods_IdentityFileAndAgent(t *testing.T) {
	sockPath := startTestAgentWithKey(t)
	t.Setenv("SSH_AUTH_SOCK", sockPath)
	keyFile := writeTestKeyFile(t)

	methods := buildAuthMethods(keyFile)
	if len(methods) != 2 {
		t.Fatalf("expected 2 auth methods, got %d", len(methods))
	}
}

func TestBuildAuthMethods_InvalidIdentityFile(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods := buildAuthMethods("/nonexistent/key")
	if len(methods) != 0 {
		t.Fatalf("expected 0 auth methods for invalid identity file, got %d", len(methods))
	}
}

func TestBuildAuthMethods_CorruptIdentityFile(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	tmpFile := filepath.Join(t.TempDir(), "bad_key")
	if err := os.WriteFile(tmpFile, []byte("not a real key"), 0o600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}
	methods := buildAuthMethods(tmpFile)
	if len(methods) != 0 {
		t.Fatalf("expected 0 auth methods for corrupt identity file, got %d", len(methods))
	}
}

// --- test helpers ---

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
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, conn)
		}
	}()

	return sockPath
}

// writeTestKeyFile generates an ed25519 key, writes it to a temp file in
// PKCS8 PEM format (compatible with gossh.ParsePrivateKey), and returns the path.
func writeTestKeyFile(t *testing.T) string {
	t.Helper()
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	derBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return keyFile
}
