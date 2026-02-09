package toolkit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jonchun/shellguard/ssh"
)

func TestBuildProbeCommand(t *testing.T) {
	cmd := BuildProbeCommand()
	if !strings.Contains(cmd, "command -v") {
		t.Fatalf("expected command -v in %q", cmd)
	}
	for _, tool := range ToolkitTools {
		if !strings.Contains(cmd, tool) {
			t.Fatalf("missing tool %q in %q", tool, cmd)
		}
	}
	if !strings.Contains(cmd, "uname -m") {
		t.Fatalf("expected uname -m in %q", cmd)
	}
	if !strings.Contains(cmd, "---") {
		t.Fatalf("expected separator in %q", cmd)
	}
}

func TestParseProbeOutput(t *testing.T) {
	tests := []struct {
		name        string
		stdout      string
		wantMissing []string
		wantArch    string
	}{
		{
			name:        "all found",
			stdout:      "/usr/bin/rg\n/usr/bin/jq\n/usr/local/bin/yq\n---\nx86_64\n",
			wantMissing: []string{},
			wantArch:    "x86_64",
		},
		{
			name:        "some missing",
			stdout:      "/usr/bin/jq\n---\naarch64\n",
			wantMissing: []string{"rg", "yq"},
			wantArch:    "aarch64",
		},
		{
			name:        "all missing",
			stdout:      "\n---\narm64\n",
			wantMissing: []string{"rg", "jq", "yq"},
			wantArch:    "arm64",
		},
		{
			name:        "extract basename",
			stdout:      "/deep/path/rg\n/usr/local/bin/jq\n/snap/bin/yq\n---\nx86_64\n",
			wantMissing: []string{},
			wantArch:    "x86_64",
		},
		{
			name:        "empty output",
			stdout:      "",
			wantMissing: []string{"rg", "jq", "yq"},
			wantArch:    "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMissing, gotArch := ParseProbeOutput(tt.stdout)
			if strings.Join(gotMissing, ",") != strings.Join(tt.wantMissing, ",") {
				t.Fatalf("missing = %v, want %v", gotMissing, tt.wantMissing)
			}
			if gotArch != tt.wantArch {
				t.Fatalf("arch = %q, want %q", gotArch, tt.wantArch)
			}
		})
	}
}

func TestNormalizeArch(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "x86_64", want: "x86_64"},
		{in: "aarch64", want: "aarch64"},
		{in: "arm64", want: "aarch64"},
		{in: "s390x", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeArch(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeArch(%q) error = %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeArch(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDownloadURL(t *testing.T) {
	for _, tool := range ToolkitTools {
		for _, arch := range []string{"x86_64", "aarch64"} {
			url, sum, err := DownloadURL(tool, arch)
			if err != nil {
				t.Fatalf("DownloadURL(%q,%q) error = %v", tool, arch, err)
			}
			if url == "" || sum == "" {
				t.Fatalf("DownloadURL(%q,%q) returned empty url or checksum", tool, arch)
			}
		}
	}
	if _, _, err := DownloadURL("bad-tool", "x86_64"); err == nil {
		t.Fatal("expected error for unsupported tool")
	}
	if _, _, err := DownloadURL("rg", "s390x"); err == nil {
		t.Fatal("expected error for unsupported arch")
	}
}

func TestEnsureLocal(t *testing.T) {
	cacheDir := t.TempDir()
	payload := []byte("fake-tool-binary")
	sum := sha256.Sum256(payload)
	checksum := hex.EncodeToString(sum[:])

	var hitCount int
	client := &http.Client{
		Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
			hitCount++
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(payload)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	oldSpecs := downloadSpecs
	oldClient := downloadHTTPClient
	oldCacheRoot := cacheRootDir
	t.Cleanup(func() {
		downloadSpecs = oldSpecs
		downloadHTTPClient = oldClient
		cacheRootDir = oldCacheRoot
	})

	downloadSpecs = map[string]map[string]DownloadSpec{
		"rg": {
			"x86_64": {URL: "https://toolkit.example/rg", SHA256: checksum},
		},
	}
	downloadHTTPClient = client
	cacheRootDir = func() (string, error) { return cacheDir, nil }

	got, err := EnsureLocal(context.Background(), "rg", "x86_64")
	if err != nil {
		t.Fatalf("EnsureLocal() error = %v", err)
	}
	content, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", got, err)
	}
	if string(content) != string(payload) {
		t.Fatalf("downloaded payload mismatch: got %q, want %q", string(content), string(payload))
	}
	if hitCount != 1 {
		t.Fatalf("hitCount = %d, want 1", hitCount)
	}

	got2, err := EnsureLocal(context.Background(), "rg", "x86_64")
	if err != nil {
		t.Fatalf("EnsureLocal() cached error = %v", err)
	}
	if got2 != got {
		t.Fatalf("cached path = %q, want %q", got2, got)
	}
	if hitCount != 1 {
		t.Fatalf("expected cache hit without extra download, hitCount = %d", hitCount)
	}
}

func TestDeployTools(t *testing.T) {
	cacheDir := t.TempDir()
	archDir := filepath.Join(cacheDir, "x86_64")
	if err := os.MkdirAll(archDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) error = %v", archDir, err)
	}
	if err := os.WriteFile(filepath.Join(archDir, "rg"), []byte("rg-bin"), 0o755); err != nil {
		t.Fatalf("WriteFile(rg) error = %v", err)
	}

	oldCacheRoot := cacheRootDir
	oldToolkitDir := os.Getenv("SHELLGUARD_TOOLKIT_DIR")
	t.Cleanup(func() {
		cacheRootDir = oldCacheRoot
		_ = os.Setenv("SHELLGUARD_TOOLKIT_DIR", oldToolkitDir)
	})
	cacheRootDir = func() (string, error) { return cacheDir, nil }
	if err := os.Setenv("SHELLGUARD_TOOLKIT_DIR", cacheDir); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}

	t.Run("success", func(t *testing.T) {
		client := newMockSFTPClient()
		msg, err := DeployTools(client, []string{"rg"}, "x86_64")
		if err != nil {
			t.Fatalf("DeployTools() error = %v", err)
		}
		if !strings.Contains(msg, "Deployed") || !strings.Contains(msg, "rg") {
			t.Fatalf("unexpected message: %q", msg)
		}
		if _, ok := client.files[RemoteBinDir+"/rg"]; !ok {
			t.Fatalf("expected remote file %q to be created", RemoteBinDir+"/rg")
		}
		if mode := client.modes[RemoteBinDir+"/rg"]; mode != 0o755 {
			t.Fatalf("remote chmod mode = %o, want 0755", mode)
		}
	})

	t.Run("unsupported arch", func(t *testing.T) {
		client := newMockSFTPClient()
		if _, err := DeployTools(client, []string{"rg"}, "s390x"); err == nil {
			t.Fatal("expected unsupported arch error")
		}
	})

	t.Run("partial failure", func(t *testing.T) {
		client := newMockSFTPClient()
		msg, err := DeployTools(client, []string{"rg", "jq"}, "x86_64")
		if err != nil {
			t.Fatalf("DeployTools() error = %v", err)
		}
		if !strings.Contains(msg, "Deployed") || !strings.Contains(msg, "Errors") {
			t.Fatalf("expected partial failure message, got %q", msg)
		}
	})
}

func TestFormatMissingToolsMessage(t *testing.T) {
	single := FormatMissingToolsMessage([]string{"rg"}, "x86_64")
	if !strings.Contains(single, "rg") {
		t.Fatalf("missing tool not in message: %q", single)
	}

	multi := FormatMissingToolsMessage([]string{"rg", "jq"}, "aarch64")
	if !strings.Contains(multi, "rg, jq") {
		t.Fatalf("tool list not in message: %q", multi)
	}

	all := FormatMissingToolsMessage([]string{"rg", "jq", "yq"}, "x86_64")
	for _, tool := range []string{"rg", "jq", "yq"} {
		if !strings.Contains(all, tool) {
			t.Fatalf("tool %q missing in message: %q", tool, all)
		}
	}
}

type mockSFTPClient struct {
	mu       sync.Mutex
	files    map[string][]byte
	modes    map[string]os.FileMode
	mkdirAll []string
}

func newMockSFTPClient() *mockSFTPClient {
	return &mockSFTPClient{
		files: make(map[string][]byte),
		modes: make(map[string]os.FileMode),
	}
}

func (m *mockSFTPClient) Stat(_ string) (os.FileInfo, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSFTPClient) Open(_ string) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSFTPClient) Create(path string) (io.WriteCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf := &bytes.Buffer{}
	return &mockWriteCloser{
		onClose: func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.files[path] = append([]byte(nil), buf.Bytes()...)
		},
		Buffer: buf,
	}, nil
}

func (m *mockSFTPClient) MkdirAll(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mkdirAll = append(m.mkdirAll, path)
	return nil
}

func (m *mockSFTPClient) Chmod(path string, mode os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.modes[path] = mode
	return nil
}

func (m *mockSFTPClient) Close() error {
	return nil
}

type mockWriteCloser struct {
	*bytes.Buffer
	onClose func()
}

func (m *mockWriteCloser) Close() error {
	if m.onClose != nil {
		m.onClose()
	}
	return nil
}

var _ ssh.SFTPClient = (*mockSFTPClient)(nil)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
