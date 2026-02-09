// Package toolkit downloads and deploys diagnostic tools (rg, jq, yq) to remote servers.
package toolkit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jonchun/shellguard/ssh"
)

var ToolkitTools = []string{"rg", "jq", "yq"}

const (
	RemoteBinDir        = ".shellguard/bin"
	toolkitOverrideEnv  = "SHELLGUARD_TOOLKIT_DIR"
	defaultDownloadMode = 0o755
)

type DownloadSpec struct {
	URL     string
	SHA256  string
	Archive bool
}

var downloadSpecs = map[string]map[string]DownloadSpec{
	"rg": {
		"x86_64": {
			URL:     "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz",
			SHA256:  "4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e",
			Archive: true,
		},
		"aarch64": {
			URL:     "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-aarch64-unknown-linux-gnu.tar.gz",
			SHA256:  "c827481c4ff4ea10c9dc7a4022c8de5db34a5737cb74484d62eb94a95841ab2f",
			Archive: true,
		},
	},
	"jq": {
		"x86_64": {
			URL:    "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-amd64",
			SHA256: "5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5",
		},
		"aarch64": {
			URL:    "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-arm64",
			SHA256: "4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5",
		},
	},
	"yq": {
		"x86_64": {
			URL:    "https://github.com/mikefarah/yq/releases/download/v4.52.2/yq_linux_amd64",
			SHA256: "a74bd266990339e0c48a2103534aef692abf99f19390d12c2b0ce6830385c459",
		},
		"aarch64": {
			URL:    "https://github.com/mikefarah/yq/releases/download/v4.52.2/yq_linux_arm64",
			SHA256: "c82856ac30da522f50dcdd4f53065487b5a2927e9b87ff637956900986f1f7c2",
		},
	},
}

var (
	downloadHTTPClient = &http.Client{Timeout: 60 * time.Second}
	cacheRootDir       = defaultCacheRootDir
)

func BuildProbeCommand() string {
	return "PATH=$HOME/.shellguard/bin:$PATH command -v rg jq yq 2>/dev/null; echo '---'; uname -m"
}

func ParseProbeOutput(stdout string) (missing []string, arch string) {
	found := map[string]struct{}{}
	parts := strings.SplitN(stdout, "---", 2)
	foundSection := ""
	if len(parts) > 0 {
		foundSection = strings.TrimSpace(parts[0])
	}
	arch = "unknown"
	if len(parts) == 2 {
		if got := strings.TrimSpace(parts[1]); got != "" {
			arch = got
		}
	}

	for _, line := range strings.Split(foundSection, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		found[filepath.Base(line)] = struct{}{}
	}
	for _, tool := range ToolkitTools {
		if _, ok := found[tool]; !ok {
			missing = append(missing, tool)
		}
	}
	return missing, arch
}

func NormalizeArch(arch string) (string, error) {
	switch strings.TrimSpace(arch) {
	case "x86_64":
		return "x86_64", nil
	case "aarch64", "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", arch)
	}
}

func DownloadURL(tool, arch string) (url string, sha256Hex string, err error) {
	spec, err := getDownloadSpec(tool, arch)
	if err != nil {
		return "", "", err
	}
	return spec.URL, spec.SHA256, nil
}

func EnsureLocal(ctx context.Context, tool, arch string) (string, error) {
	normArch, err := NormalizeArch(arch)
	if err != nil {
		return "", err
	}

	if overrideDir := strings.TrimSpace(os.Getenv(toolkitOverrideEnv)); overrideDir != "" {
		overridePath := filepath.Join(overrideDir, normArch, tool)
		info, statErr := os.Stat(overridePath)
		if statErr != nil {
			return "", fmt.Errorf("tool %q not found in %s: %w", tool, overridePath, statErr)
		}
		if info.IsDir() {
			return "", fmt.Errorf("tool %q override path %s is a directory", tool, overridePath)
		}
		return overridePath, nil
	}

	rootDir, err := cacheRootDir()
	if err != nil {
		return "", err
	}
	toolDir := filepath.Join(rootDir, normArch)
	targetPath := filepath.Join(toolDir, tool)

	if info, statErr := os.Stat(targetPath); statErr == nil && !info.IsDir() {
		return targetPath, nil
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return "", statErr
	}

	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir %s: %w", toolDir, err)
	}

	spec, err := getDownloadSpec(tool, normArch)
	if err != nil {
		return "", err
	}

	body, err := downloadFile(ctx, spec.URL)
	if err != nil {
		return "", err
	}
	if err := verifySHA256(body, spec.SHA256); err != nil {
		return "", fmt.Errorf("checksum mismatch for %s: %w", spec.URL, err)
	}

	payload := body
	if spec.Archive {
		payload, err = extractFromTarGz(body, tool)
		if err != nil {
			return "", fmt.Errorf("extract tool %q from archive: %w", tool, err)
		}
	}

	tmp, err := os.CreateTemp(toolDir, tool+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temp file in %s: %w", toolDir, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Chmod(defaultDownloadMode); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("chmod temp file %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, targetPath); err != nil {
		return "", fmt.Errorf("move temp file to %s: %w", targetPath, err)
	}
	return targetPath, nil
}

func DeployTools(sftpClient ssh.SFTPClient, missing []string, arch string) (string, error) {
	normArch, err := NormalizeArch(arch)
	if err != nil {
		return "", err
	}

	if len(missing) == 0 {
		return "Nothing to deploy.", nil
	}
	if err := sftpClient.MkdirAll(RemoteBinDir); err != nil {
		return "", fmt.Errorf("create remote directory %s: %w", RemoteBinDir, err)
	}

	deployed := make([]string, 0, len(missing))
	problems := make([]string, 0)

	for _, tool := range missing {
		localPath, err := EnsureLocal(context.Background(), tool, normArch)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", tool, err))
			continue
		}
		remotePath := path.Join(RemoteBinDir, tool)
		if err := uploadTool(sftpClient, localPath, remotePath); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", tool, err))
			continue
		}
		deployed = append(deployed, tool)
	}

	parts := []string{}
	if len(deployed) > 0 {
		parts = append(parts, fmt.Sprintf("Deployed to ~/.shellguard/bin/: %s", strings.Join(deployed, ", ")))
	}
	if len(problems) > 0 {
		parts = append(parts, "Errors: "+strings.Join(problems, "; "))
	}
	if len(parts) == 0 {
		return "Nothing to deploy.", nil
	}
	return strings.Join(parts, "\n"), nil
}

func FormatMissingToolsMessage(missing []string, arch string) string {
	if len(missing) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\n\nMissing tools: %s\nArchitecture: %s\nThese tools can be deployed to ~/.shellguard/bin/ on the remote server using the provision tool. Ask the operator for approval before deploying.",
		strings.Join(missing, ", "),
		arch,
	)
}

func getDownloadSpec(tool, arch string) (DownloadSpec, error) {
	normArch, err := NormalizeArch(arch)
	if err != nil {
		return DownloadSpec{}, err
	}
	toolMap, ok := downloadSpecs[tool]
	if !ok {
		return DownloadSpec{}, fmt.Errorf("unsupported toolkit tool %q", tool)
	}
	spec, ok := toolMap[normArch]
	if !ok {
		return DownloadSpec{}, fmt.Errorf("no download mapping for tool %q arch %q", tool, normArch)
	}
	return spec, nil
}

func defaultCacheRootDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".cache", "shellguard", "toolkit"), nil
}

func downloadFile(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request %s: %w", url, err)
	}
	resp, err := downloadHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: unexpected status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return body, nil
}

func verifySHA256(content []byte, expected string) error {
	sum := sha256.Sum256(content)
	got := hex.EncodeToString(sum[:])
	if !strings.EqualFold(got, strings.TrimSpace(expected)) {
		return fmt.Errorf("got %s want %s", got, expected)
	}
	return nil
}

func extractFromTarGz(content []byte, tool string) ([]byte, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return nil, err
	}
	defer func() { _ = gzReader.Close() }()

	tr := tar.NewReader(gzReader)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.FileInfo().IsDir() {
			continue
		}
		if filepath.Base(hdr.Name) == tool {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", tool)
}

func uploadTool(sftpClient ssh.SFTPClient, localPath, remotePath string) error {
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local binary %s: %w", localPath, err)
	}
	defer func() { _ = localFile.Close() }()

	remoteFile, err := sftpClient.Create(remotePath)
	if err != nil {
		return fmt.Errorf("create remote file %s: %w", remotePath, err)
	}
	if _, err := io.Copy(remoteFile, localFile); err != nil {
		_ = remoteFile.Close()
		return fmt.Errorf("upload to %s: %w", remotePath, err)
	}
	if err := remoteFile.Close(); err != nil {
		return fmt.Errorf("close remote file %s: %w", remotePath, err)
	}
	if err := sftpClient.Chmod(remotePath, defaultDownloadMode); err != nil {
		return fmt.Errorf("chmod remote file %s: %w", remotePath, err)
	}
	return nil
}
