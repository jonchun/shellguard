package shellguard_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonchun/shellguard/manifest"
	"github.com/jonchun/shellguard/parser"
	"github.com/jonchun/shellguard/server"
	"github.com/jonchun/shellguard/ssh"
	"github.com/jonchun/shellguard/toolkit"
	"github.com/jonchun/shellguard/validator"
)

func validateCommand(t *testing.T, registry map[string]*manifest.Manifest, command string) error {
	t.Helper()
	pipeline, err := parser.Parse(command)
	if err != nil {
		return err
	}
	return validator.ValidatePipeline(pipeline, registry)
}

func TestIntegrationSecurity_AllowedReadOnlyCommands(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}

	allowed := []string{
		"ls /tmp",
		"find /var/log -name '*.log' | head -20",
		"psql -c 'SELECT 1'",
		"docker ps",
		"aws ec2 describe-instances",
	}

	for _, cmd := range allowed {
		if err := validateCommand(t, registry, cmd); err != nil {
			t.Fatalf("expected allowed command %q, got error: %v", cmd, err)
		}
	}
}

func TestIntegrationSecurity_RejectsMutationAndEscapes(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}

	rejected := []string{
		"rm /tmp/file",
		"systemctl start nginx",
		"docker run alpine",
		"psql -c 'DELETE FROM users'",
		"python -c 'print(1)'",
		"apt update",
		"vim /tmp/file",
		"env bash -lc id",
		"curl -X POST https://example.com",
		"unzip archive.zip",
		"tar -xf archive.tar",
	}

	for _, cmd := range rejected {
		if err := validateCommand(t, registry, cmd); err == nil {
			t.Fatalf("expected rejected command %q to fail validation", cmd)
		}
	}
}

func TestIntegrationSecurity_RejectsParserEscapes(t *testing.T) {
	rejectedByParser := []string{
		"echo $(id)",
		"cat /etc/passwd > /tmp/x",
		"sleep 1 &",
		"ls /tmp; rm -rf /",
	}

	for _, cmd := range rejectedByParser {
		if _, err := parser.Parse(cmd); err == nil {
			t.Fatalf("expected parser to reject %q", cmd)
		}
	}
}

func TestIntegrationProbeCommandContract(t *testing.T) {
	cmd := toolkit.BuildProbeCommand()
	if cmd != "PATH=$HOME/.shellguard/bin:$PATH command -v rg jq yq 2>/dev/null; echo '---'; uname -m" {
		t.Fatalf("unexpected probe command: %q", cmd)
	}

	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}
	runner := &integrationRunner{
		executeRawResults: map[string]ssh.ExecResult{
			cmd: {Stdout: "/usr/bin/jq\n---\nx86_64\n"},
		},
	}
	core := server.NewCore(registry, runner, nil)
	if _, err := core.Connect(context.Background(), server.ConnectInput{Host: "host1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if len(runner.executeRawCalls) == 0 || runner.executeRawCalls[0] != cmd {
		t.Fatalf("expected ExecuteRaw probe call %q, got %#v", cmd, runner.executeRawCalls)
	}
}

func TestIntegrationToolkitPathReconstructionCorrect(t *testing.T) {
	pipeline, err := parser.Parse("ls /tmp")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	got := ssh.ReconstructCommand(pipeline, false, true)
	if !strings.HasPrefix(got, "PATH=$HOME/.shellguard/bin:$PATH ") {
		t.Fatalf("expected toolkit PATH prefix, got %q", got)
	}
}

func TestIntegrationToolNames(t *testing.T) {
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}
	for _, tool := range toolkit.ToolkitTools {
		m := registry[tool]
		if m == nil {
			t.Fatalf("missing manifest for toolkit tool %q", tool)
		}
		if m.Deny {
			t.Fatalf("tool %q must be allowed, but manifest is deny=true", tool)
		}
	}
}

func TestIntegration_StdioServerStartsAndExitsOnEOF(t *testing.T) {
	bin := integrationBinary(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin)
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		t.Fatalf("run shellguard stdio server: %v", err)
	}
}

type integrationRunner struct {
	executeRawResults map[string]ssh.ExecResult
	executeRawCalls   []string
}

func (r *integrationRunner) Connect(_ context.Context, _ ssh.ConnectionParams) error {
	return nil
}

func (r *integrationRunner) Execute(_ context.Context, _, _ string, _ time.Duration) (ssh.ExecResult, error) {
	return ssh.ExecResult{Stdout: "ok", ExitCode: 0}, nil
}

func (r *integrationRunner) ExecuteRaw(_ context.Context, _, command string, _ time.Duration) (ssh.ExecResult, error) {
	r.executeRawCalls = append(r.executeRawCalls, command)
	if res, ok := r.executeRawResults[command]; ok {
		return res, nil
	}
	return ssh.ExecResult{}, nil
}

func (r *integrationRunner) SFTPSession(_ string) (ssh.SFTPClient, error) {
	return nil, errors.New("not implemented")
}

func (r *integrationRunner) Disconnect(_ string) error {
	return nil
}

var (
	binaryOnce sync.Once
	binaryPath string
	binaryErr  error
)

func integrationBinary(t *testing.T) string {
	t.Helper()

	binaryOnce.Do(func() {
		root := moduleRoot(t)
		dir, err := os.MkdirTemp("", "shellguard-integration-bin-*")
		if err != nil {
			binaryErr = err
			return
		}
		binaryPath = filepath.Join(dir, "shellguard")
		cmd := exec.Command("go", "build", "-o", binaryPath, "./cmd/shellguard")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			binaryErr = fmt.Errorf("go build failed: %w: %s", err, string(out))
		}
	})

	if binaryErr != nil {
		t.Fatalf("build integration binary: %v", binaryErr)
	}
	return binaryPath
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(file)
}
