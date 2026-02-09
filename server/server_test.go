package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonchun/shellguard/manifest"
	"github.com/jonchun/shellguard/output"
	"github.com/jonchun/shellguard/parser"
	"github.com/jonchun/shellguard/ssh"
	"github.com/jonchun/shellguard/toolkit"
	"github.com/jonchun/shellguard/validator"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeRunner struct {
	mu               sync.Mutex
	connectCalled    bool
	executeCalled    bool
	disconnectCalled bool
	lastCommand      string
	lastExecuteHost  string
	order            *[]string
	connectErr       error
	executeErr       error
	executeResult    ssh.ExecResult
	executeRawErrs   map[string]error
	executeRawRes    map[string]ssh.ExecResult
	executeRawCalls  []string
	connected        map[string]bool
	sftpClient       ssh.SFTPClient
	sftpErr          error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		executeRawErrs: make(map[string]error),
		executeRawRes:  make(map[string]ssh.ExecResult),
		connected:      make(map[string]bool),
		executeResult:  ssh.ExecResult{Stdout: "stdout", Stderr: "", ExitCode: 0, RuntimeMs: 12},
	}
}

func (f *fakeRunner) Connect(_ context.Context, p ssh.ConnectionParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connectErr != nil {
		return f.connectErr
	}
	f.connectCalled = true
	f.connected[p.Host] = true
	return nil
}

func (f *fakeRunner) Execute(_ context.Context, host, command string, _ time.Duration) (ssh.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executeCalled = true
	f.lastExecuteHost = host
	f.lastCommand = command
	if f.order != nil {
		*f.order = append(*f.order, "execute")
	}
	if f.executeErr != nil {
		return ssh.ExecResult{}, f.executeErr
	}
	return f.executeResult, nil
}

func (f *fakeRunner) ExecuteRaw(_ context.Context, host, command string, _ time.Duration) (ssh.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executeRawCalls = append(f.executeRawCalls, command)
	if host != "" && !f.connected[host] {
		return ssh.ExecResult{}, errors.New("not connected")
	}
	if err, ok := f.executeRawErrs[command]; ok {
		return ssh.ExecResult{}, err
	}
	if res, ok := f.executeRawRes[command]; ok {
		return res, nil
	}
	return ssh.ExecResult{}, nil
}

func (f *fakeRunner) SFTPSession(host string) (ssh.SFTPClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sftpErr != nil {
		return nil, f.sftpErr
	}
	if host != "" && !f.connected[host] {
		return nil, errors.New("not connected")
	}
	if f.sftpClient == nil {
		return nil, errors.New("missing sftp client")
	}
	return f.sftpClient, nil
}

func (f *fakeRunner) Disconnect(_ context.Context, host string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnectCalled = true
	if host == "" {
		for h := range f.connected {
			delete(f.connected, h)
		}
	} else {
		delete(f.connected, host)
	}
	return nil
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

func (m *mockSFTPClient) Stat(path string) (os.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	content, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return fakeFileInfo{name: path, size: int64(len(content)), mode: 0o644}, nil
}

func (m *mockSFTPClient) Open(path string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	content, ok := m.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

func (m *mockSFTPClient) Create(path string) (io.WriteCloser, error) {
	buf := &bytes.Buffer{}
	return &mockWriteCloser{
		Buffer: buf,
		onClose: func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.files[path] = append([]byte(nil), buf.Bytes()...)
		},
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

type fakeFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }

func basicRegistry() map[string]*manifest.Manifest {
	return map[string]*manifest.Manifest{
		"ls": {Name: "ls", Timeout: 30},
		"rg": {Name: "rg", Timeout: 30},
		"jq": {Name: "jq", Timeout: 30},
		"yq": {Name: "yq", Timeout: 30},
		"rm": {Name: "rm", Deny: true, Reason: "no writes"},
	}
}

func TestExecuteChainOrder(t *testing.T) {
	order := []string{}
	runner := newFakeRunner()
	runner.order = &order
	core := NewCore(basicRegistry(), runner, nil)

	core.Parse = func(_ string) (*parser.Pipeline, error) {
		order = append(order, "parse")
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error {
		order = append(order, "validate")
		return nil
	}
	core.Reconstruct = func(_ *parser.Pipeline, _, _ bool) string {
		order = append(order, "reconstruct")
		return "ls"
	}
	core.Truncate = func(_, _ string, _, _ int, _ ...int) output.CommandResult {
		order = append(order, "truncate")
		return output.CommandResult{Stdout: "stdout"}
	}

	_, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	want := []string{"parse", "validate", "reconstruct", "execute", "truncate"}
	if !reflect.DeepEqual(order, want) {
		t.Fatalf("order = %#v, want %#v", order, want)
	}
}

func TestExecuteStopsBeforeRunnerOnParseError(t *testing.T) {
	runner := newFakeRunner()
	core := NewCore(basicRegistry(), runner, nil)
	core.Parse = func(_ string) (*parser.Pipeline, error) { return nil, errors.New("parse failed") }

	_, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls"})
	if err == nil {
		t.Fatal("expected parse error")
	}
	if runner.executeCalled {
		t.Fatal("runner execute must not be called on parse error")
	}
}

func TestExecuteStopsBeforeRunnerOnValidationError(t *testing.T) {
	runner := newFakeRunner()
	core := NewCore(basicRegistry(), runner, nil)
	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error {
		return errors.New("validation failed")
	}

	_, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls"})
	if err == nil {
		t.Fatal("expected validation error")
	}
	if runner.executeCalled {
		t.Fatal("runner execute must not be called on validation error")
	}
}

func TestConnectProbeReportsMissing(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/jq\n---\nx86_64\n",
	}
	runner.executeRawRes["test -d $HOME/.shellguard/bin && echo yes"] = ssh.ExecResult{}

	core := NewCore(basicRegistry(), runner, nil)
	out, err := core.Connect(context.Background(), ConnectInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	msg, _ := out["message"].(string)
	if !strings.Contains(msg, "Missing tools") || !strings.Contains(msg, "rg") || !strings.Contains(msg, "yq") {
		t.Fatalf("unexpected connect message %q", msg)
	}
}

func TestConnectProbeAllPresent(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/rg\n/usr/bin/jq\n/usr/bin/yq\n---\nx86_64\n",
	}

	core := NewCore(basicRegistry(), runner, nil)
	out, err := core.Connect(context.Background(), ConnectInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	msg, _ := out["message"].(string)
	if strings.Contains(msg, "Missing tools") {
		t.Fatalf("did not expect missing-tools message: %q", msg)
	}
}

func TestConnectProbeFailsGracefully(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawErrs[toolkit.BuildProbeCommand()] = errors.New("probe failed")
	core := NewCore(basicRegistry(), runner, nil)

	out, err := core.Connect(context.Background(), ConnectInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Connect() should succeed even when probe fails: %v", err)
	}
	if out["ok"] != true {
		t.Fatalf("unexpected connect result: %#v", out)
	}
}

func TestConnectAutoEnablesToolkitPathWhenDirExists(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/jq\n---\nx86_64\n",
	}
	runner.executeRawRes["test -d $HOME/.shellguard/bin && echo yes"] = ssh.ExecResult{Stdout: "yes\n"}
	core := NewCore(basicRegistry(), runner, nil)

	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	var toolkitPath bool
	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error { return nil }
	core.Reconstruct = func(_ *parser.Pipeline, _, p bool) string {
		toolkitPath = p
		return "ls"
	}
	if _, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls"}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !toolkitPath {
		t.Fatal("toolkitPath should be true when ~/.shellguard/bin exists on remote")
	}
}

func TestProvisionNothingMissing(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/rg\n/usr/bin/jq\n/usr/bin/yq\n---\nx86_64\n",
	}
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	out, err := core.Provision(context.Background(), ProvisionInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	msg, _ := out["message"].(string)
	if !strings.Contains(strings.ToLower(msg), "already") {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestProvisionArchUnknown(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/jq\n---\n\n",
	}
	runner.sftpClient = newMockSFTPClient()
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if _, err := core.Provision(context.Background(), ProvisionInput{Host: "h1"}); err == nil {
		t.Fatal("expected architecture error")
	}
}

func TestProvisionSuccessEnablesToolkitPath(t *testing.T) {
	t.Setenv("SHELLGUARD_TOOLKIT_DIR", t.TempDir())
	overrideDir := os.Getenv("SHELLGUARD_TOOLKIT_DIR")
	if err := os.MkdirAll(overrideDir+"/x86_64", 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(overrideDir+"/x86_64/rg", []byte("rg-bin"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runner := newFakeRunner()
	sftp := newMockSFTPClient()
	runner.sftpClient = sftp
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/jq\n---\nx86_64\n",
	}

	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if _, err := core.Provision(context.Background(), ProvisionInput{Host: "h1"}); err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if _, ok := sftp.files[toolkit.RemoteBinDir+"/rg"]; !ok {
		t.Fatalf("expected %q to be uploaded", toolkit.RemoteBinDir+"/rg")
	}

	var toolkitPath bool
	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error { return nil }
	core.Reconstruct = func(_ *parser.Pipeline, _, p bool) string {
		toolkitPath = p
		return "ls"
	}
	if _, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls"}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !toolkitPath {
		t.Fatal("toolkitPath should be true after successful provision")
	}
}

func TestExecuteNoToolkitPathByDefault(t *testing.T) {
	runner := newFakeRunner()
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	var toolkitPath bool
	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error { return nil }
	core.Reconstruct = func(_ *parser.Pipeline, _, p bool) string {
		toolkitPath = p
		return "ls"
	}
	if _, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls"}); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if toolkitPath {
		t.Fatal("toolkitPath should be false by default")
	}
}

func TestDisconnectCleansUpState(t *testing.T) {
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/jq\n---\nx86_64\n",
	}
	core := NewCore(basicRegistry(), runner, nil)

	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	core.setToolkitDeployed("h1", true)
	if _, err := core.Disconnect(context.Background(), DisconnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if _, ok := core.getProbeState("h1"); ok {
		t.Fatal("expected probe state to be cleared")
	}
	if core.isToolkitDeployed("h1") {
		t.Fatal("expected toolkitDeployed to be cleared")
	}
}

func TestDownloadSuccess(t *testing.T) {
	runner := newFakeRunner()
	sftp := newMockSFTPClient()
	sftp.files["/var/log/test.log"] = []byte("hello")
	runner.sftpClient = sftp
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	out, err := core.DownloadFile(context.Background(), DownloadInput{
		Host:       "h1",
		RemotePath: "/var/log/test.log",
		LocalDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("DownloadFile() error = %v", err)
	}
	if out.Filename != "test.log" {
		t.Fatalf("filename = %q, want test.log", out.Filename)
	}
	if out.SizeBytes != 5 {
		t.Fatalf("size = %d, want 5", out.SizeBytes)
	}
	content, err := os.ReadFile(out.LocalPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", out.LocalPath, err)
	}
	if string(content) != "hello" {
		t.Fatalf("local content = %q, want hello", string(content))
	}
}

func TestDownloadFileTooLarge(t *testing.T) {
	runner := newFakeRunner()
	sftp := newMockSFTPClient()
	sftp.files["/var/data/huge.bin"] = make([]byte, maxDownloadBytes+1)
	runner.sftpClient = sftp
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if _, err := core.DownloadFile(context.Background(), DownloadInput{
		Host:       "h1",
		RemotePath: "/var/data/huge.bin",
		LocalDir:   t.TempDir(),
	}); err == nil {
		t.Fatal("expected size-limit error")
	}
}

func TestDownloadFileNotFound(t *testing.T) {
	runner := newFakeRunner()
	runner.sftpClient = newMockSFTPClient()
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if _, err := core.DownloadFile(context.Background(), DownloadInput{
		Host:       "h1",
		RemotePath: "/nonexistent",
		LocalDir:   t.TempDir(),
	}); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestDownloadLocalDirOverride(t *testing.T) {
	runner := newFakeRunner()
	sftp := newMockSFTPClient()
	sftp.files["/var/log/test.log"] = []byte("ok")
	runner.sftpClient = sftp
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	localDir := t.TempDir()
	out, err := core.DownloadFile(context.Background(), DownloadInput{
		Host:       "h1",
		RemotePath: "/var/log/test.log",
		LocalDir:   localDir,
	})
	if err != nil {
		t.Fatalf("DownloadFile() error = %v", err)
	}
	if !strings.HasPrefix(out.LocalPath, localDir+string(os.PathSeparator)) {
		t.Fatalf("expected local path in %q, got %q", localDir, out.LocalPath)
	}
}

func TestDownloadNameCollision(t *testing.T) {
	runner := newFakeRunner()
	sftp := newMockSFTPClient()
	sftp.files["/var/log/test.log"] = []byte("new")
	runner.sftpClient = sftp
	core := NewCore(basicRegistry(), runner, nil)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	localDir := t.TempDir()
	if err := os.WriteFile(localDir+"/test.log", []byte("old"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	out, err := core.DownloadFile(context.Background(), DownloadInput{
		Host:       "h1",
		RemotePath: "/var/log/test.log",
		LocalDir:   localDir,
	})
	if err != nil {
		t.Fatalf("DownloadFile() error = %v", err)
	}
	if !strings.HasSuffix(out.LocalPath, "test_1.log") {
		t.Fatalf("expected collision-safe name, got %q", out.LocalPath)
	}
}

func TestCollisionSafePath_NoCollision(t *testing.T) {
	dir := t.TempDir()
	got, err := collisionSafePath(dir, "report.csv")
	if err != nil {
		t.Fatalf("collisionSafePath() error = %v", err)
	}
	want := filepath.Join(dir, "report.csv")
	if got != want {
		t.Fatalf("collisionSafePath() = %q, want %q", got, want)
	}
}

func TestCollisionSafePath_WithCollisions(t *testing.T) {
	dir := t.TempDir()
	// Create the base file and first two numbered variants.
	for _, name := range []string{"data.log", "data_1.log", "data_2.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}

	got, err := collisionSafePath(dir, "data.log")
	if err != nil {
		t.Fatalf("collisionSafePath() error = %v", err)
	}
	want := filepath.Join(dir, "data_3.log")
	if got != want {
		t.Fatalf("collisionSafePath() = %q, want %q", got, want)
	}
}

func TestCollisionSafePath_Exhausted(t *testing.T) {
	dir := t.TempDir()

	// Temporarily lower the retry limit.
	orig := maxCollisionRetries
	maxCollisionRetries = 3
	t.Cleanup(func() { maxCollisionRetries = orig })

	// Create base file plus numbered variants 1..3 to exhaust all candidates.
	for _, name := range []string{"f.txt", "f_1.txt", "f_2.txt", "f_3.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", name, err)
		}
	}

	_, err := collisionSafePath(dir, "f.txt")
	if err == nil {
		t.Fatal("expected error when all candidates exhausted")
	}
	if !strings.Contains(err.Error(), "collision") {
		t.Fatalf("error should mention collision, got: %v", err)
	}
}

func TestNewMCPServerRegistersTools(t *testing.T) {
	ctx := context.Background()
	core := NewCore(basicRegistry(), newFakeRunner(), nil)
	s := NewMCPServer(core)
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	t1, t2 := mcp.NewInMemoryTransports()
	ss, err := s.Connect(ctx, t1, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() { _ = ss.Close() }()
	cs, err := c.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	found := map[string]*mcp.Tool{}
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("tools iterator error: %v", err)
		}
		found[tool.Name] = tool
	}

	for _, name := range []string{"connect", "execute", "disconnect", "provision", "download_file"} {
		if _, ok := found[name]; !ok {
			t.Fatalf("missing tool %q", name)
		}
	}

	provision := found["provision"]
	if !strings.Contains(provision.Description, "WRITE operation") {
		t.Fatalf("expected provision description to mention WRITE operation, got %q", provision.Description)
	}
	if provision.Annotations == nil {
		t.Fatal("expected provision annotations")
	}
	if provision.Annotations.ReadOnlyHint {
		t.Fatal("provision should not be read-only")
	}
	if !provision.Annotations.IdempotentHint {
		t.Fatal("provision should be idempotent")
	}

	download := found["download_file"]
	if !strings.Contains(download.Description, "WRITE operation") {
		t.Fatalf("expected download description to mention WRITE operation, got %q", download.Description)
	}
	if download.Annotations == nil {
		t.Fatal("expected download annotations")
	}
	if download.Annotations.ReadOnlyHint {
		t.Fatal("download_file should not be read-only")
	}
}

func TestNewCoreAcceptsLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	core := NewCore(basicRegistry(), newFakeRunner(), logger)
	if core.logger == nil {
		t.Fatal("expected logger to be set")
	}
}

func TestNewCoreNilLoggerUsesDiscard(t *testing.T) {
	core := NewCore(basicRegistry(), newFakeRunner(), nil)
	if core.logger == nil {
		t.Fatal("expected discard logger, got nil")
	}
}

func TestCoreLoggerReturnsLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	core := NewCore(basicRegistry(), newFakeRunner(), logger)
	if got := core.Logger(); got != logger {
		t.Fatalf("Logger() = %v, want %v", got, logger)
	}
}

func TestCoreLoggerReturnsDiscardWhenNil(t *testing.T) {
	core := NewCore(basicRegistry(), newFakeRunner(), nil)
	if got := core.Logger(); got == nil {
		t.Fatal("Logger() should return discard logger, got nil")
	}
}

func TestExecuteLogsSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	runner := newFakeRunner()
	core := NewCore(basicRegistry(), runner, logger)

	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "ls"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error { return nil }
	core.Reconstruct = func(_ *parser.Pipeline, _, _ bool) string { return "ls" }

	_, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "ls -la"})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	logged := buf.String()
	for _, want := range []string{`"command"`, `"ls -la"`, `"host"`, `"h1"`, `"outcome"`, `"success"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestExecuteLogsRejection(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	core := NewCore(basicRegistry(), newFakeRunner(), logger)

	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: "rm"}}}, nil
	}
	core.Validate = func(_ *parser.Pipeline, _ map[string]*manifest.Manifest) error {
		return &validator.ValidationError{Message: "command denied: rm"}
	}

	_, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "rm -rf /"})
	if err == nil {
		t.Fatal("expected validation error")
	}

	logged := buf.String()
	for _, want := range []string{`"command"`, `"rm -rf /"`, `"outcome"`, `"rejected"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestExecuteLogsParseError(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	core := NewCore(basicRegistry(), newFakeRunner(), logger)

	core.Parse = func(_ string) (*parser.Pipeline, error) {
		return nil, &parser.ParseError{Message: "syntax error"}
	}

	_, err := core.Execute(context.Background(), ExecuteInput{Host: "h1", Command: "$(evil)"})
	if err == nil {
		t.Fatal("expected parse error")
	}

	logged := buf.String()
	for _, want := range []string{`"command"`, `"$(evil)"`, `"outcome"`, `"rejected"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestConnectLogsSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	runner := newFakeRunner()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/rg\n/usr/bin/jq\n/usr/bin/yq\n---\nx86_64\n",
	}
	core := NewCore(basicRegistry(), runner, logger)

	_, err := core.Connect(context.Background(), ConnectInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	logged := buf.String()
	for _, want := range []string{`"connect"`, `"host"`, `"h1"`, `"outcome"`, `"success"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestConnectLogsFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	runner := newFakeRunner()
	runner.connectErr = errors.New("connection refused")
	core := NewCore(basicRegistry(), runner, logger)

	_, err := core.Connect(context.Background(), ConnectInput{Host: "h1"})
	if err == nil {
		t.Fatal("expected error")
	}

	logged := buf.String()
	for _, want := range []string{`"connect"`, `"h1"`, `"outcome"`, `"error"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestDisconnectLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	runner := newFakeRunner()
	core := NewCore(basicRegistry(), runner, logger)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	_, err := core.Disconnect(context.Background(), DisconnectInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	logged := buf.String()
	for _, want := range []string{`"disconnect"`, `"h1"`, `"outcome"`, `"success"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestProvisionLogsSuccess(t *testing.T) {
	t.Setenv("SHELLGUARD_TOOLKIT_DIR", t.TempDir())
	overrideDir := os.Getenv("SHELLGUARD_TOOLKIT_DIR")
	if err := os.MkdirAll(overrideDir+"/x86_64", 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(overrideDir+"/x86_64/rg", []byte("rg-bin"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	runner := newFakeRunner()
	runner.sftpClient = newMockSFTPClient()
	runner.executeRawRes[toolkit.BuildProbeCommand()] = ssh.ExecResult{
		Stdout: "/usr/bin/jq\n---\nx86_64\n",
	}
	core := NewCore(basicRegistry(), runner, logger)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	_, err := core.Provision(context.Background(), ProvisionInput{Host: "h1"})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	logged := buf.String()
	for _, want := range []string{`"provision"`, `"h1"`, `"outcome"`, `"success"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}

func TestDownloadFileLogsSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	runner := newFakeRunner()
	sftp := newMockSFTPClient()
	sftp.files["/var/log/test.log"] = []byte("hello")
	runner.sftpClient = sftp
	core := NewCore(basicRegistry(), runner, logger)
	if _, err := core.Connect(context.Background(), ConnectInput{Host: "h1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	_, err := core.DownloadFile(context.Background(), DownloadInput{
		Host:       "h1",
		RemotePath: "/var/log/test.log",
		LocalDir:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("DownloadFile() error = %v", err)
	}

	logged := buf.String()
	for _, want := range []string{`"download"`, `"/var/log/test.log"`, `"h1"`, `"outcome"`, `"success"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("log output missing %s:\n%s", want, logged)
		}
	}
}
