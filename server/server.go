// Package server wires together the security pipeline and registers MCP tools.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jonchun/shellguard/manifest"
	"github.com/jonchun/shellguard/output"
	"github.com/jonchun/shellguard/parser"
	"github.com/jonchun/shellguard/ssh"
	"github.com/jonchun/shellguard/toolkit"
	"github.com/jonchun/shellguard/validator"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxDownloadBytes   = 50 * 1024 * 1024
	defaultDownloadDir = "/tmp/shellguard-downloads"
)

// Executor runs commands on remote targets.
type Executor interface {
	Connect(ctx context.Context, params ssh.ConnectionParams) error
	Execute(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error)
	ExecuteRaw(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error)
	SFTPSession(host string) (ssh.SFTPClient, error)
	Disconnect(host string) error
}

type ProbeResult struct {
	Missing []string
	Arch    string
}

type Core struct {
	Registry map[string]*manifest.Manifest
	Runner   Executor

	Parse       func(string) (*parser.Pipeline, error)
	Validate    func(*parser.Pipeline, map[string]*manifest.Manifest) error
	Reconstruct func(*parser.Pipeline, bool, bool) string
	Truncate    func(string, string, int, int, ...int) output.CommandResult

	DefaultTimeout   int
	MaxOutputBytes   int
	MaxDownloadBytes int
	DownloadDir      string
	MaxSleepSeconds  int

	logger          *slog.Logger
	mu              sync.RWMutex
	probeState      map[string]*ProbeResult
	toolkitDeployed map[string]bool
	connectedHosts  map[string]struct{}
}

type ConnectInput struct {
	Host         string `json:"host" jsonschema:"Hostname or IP address"`
	User         string `json:"user,omitempty" jsonschema:"SSH username (default root)"`
	Port         int    `json:"port,omitempty" jsonschema:"SSH port (default 22)"`
	IdentityFile string `json:"identity_file,omitempty" jsonschema:"Path to SSH identity file"`
}

type ExecuteInput struct {
	Command string `json:"command" jsonschema:"Shell command or pipeline to execute"`
	Host    string `json:"host,omitempty" jsonschema:"Hostname when multiple connections exist"`
}

type DisconnectInput struct {
	Host string `json:"host,omitempty" jsonschema:"Hostname to disconnect; empty disconnects all"`
}

type ProvisionInput struct {
	Host string `json:"host,omitempty" jsonschema:"Hostname to provision. Required when connected to multiple servers."`
}

type SleepInput struct {
	Seconds float64 `json:"seconds" jsonschema:"Duration to sleep in seconds"`
}

type DownloadInput struct {
	RemotePath string `json:"remote_path" jsonschema:"Absolute path to file on remote server"`
	LocalDir   string `json:"local_dir,omitempty" jsonschema:"Local directory to save to (default: /tmp/shellguard-downloads/)"`
	Host       string `json:"host,omitempty" jsonschema:"Hostname when multiple connections exist"`
}

type DownloadResult struct {
	LocalPath string `json:"local_path"`
	SizeBytes int64  `json:"size_bytes"`
	Filename  string `json:"filename"`
}

type CoreOption func(*Core)

func WithDefaultTimeout(seconds int) CoreOption {
	return func(c *Core) { c.DefaultTimeout = seconds }
}

func WithMaxOutputBytes(bytes int) CoreOption {
	return func(c *Core) { c.MaxOutputBytes = bytes }
}

func WithMaxDownloadBytes(bytes int) CoreOption {
	return func(c *Core) { c.MaxDownloadBytes = bytes }
}

func WithDownloadDir(dir string) CoreOption {
	return func(c *Core) { c.DownloadDir = dir }
}

func WithMaxSleepSeconds(seconds int) CoreOption {
	return func(c *Core) { c.MaxSleepSeconds = seconds }
}

func NewCore(registry map[string]*manifest.Manifest, runner Executor, logger *slog.Logger, opts ...CoreOption) *Core {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	c := &Core{
		Registry:         registry,
		Runner:           runner,
		logger:           logger,
		Parse:            parser.Parse,
		Validate:         validator.ValidatePipeline,
		Reconstruct:      ssh.ReconstructCommand,
		Truncate:         output.TruncateOutput,
		DefaultTimeout:   30,
		MaxOutputBytes:   output.DefaultMaxBytes,
		MaxDownloadBytes: maxDownloadBytes,
		DownloadDir:      defaultDownloadDir,
		MaxSleepSeconds:  15,
		probeState:       make(map[string]*ProbeResult),
		toolkitDeployed:  make(map[string]bool),
		connectedHosts:   make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Core) Connect(ctx context.Context, in ConnectInput) (map[string]any, error) {
	if strings.TrimSpace(in.Host) == "" {
		return nil, errors.New("host is required")
	}

	start := time.Now()

	params := ssh.ConnectionParams{
		Host:         in.Host,
		User:         in.User,
		Port:         in.Port,
		IdentityFile: in.IdentityFile,
	}
	if err := c.Runner.Connect(ctx, params); err != nil {
		c.logger.InfoContext(ctx, "connect",
			"host", in.Host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}
	c.setConnected(in.Host, true)
	c.setToolkitDeployed(in.Host, false)
	c.clearProbeState(in.Host)

	message := fmt.Sprintf("Connected to %s", in.Host)

	probeRes, err := c.Runner.ExecuteRaw(ctx, in.Host, toolkit.BuildProbeCommand(), 10*time.Second)
	if err == nil {
		missing, arch := toolkit.ParseProbeOutput(probeRes.Stdout)
		c.setProbeState(in.Host, &ProbeResult{Missing: missing, Arch: arch})
		if len(missing) > 0 {
			message += toolkit.FormatMissingToolsMessage(missing, arch)
		}
	}

	toolkitDirCheck, err := c.Runner.ExecuteRaw(ctx, in.Host, "test -d $HOME/.shellguard/bin && echo yes", 5*time.Second)
	if err == nil && strings.TrimSpace(toolkitDirCheck.Stdout) == "yes" {
		c.setToolkitDeployed(in.Host, true)
	}

	c.logger.InfoContext(ctx, "connect",
		"host", in.Host,
		"outcome", "success",
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return map[string]any{"ok": true, "host": in.Host, "message": message}, nil
}

func (c *Core) Execute(ctx context.Context, in ExecuteInput) (output.CommandResult, error) {
	if strings.TrimSpace(in.Command) == "" {
		return output.CommandResult{}, errors.New("command is required")
	}

	start := time.Now()

	pipeline, err := c.Parse(in.Command)
	if err != nil {
		c.logger.InfoContext(ctx, "execute",
			"command", in.Command,
			"host", in.Host,
			"outcome", "rejected",
			"stage", "parse",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return output.CommandResult{}, err
	}
	if err := c.Validate(pipeline, c.Registry); err != nil {
		c.logger.InfoContext(ctx, "execute",
			"command", in.Command,
			"host", in.Host,
			"outcome", "rejected",
			"stage", "validate",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return output.CommandResult{}, err
	}

	isPSQL := pipelineContainsPSQL(pipeline)
	hostForState := c.resolveHostForState(in.Host)
	reconstructed := c.Reconstruct(pipeline, isPSQL, c.isToolkitDeployed(hostForState))
	timeout := c.getPipelineTimeout(pipeline)

	execRes, err := c.Runner.Execute(ctx, in.Host, reconstructed, timeout)
	if err != nil {
		c.logger.InfoContext(ctx, "execute",
			"command", in.Command,
			"host", in.Host,
			"outcome", "error",
			"stage", "run",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return output.CommandResult{}, err
	}

	c.logger.InfoContext(ctx, "execute",
		"command", in.Command,
		"host", in.Host,
		"outcome", "success",
		"exit_code", execRes.ExitCode,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	truncated := c.Truncate(execRes.Stdout, execRes.Stderr, execRes.ExitCode, execRes.RuntimeMs, c.MaxOutputBytes)
	return truncated, nil
}

func (c *Core) Provision(ctx context.Context, in ProvisionInput) (map[string]any, error) {
	host, err := c.resolveProvisionHost(in.Host)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	probe, ok := c.getProbeState(host)
	if !ok || len(probe.Missing) == 0 {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "success",
			"detail", "nothing_missing",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return map[string]any{
			"ok":      true,
			"host":    host,
			"message": "All toolkit tools are already available. Nothing to deploy.",
		}, nil
	}

	if strings.TrimSpace(probe.Arch) == "" || probe.Arch == "unknown" {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "error",
			"error", "architecture unknown",
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, errors.New("cannot provision: architecture unknown")
	}

	sftpClient, err := c.Runner.SFTPSession(host)
	if err != nil {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}
	defer func() { _ = sftpClient.Close() }()

	message, err := toolkit.DeployTools(sftpClient, probe.Missing, probe.Arch)
	if err != nil {
		c.logger.InfoContext(ctx, "provision",
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return nil, err
	}

	c.setToolkitDeployed(host, true)
	c.clearProbeState(host)

	c.logger.InfoContext(ctx, "provision",
		"host", host,
		"outcome", "success",
		"tools_deployed", probe.Missing,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return map[string]any{
		"ok":      true,
		"host":    host,
		"message": message,
	}, nil
}

func (c *Core) Disconnect(in DisconnectInput) (map[string]any, error) {
	if err := c.Runner.Disconnect(in.Host); err != nil {
		c.logger.Info("disconnect",
			"host", in.Host,
			"outcome", "error",
			"error", err.Error(),
		)
		return nil, err
	}
	c.clearHostState(in.Host)

	c.logger.Info("disconnect",
		"host", in.Host,
		"outcome", "success",
	)

	return map[string]any{"ok": true}, nil
}

func (c *Core) DownloadFile(ctx context.Context, in DownloadInput) (DownloadResult, error) {
	if strings.TrimSpace(in.RemotePath) == "" {
		return DownloadResult{}, errors.New("remote_path is required")
	}

	host, err := c.resolveProvisionHost(in.Host)
	if err != nil {
		return DownloadResult{}, err
	}

	start := time.Now()

	sftpClient, err := c.Runner.SFTPSession(host)
	if err != nil {
		c.logger.InfoContext(ctx, "download",
			"remote_path", in.RemotePath,
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return DownloadResult{}, err
	}
	defer func() { _ = sftpClient.Close() }()

	info, err := sftpClient.Stat(in.RemotePath)
	if err != nil {
		c.logger.InfoContext(ctx, "download",
			"remote_path", in.RemotePath,
			"host", host,
			"outcome", "error",
			"error", err.Error(),
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return DownloadResult{}, fmt.Errorf("stat remote file %s: %w", in.RemotePath, err)
	}
	if info.IsDir() {
		return DownloadResult{}, fmt.Errorf("remote path is a directory: %s", in.RemotePath)
	}
	if info.Size() > int64(c.MaxDownloadBytes) {
		return DownloadResult{}, fmt.Errorf("file too large: %d bytes exceeds %d byte limit", info.Size(), c.MaxDownloadBytes)
	}

	localDir := strings.TrimSpace(in.LocalDir)
	if localDir == "" {
		localDir = c.DownloadDir
	}
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return DownloadResult{}, fmt.Errorf("create local directory %s: %w", localDir, err)
	}

	filename := filepath.Base(in.RemotePath)
	if filename == "." || filename == string(filepath.Separator) || filename == "" {
		return DownloadResult{}, fmt.Errorf("invalid remote filename: %s", in.RemotePath)
	}
	localPath, err := collisionSafePath(localDir, filename)
	if err != nil {
		return DownloadResult{}, err
	}

	src, err := sftpClient.Open(in.RemotePath)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("open remote file %s: %w", in.RemotePath, err)
	}
	defer func() { _ = src.Close() }()

	dst, err := os.Create(localPath)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create local file %s: %w", localPath, err)
	}

	copied, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		_ = os.Remove(localPath)
		return DownloadResult{}, fmt.Errorf("copy remote file %s to %s: %w", in.RemotePath, localPath, copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(localPath)
		return DownloadResult{}, fmt.Errorf("close local file %s: %w", localPath, closeErr)
	}

	c.logger.InfoContext(ctx, "download",
		"remote_path", in.RemotePath,
		"host", host,
		"outcome", "success",
		"size_bytes", copied,
		"local_path", localPath,
		"duration_ms", time.Since(start).Milliseconds(),
	)

	return DownloadResult{
		LocalPath: localPath,
		SizeBytes: copied,
		Filename:  filepath.Base(localPath),
	}, nil
}

func (c *Core) getPipelineTimeout(p *parser.Pipeline) time.Duration {
	maxSec := c.DefaultTimeout
	for _, seg := range p.Segments {
		m := c.Registry[seg.Command]
		if m != nil && m.Timeout > maxSec {
			maxSec = m.Timeout
		}
		if subcommandCommands[seg.Command] && len(seg.Args) > 0 {
			key := seg.Command + "_" + seg.Args[0]
			if seg.Command == "aws" && len(seg.Args) >= 2 {
				key = seg.Command + "_" + seg.Args[0] + "_" + seg.Args[1]
			}
			if sm := c.Registry[key]; sm != nil && sm.Timeout > maxSec {
				maxSec = sm.Timeout
			}
		}
	}
	return time.Duration(maxSec) * time.Second
}

var subcommandCommands = map[string]bool{
	"docker":    true,
	"kubectl":   true,
	"svn":       true,
	"systemctl": true,
	"aws":       true,
}

func pipelineContainsPSQL(p *parser.Pipeline) bool {
	for _, s := range p.Segments {
		if s.Command == "psql" {
			return true
		}
		if s.Command == "sudo" && len(s.Args) >= 3 && s.Args[0] == "-u" && s.Args[2] == "psql" {
			return true
		}
		if s.Command == "sudo" && len(s.Args) >= 1 && s.Args[0] == "psql" {
			return true
		}
	}
	return false
}

func (c *Core) resolveHostForState(host string) string {
	if host != "" {
		return host
	}
	hosts := c.connectedHostsSnapshot()
	if len(hosts) == 1 {
		return hosts[0]
	}
	return ""
}

func (c *Core) resolveProvisionHost(host string) (string, error) {
	if host != "" {
		if !c.isConnected(host) {
			return "", fmt.Errorf("not connected to host %q", host)
		}
		return host, nil
	}
	hosts := c.connectedHostsSnapshot()
	switch len(hosts) {
	case 0:
		return "", errors.New("not connected")
	case 1:
		return hosts[0], nil
	default:
		return "", errors.New("host is required when multiple connections are active")
	}
}

func (c *Core) connectedHostsSnapshot() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hosts := make([]string, 0, len(c.connectedHosts))
	for host := range c.connectedHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func (c *Core) isConnected(host string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.connectedHosts[host]
	return ok
}

func (c *Core) setConnected(host string, connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if connected {
		c.connectedHosts[host] = struct{}{}
		return
	}
	delete(c.connectedHosts, host)
}

func (c *Core) setProbeState(host string, result *ProbeResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if result == nil {
		delete(c.probeState, host)
		return
	}
	cloned := &ProbeResult{
		Missing: append([]string(nil), result.Missing...),
		Arch:    result.Arch,
	}
	c.probeState[host] = cloned
}

func (c *Core) getProbeState(host string) (*ProbeResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, ok := c.probeState[host]
	if !ok || result == nil {
		return nil, false
	}
	return &ProbeResult{
		Missing: append([]string(nil), result.Missing...),
		Arch:    result.Arch,
	}, true
}

func (c *Core) clearProbeState(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.probeState, host)
}

func (c *Core) setToolkitDeployed(host string, deployed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.toolkitDeployed[host] = deployed
}

func (c *Core) isToolkitDeployed(host string) bool {
	if host == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.toolkitDeployed[host]
}

func (c *Core) clearHostState(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if host == "" {
		clear(c.connectedHosts)
		clear(c.probeState)
		clear(c.toolkitDeployed)
		return
	}
	delete(c.connectedHosts, host)
	delete(c.probeState, host)
	delete(c.toolkitDeployed, host)
}

func collisionSafePath(dir, filename string) (string, error) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	ext := filepath.Ext(filename)
	candidate := filepath.Join(dir, filename)

	if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
		return candidate, nil
	} else if err != nil {
		return "", fmt.Errorf("stat local path %s: %w", candidate, err)
	}

	for i := 1; ; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s_%d%s", base, i, ext))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		} else if err != nil {
			return "", fmt.Errorf("stat local path %s: %w", candidate, err)
		}
	}
}

func (c *Core) Sleep(ctx context.Context, in SleepInput) (map[string]any, error) {
	if in.Seconds <= 0 {
		return nil, errors.New("seconds must be greater than 0")
	}
	if in.Seconds > float64(c.MaxSleepSeconds) {
		return nil, fmt.Errorf("seconds must not exceed %d", c.MaxSleepSeconds)
	}
	d := time.Duration(in.Seconds * float64(time.Second))
	select {
	case <-time.After(d):
		return map[string]any{"ok": true, "slept_seconds": in.Seconds}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type ServerOptions struct {
	// Name is the MCP server implementation name. Default: "shellguard".
	Name string
	// Version is the MCP server implementation version. Default: "0.1.0".
	Version string
}

func NewMCPServer(core *Core, logger *slog.Logger, opts ...ServerOptions) *mcp.Server {
	name := "shellguard"
	version := "0.1.0"
	if len(opts) > 0 {
		if opts[0].Name != "" {
			name = opts[0].Name
		}
		if opts[0].Version != "" {
			version = opts[0].Version
		}
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, &mcp.ServerOptions{Logger: logger})

	mcp.AddTool(srv, &mcp.Tool{Name: "connect", Description: "Connect to a remote server via SSH"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in ConnectInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := core.Connect(ctx, in)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "execute",
		Description: fmt.Sprintf("Execute a shell command on the connected remote server. "+
			"Commands are validated against a security allowlist before execution. "+
			"Denied commands return the reason and often suggest alternatives. "+
			"Supported shell syntax: simple commands, pipes (|), and conditional chaining (&& ||). "+
			"Semicolons, redirections, variable expansion, command substitution, and subshells are not allowed. "+
			"Output is truncated to %d bytes (head/tail preserved) for large results.", core.MaxOutputBytes),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: true,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ExecuteInput) (*mcp.CallToolResult, output.CommandResult, error) {
		out, err := core.Execute(ctx, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{Name: "disconnect", Description: "Disconnect from remote server(s)"},
		func(_ context.Context, _ *mcp.CallToolRequest, in DisconnectInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := core.Disconnect(in)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{Name: "sleep", Description: fmt.Sprintf("Sleep locally for a specified duration (max %d seconds). Use to wait between checks, e.g. after observing an issue and before re-checking.", core.MaxSleepSeconds)},
		func(ctx context.Context, _ *mcp.CallToolRequest, in SleepInput) (*mcp.CallToolResult, map[string]any, error) {
			out, err := core.Sleep(ctx, in)
			return nil, out, err
		})

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "provision",
		Description: "Deploy missing diagnostic tools (rg, jq, yq) to ~/.shellguard/bin/ on the remote server. Uses SFTP over the existing SSH connection -- no outbound internet required on the remote. This is a WRITE operation: ask the operator for approval before calling this tool.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:   false,
			IdempotentHint: true,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ProvisionInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := core.Provision(ctx, in)
		return nil, out, err
	})

	mcp.AddTool(srv, &mcp.Tool{
		Name: "download_file",
		Description: fmt.Sprintf("Download a file from the remote server to the local filesystem via SFTP. "+
			"Returns the local path so you can process the file with local tools. "+
			"Maximum file size: %d bytes. Files are saved to %s by default. "+
			"This is a WRITE operation on the local machine: ask the operator for approval before calling this tool.",
			core.MaxDownloadBytes, core.DownloadDir),
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint: false,
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in DownloadInput) (*mcp.CallToolResult, DownloadResult, error) {
		out, err := core.DownloadFile(ctx, in)
		return nil, out, err
	})

	return srv
}

func RunStdio(ctx context.Context, core *Core, logger *slog.Logger, opts ...ServerOptions) error {
	server := NewMCPServer(core, logger, opts...)
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("run mcp stdio server: %w", err)
	}
	return nil
}

// NewHTTPHandler returns an http.Handler serving MCP over SSE.
func NewHTTPHandler(core *Core, logger *slog.Logger, opts ...ServerOptions) http.Handler {
	srv := NewMCPServer(core, logger, opts...)
	return mcp.NewSSEHandler(func(_ *http.Request) *mcp.Server {
		return srv
	}, nil)
}
