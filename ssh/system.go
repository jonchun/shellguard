package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

const (
	defaultControlDir     = "/tmp/shellguard-ctl"
	controlPersistSeconds = 30
)

// SystemSSHDialer implements Dialer by spawning the system ssh binary.
// It uses ControlMaster for connection multiplexing so that only the
// first Dial pays the SSH handshake cost; subsequent Execute calls
// reuse the existing control socket.
type SystemSSHDialer struct {
	// ControlDir is the directory for ControlMaster sockets.
	// Defaults to /tmp/shellguard-ctl.
	ControlDir string

	// sshBinary is the resolved path to the ssh binary.
	// Set lazily by Dial; exported only for testing.
	sshBinary string
}

// CheckBinary returns true if ssh is available in PATH.
func (d *SystemSSHDialer) CheckBinary() bool {
	p, err := exec.LookPath("ssh")
	if err != nil {
		return false
	}
	d.sshBinary = p
	return true
}

func (d *SystemSSHDialer) controlDir() string {
	if d.ControlDir != "" {
		return d.ControlDir
	}
	return defaultControlDir
}

func (d *SystemSSHDialer) controlPath() string {
	return filepath.Join(d.controlDir(), "%C")
}

func (d *SystemSSHDialer) ssh() string {
	if d.sshBinary != "" {
		return d.sshBinary
	}
	return "ssh"
}

// Dial establishes a ControlMaster connection by spawning a background
// ssh process. The process exits after ControlPersist seconds of idle.
func (d *SystemSSHDialer) Dial(ctx context.Context, params ConnectionParams) (Client, error) {
	params = withDefaults(params)

	if err := os.MkdirAll(d.controlDir(), 0o700); err != nil {
		return nil, fmt.Errorf("create control dir: %w", err)
	}

	target := fmt.Sprintf("%s@%s", params.User, params.Host)
	ctlPath := d.controlPath()

	args := []string{
		"-o", "ControlMaster=yes",
		"-o", "ControlPath=" + ctlPath,
		"-o", fmt.Sprintf("ControlPersist=%d", controlPersistSeconds),
		"-o", "BatchMode=yes",
		"-p", strconv.Itoa(params.Port),
		"-N",
	}
	if params.IdentityFile != "" {
		args = append(args, "-i", params.IdentityFile)
	}
	args = append(args, target)

	cmd := exec.CommandContext(ctx, d.ssh(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("ssh connect: %s", msg)
		}
		return nil, fmt.Errorf("ssh connect: %w", err)
	}

	return &systemSSHClient{
		sshBinary:   d.ssh(),
		controlPath: ctlPath,
		target:      target,
		port:        params.Port,
	}, nil
}

type systemSSHClient struct {
	sshBinary   string
	controlPath string
	target      string
	port        int
}

func (c *systemSSHClient) baseArgs() []string {
	return []string{
		"-o", "ControlPath=" + c.controlPath,
		"-o", "BatchMode=yes",
		"-p", strconv.Itoa(c.port),
	}
}

func (c *systemSSHClient) Execute(ctx context.Context, command string, timeout time.Duration) (ExecResult, error) {
	execCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	args := c.baseArgs()
	args = append(args, c.target, command)

	cmd := exec.CommandContext(execCtx, c.sshBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	started := time.Now()
	err := cmd.Run()
	runtime := int(time.Since(started).Milliseconds())

	if err == nil {
		return ExecResult{
			Stdout:    stdout.String(),
			Stderr:    stderr.String(),
			ExitCode:  0,
			RuntimeMs: runtime,
		}, nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		return ExecResult{
			Stdout:    stdout.String(),
			Stderr:    stderr.String(),
			ExitCode:  exitErr.ExitCode(),
			RuntimeMs: runtime,
		}, nil
	}

	return ExecResult{}, err
}

func (c *systemSSHClient) SFTPSession() (SFTPClient, error) {
	args := c.baseArgs()
	args = append(args, "-s", c.target, "sftp")

	cmd := exec.Command(c.sshBinary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("sftp stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("sftp stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sftp start: %w", err)
	}

	client, err := sftp.NewClientPipe(stdout, stdin)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("sftp client: %w", err)
	}

	return &systemSFTPClient{client: client, cmd: cmd}, nil
}

func (c *systemSSHClient) Close() error {
	args := c.baseArgs()
	args = append(args, "-O", "exit", c.target)

	cmd := exec.Command(c.sshBinary, args...)
	_ = cmd.Run()
	return nil
}

// systemSFTPClient wraps an sftp.Client backed by a subprocess.
type systemSFTPClient struct {
	client *sftp.Client
	cmd    *exec.Cmd
}

func (c *systemSFTPClient) Stat(path string) (os.FileInfo, error)      { return c.client.Stat(path) }
func (c *systemSFTPClient) Open(path string) (io.ReadCloser, error)    { return c.client.Open(path) }
func (c *systemSFTPClient) Create(path string) (io.WriteCloser, error) { return c.client.Create(path) }
func (c *systemSFTPClient) MkdirAll(path string) error                 { return c.client.MkdirAll(path) }
func (c *systemSFTPClient) Chmod(path string, mode os.FileMode) error {
	return c.client.Chmod(path, mode)
}

func (c *systemSFTPClient) Close() error {
	err := c.client.Close()
	_ = c.cmd.Wait()
	return err
}
