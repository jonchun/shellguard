// Package ssh manages connections, command execution, and SFTP transfers.
package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

type ExecResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	RuntimeMs int
}

type SFTPClient interface {
	Stat(path string) (os.FileInfo, error)
	Open(path string) (io.ReadCloser, error)
	Create(path string) (io.WriteCloser, error)
	MkdirAll(path string) error
	Chmod(path string, mode os.FileMode) error
	Close() error
}

type Client interface {
	Execute(ctx context.Context, command string, timeout time.Duration) (ExecResult, error)
	SFTPSession() (SFTPClient, error)
	Close() error
}

type Dialer interface {
	Dial(ctx context.Context, params ConnectionParams) (Client, error)
}

type ConnectionParams struct {
	Host         string
	User         string
	Port         int
	IdentityFile string
}

type ManagedConnection struct {
	Client Client
	Params ConnectionParams
}

type SSHManager struct {
	mu          sync.Mutex
	dialer      Dialer
	connections map[string]*ManagedConnection
	retries     int
	backoff     time.Duration
}

type Option func(*SSHManager)

func WithRetries(retries int) Option {
	return func(m *SSHManager) {
		if retries >= 0 {
			m.retries = retries
		}
	}
}

func WithConnectTimeout(timeout time.Duration) Option {
	return func(m *SSHManager) {
		if d, ok := m.dialer.(*XCryptoDialer); ok {
			d.ConnectTimeout = timeout
		}
	}
}

func WithRetryBackoff(backoff time.Duration) Option {
	return func(m *SSHManager) {
		if backoff > 0 {
			m.backoff = backoff
		}
	}
}

func NewSSHManager(dialer Dialer, opts ...Option) *SSHManager {
	if dialer == nil {
		dialer = &XCryptoDialer{}
	}
	m := &SSHManager{
		dialer:      dialer,
		connections: make(map[string]*ManagedConnection),
		retries:     2,
		backoff:     250 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *SSHManager) Connected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.connections) > 0
}

func (m *SSHManager) Connect(ctx context.Context, params ConnectionParams) error {
	params = withDefaults(params)
	if params.Host == "" {
		return errors.New("host is required")
	}

	var lastErr error
	for attempt := 0; attempt <= m.retries; attempt++ {
		client, err := m.dialer.Dial(ctx, params)
		if err == nil {
			m.mu.Lock()
			m.connections[params.Host] = &ManagedConnection{Client: client, Params: params}
			m.mu.Unlock()
			return nil
		}
		lastErr = err

		if !isRetriable(err) || attempt == m.retries {
			break
		}
		if sleepErr := sleepWithContext(ctx, m.backoff*time.Duration(1<<attempt)); sleepErr != nil {
			return sleepErr
		}
	}

	return fmt.Errorf("connect %s:%d failed: %w", params.Host, params.Port, lastErr)
}

func (m *SSHManager) ResolveConnection(host string) (*ManagedConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if host != "" {
		conn := m.connections[host]
		if conn == nil {
			return nil, fmt.Errorf("not connected to host %q", host)
		}
		return conn, nil
	}

	if len(m.connections) == 0 {
		return nil, errors.New("not connected")
	}
	if len(m.connections) > 1 {
		return nil, errors.New("host is required when multiple connections are active")
	}
	for _, conn := range m.connections {
		return conn, nil
	}
	return nil, errors.New("not connected")
}

func (m *SSHManager) Execute(ctx context.Context, host, command string, timeout time.Duration) (ExecResult, error) {
	conn, err := m.ResolveConnection(host)
	if err != nil {
		return ExecResult{}, err
	}

	var lastErr error
	for attempt := 0; attempt <= m.retries; attempt++ {
		res, err := conn.Client.Execute(ctx, command, timeout)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !isRetriable(err) || attempt == m.retries {
			break
		}
		if sleepErr := sleepWithContext(ctx, m.backoff*time.Duration(1<<attempt)); sleepErr != nil {
			return ExecResult{}, sleepErr
		}
	}

	return ExecResult{}, fmt.Errorf("execute failed: %w", lastErr)
}

func (m *SSHManager) ExecuteRaw(ctx context.Context, host, command string, timeout time.Duration) (ExecResult, error) {
	conn, err := m.ResolveConnection(host)
	if err != nil {
		return ExecResult{}, err
	}

	res, err := conn.Client.Execute(ctx, command, timeout)
	if err != nil {
		return ExecResult{}, fmt.Errorf("execute raw failed: %w", err)
	}
	return res, nil
}

func (m *SSHManager) SFTPSession(host string) (SFTPClient, error) {
	conn, err := m.ResolveConnection(host)
	if err != nil {
		return nil, err
	}
	client, err := conn.Client.SFTPSession()
	if err != nil {
		return nil, fmt.Errorf("sftp session failed: %w", err)
	}
	return client, nil
}

func (m *SSHManager) Disconnect(host string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if host == "" {
		for h, conn := range m.connections {
			if conn != nil && conn.Client != nil {
				_ = conn.Client.Close()
			}
			delete(m.connections, h)
		}
		return nil
	}

	conn := m.connections[host]
	if conn == nil {
		return nil
	}
	if conn.Client != nil {
		_ = conn.Client.Close()
	}
	delete(m.connections, host)
	return nil
}

func withDefaults(params ConnectionParams) ConnectionParams {
	if params.User == "" {
		params.User = "root"
	}
	if params.Port == 0 {
		params.Port = 22
	}
	return params
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isRetriable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range []string{"connection reset", "broken pipe", "timeout", "temporarily unavailable", "eof"} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

type XCryptoDialer struct {
	ConnectTimeout time.Duration
}

func (d *XCryptoDialer) connectTimeout() time.Duration {
	if d.ConnectTimeout > 0 {
		return d.ConnectTimeout
	}
	return 10 * time.Second
}

func (d *XCryptoDialer) Dial(ctx context.Context, params ConnectionParams) (Client, error) {
	params = withDefaults(params)

	authMethods, authCleanup := buildAuthMethods(params.IdentityFile)
	defer authCleanup()

	cfg := &gossh.ClientConfig{
		User:            params.User,
		Auth:            authMethods,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         d.connectTimeout(),
	}

	addr := fmt.Sprintf("%s:%d", params.Host, params.Port)
	var netDialer net.Dialer
	conn, err := netDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := gossh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &xcryptoClient{client: gossh.NewClient(c, chans, reqs)}, nil
}

type xcryptoClient struct {
	client *gossh.Client
}

type sftpClientAdapter struct {
	client *sftp.Client
}

func (a *sftpClientAdapter) Stat(path string) (os.FileInfo, error) {
	return a.client.Stat(path)
}

func (a *sftpClientAdapter) Open(path string) (io.ReadCloser, error) {
	return a.client.Open(path)
}

func (a *sftpClientAdapter) Create(path string) (io.WriteCloser, error) {
	return a.client.Create(path)
}

func (a *sftpClientAdapter) MkdirAll(path string) error {
	return a.client.MkdirAll(path)
}

func (a *sftpClientAdapter) Chmod(path string, mode os.FileMode) error {
	return a.client.Chmod(path, mode)
}

func (a *sftpClientAdapter) Close() error {
	return a.client.Close()
}

func (c *xcryptoClient) Execute(ctx context.Context, command string, timeout time.Duration) (ExecResult, error) {
	session, err := c.client.NewSession()
	if err != nil {
		return ExecResult{}, err
	}
	defer func() { _ = session.Close() }()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	execCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	started := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case <-execCtx.Done():
		_ = session.Close()
		return ExecResult{}, execCtx.Err()
	case err := <-done:
		runtime := int(time.Since(started).Milliseconds())
		if err == nil {
			return ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: 0, RuntimeMs: runtime}, nil
		}
		if exitErr, ok := err.(*gossh.ExitError); ok {
			return ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitErr.ExitStatus(), RuntimeMs: runtime}, nil
		}
		return ExecResult{}, err
	}
}

func (c *xcryptoClient) Close() error {
	return c.client.Close()
}

func (c *xcryptoClient) SFTPSession() (SFTPClient, error) {
	client, err := sftp.NewClient(c.client)
	if err != nil {
		return nil, err
	}
	return &sftpClientAdapter{client: client}, nil
}
