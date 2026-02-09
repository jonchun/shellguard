package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type mockDialer struct {
	mu     sync.Mutex
	errs   []error
	client Client
	calls  int
	params []ConnectionParams
}

func (m *mockDialer) Dial(_ context.Context, params ConnectionParams) (Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	m.params = append(m.params, params)
	if len(m.errs) > 0 {
		err := m.errs[0]
		m.errs = m.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	return m.client, nil
}

type mockClient struct {
	mu          sync.Mutex
	execErrs    []error
	execResults []ExecResult
	execCalls   int
	sftpClient  SFTPClient
	sftpErr     error
	sftpCalls   int
	closed      bool
}

func (m *mockClient) Execute(ctx context.Context, _ string, _ time.Duration) (ExecResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.execCalls++
	if len(m.execErrs) > 0 {
		err := m.execErrs[0]
		m.execErrs = m.execErrs[1:]
		if err != nil {
			return ExecResult{}, err
		}
	}
	if len(m.execResults) > 0 {
		res := m.execResults[0]
		m.execResults = m.execResults[1:]
		return res, nil
	}
	return ExecResult{}, ctx.Err()
}

func (m *mockClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockClient) SFTPSession() (SFTPClient, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sftpCalls++
	if m.sftpErr != nil {
		return nil, m.sftpErr
	}
	return m.sftpClient, nil
}

func TestConnectStoresConnection(t *testing.T) {
	c := &mockClient{}
	d := &mockDialer{client: c}
	m := NewSSHManager(d)

	if err := m.Connect(context.Background(), ConnectionParams{Host: "host1"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if !m.Connected() {
		t.Fatal("expected manager to be connected")
	}
}

func TestConnectRetriesOnFailure(t *testing.T) {
	c := &mockClient{}
	d := &mockDialer{client: c, errs: []error{errors.New("connection reset"), nil}}
	m := NewSSHManager(d, WithRetries(2), WithRetryBackoff(1*time.Millisecond))

	if err := m.Connect(context.Background(), ConnectionParams{Host: "host2"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if d.calls != 2 {
		t.Fatalf("Dial calls = %d, want 2", d.calls)
	}
}

func TestExecuteRetriesTransientError(t *testing.T) {
	c := &mockClient{execErrs: []error{errors.New("broken pipe")}, execResults: []ExecResult{{Stdout: "ok", ExitCode: 0}}}
	d := &mockDialer{client: c}
	m := NewSSHManager(d, WithRetries(2), WithRetryBackoff(1*time.Millisecond))
	if err := m.Connect(context.Background(), ConnectionParams{Host: "host3"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	res, err := m.Execute(context.Background(), "host3", "ls", 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if res.Stdout != "ok" {
		t.Fatalf("Stdout = %q, want ok", res.Stdout)
	}
	if c.execCalls != 2 {
		t.Fatalf("Execute calls = %d, want 2", c.execCalls)
	}
}

func TestExecuteNotConnected(t *testing.T) {
	m := NewSSHManager(&mockDialer{client: &mockClient{}})
	if _, err := m.Execute(context.Background(), "", "ls", time.Second); err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestExecuteHostResolutionSingleConnection(t *testing.T) {
	c := &mockClient{execResults: []ExecResult{{Stdout: "ok", ExitCode: 0}}}
	d := &mockDialer{client: c}
	m := NewSSHManager(d)
	if err := m.Connect(context.Background(), ConnectionParams{Host: "only"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if _, err := m.Execute(context.Background(), "", "ls", time.Second); err != nil {
		t.Fatalf("Execute() with implicit host error = %v", err)
	}
}

func TestExecuteHostResolutionRequiresHostWhenMultiple(t *testing.T) {
	d := &mockDialer{client: &mockClient{execResults: []ExecResult{{Stdout: "ok"}}}}
	m := NewSSHManager(d)
	_ = m.Connect(context.Background(), ConnectionParams{Host: "h1"})
	_ = m.Connect(context.Background(), ConnectionParams{Host: "h2"})
	if _, err := m.Execute(context.Background(), "", "ls", time.Second); err == nil {
		t.Fatal("expected explicit host error")
	}
}

func TestDisconnectOneAndAll(t *testing.T) {
	c1 := &mockClient{}
	c2 := &mockClient{}
	m := NewSSHManager(&mockDialer{client: c1})
	if err := m.Connect(context.Background(), ConnectionParams{Host: "h1"}); err != nil {
		t.Fatalf("Connect(h1) error = %v", err)
	}
	m.dialer = &mockDialer{client: c2}
	if err := m.Connect(context.Background(), ConnectionParams{Host: "h2"}); err != nil {
		t.Fatalf("Connect(h2) error = %v", err)
	}

	if err := m.Disconnect(context.Background(), "h1"); err != nil {
		t.Fatalf("Disconnect(h1) error = %v", err)
	}
	if !c1.closed {
		t.Fatal("expected h1 client closed")
	}

	if err := m.Disconnect(context.Background(), ""); err != nil {
		t.Fatalf("Disconnect(all) error = %v", err)
	}
	if !c2.closed {
		t.Fatal("expected h2 client closed")
	}
}

func TestSFTPSessionReturnsClient(t *testing.T) {
	c := &mockClient{sftpClient: &mockSFTPClient{}}
	d := &mockDialer{client: c}
	m := NewSSHManager(d)
	if err := m.Connect(context.Background(), ConnectionParams{Host: "host4"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	sftpClient, err := m.SFTPSession("host4")
	if err != nil {
		t.Fatalf("SFTPSession() error = %v", err)
	}
	if sftpClient == nil {
		t.Fatal("expected non-nil sftp client")
	}
	if c.sftpCalls != 1 {
		t.Fatalf("SFTPSession calls = %d, want 1", c.sftpCalls)
	}
}

func TestExecuteRawSingleAttemptNoRetry(t *testing.T) {
	c := &mockClient{execErrs: []error{errors.New("broken pipe"), nil}}
	d := &mockDialer{client: c}
	m := NewSSHManager(d, WithRetries(2), WithRetryBackoff(1*time.Millisecond))
	if err := m.Connect(context.Background(), ConnectionParams{Host: "host5"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	_, err := m.ExecuteRaw(context.Background(), "host5", "ls", time.Second)
	if err == nil {
		t.Fatal("expected ExecuteRaw() error")
	}
	if c.execCalls != 1 {
		t.Fatalf("ExecuteRaw calls = %d, want 1", c.execCalls)
	}
}

func TestExecuteRawNotConnected(t *testing.T) {
	m := NewSSHManager(&mockDialer{client: &mockClient{}})
	if _, err := m.ExecuteRaw(context.Background(), "", "ls", time.Second); err == nil {
		t.Fatal("expected error when not connected")
	}
}

type mockSFTPClient struct{}

func (m *mockSFTPClient) Stat(_ string) (os.FileInfo, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSFTPClient) Open(_ string) (io.ReadCloser, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSFTPClient) Create(_ string) (io.WriteCloser, error) {
	return nil, errors.New("not implemented")
}

func (m *mockSFTPClient) MkdirAll(_ string) error {
	return nil
}

func (m *mockSFTPClient) Chmod(_ string, _ os.FileMode) error {
	return nil
}

func (m *mockSFTPClient) Close() error {
	return nil
}

func TestXCryptoDialer_DefaultTimeout(t *testing.T) {
	d := &XCryptoDialer{}
	if got, want := d.connectTimeout(), 10*time.Second; got != want {
		t.Fatalf("connectTimeout() = %v, want %v", got, want)
	}
}

func TestXCryptoDialer_CustomTimeout(t *testing.T) {
	d := &XCryptoDialer{ConnectTimeout: 20 * time.Second}
	if got, want := d.connectTimeout(), 20*time.Second; got != want {
		t.Fatalf("connectTimeout() = %v, want %v", got, want)
	}
}

func TestWithConnectTimeout(t *testing.T) {
	m := NewSSHManager(nil, WithConnectTimeout(25*time.Second))
	d, ok := m.dialer.(*XCryptoDialer)
	if !ok {
		t.Fatal("expected default dialer to be *XCryptoDialer")
	}
	if got, want := d.ConnectTimeout, 25*time.Second; got != want {
		t.Fatalf("ConnectTimeout = %v, want %v", got, want)
	}
}
