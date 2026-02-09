package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func tempSSHConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp ssh config: %v", err)
	}
	return path
}

func TestResolveHostAlias(t *testing.T) {
	path := tempSSHConfig(t, `
Host prod
    HostName 10.0.0.1
    User deploy
    Port 2222
`)
	r := newResolver(path)
	rc := r.resolve("prod")

	if got, want := rc.HostName, "10.0.0.1"; got != want {
		t.Fatalf("HostName = %q, want %q", got, want)
	}
	if got, want := rc.User, "deploy"; got != want {
		t.Fatalf("User = %q, want %q", got, want)
	}
	if got, want := rc.Port, 2222; got != want {
		t.Fatalf("Port = %d, want %d", got, want)
	}
}

func TestResolveWildcardPattern(t *testing.T) {
	path := tempSSHConfig(t, `
Host *.example.com
    User admin
    Port 2200
`)
	r := newResolver(path)
	rc := r.resolve("web.example.com")

	if got, want := rc.User, "admin"; got != want {
		t.Fatalf("User = %q, want %q", got, want)
	}
	if got, want := rc.Port, 2200; got != want {
		t.Fatalf("Port = %d, want %d", got, want)
	}
}

func TestResolveMultipleIdentityFiles(t *testing.T) {
	path := tempSSHConfig(t, `
Host multi
    HostName 10.0.0.5
    IdentityFile /keys/first.pem
    IdentityFile /keys/second.pem
`)
	r := newResolver(path)
	rc := r.resolve("multi")

	if got, want := len(rc.IdentityFiles), 2; got != want {
		t.Fatalf("len(IdentityFiles) = %d, want %d", got, want)
	}
	if got, want := rc.IdentityFiles[0], "/keys/first.pem"; got != want {
		t.Fatalf("IdentityFiles[0] = %q, want %q", got, want)
	}
	if got, want := rc.IdentityFiles[1], "/keys/second.pem"; got != want {
		t.Fatalf("IdentityFiles[1] = %q, want %q", got, want)
	}
}

func TestResolveTildeExpansion(t *testing.T) {
	path := tempSSHConfig(t, `
Host tilde
    HostName 10.0.0.6
    IdentityFile ~/.ssh/custom_key
`)
	r := newResolver(path)
	rc := r.resolve("tilde")

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir() error = %v", err)
	}
	want := filepath.Join(home, ".ssh", "custom_key")
	if got := rc.IdentityFiles[0]; got != want {
		t.Fatalf("IdentityFiles[0] = %q, want %q", got, want)
	}
}

func TestResolveNonMatchingHost(t *testing.T) {
	path := tempSSHConfig(t, `
Host prod
    HostName 10.0.0.1
    User deploy
    Port 2222
`)
	r := newResolver(path)
	rc := r.resolve("staging")

	if rc.HostName != "" {
		t.Fatalf("HostName = %q, want empty", rc.HostName)
	}
	if rc.User != "" {
		t.Fatalf("User = %q, want empty", rc.User)
	}
	if rc.Port != 0 {
		t.Fatalf("Port = %d, want 0", rc.Port)
	}
	if len(rc.IdentityFiles) != 0 {
		t.Fatalf("len(IdentityFiles) = %d, want 0", len(rc.IdentityFiles))
	}
}

func TestResolveMissingConfigFile(t *testing.T) {
	r := newResolver("/nonexistent/path/config")
	rc := r.resolve("anything")

	if rc.HostName != "" {
		t.Fatalf("HostName = %q, want empty", rc.HostName)
	}
	if rc.User != "" {
		t.Fatalf("User = %q, want empty", rc.User)
	}
	if rc.Port != 0 {
		t.Fatalf("Port = %d, want 0", rc.Port)
	}
	if len(rc.IdentityFiles) != 0 {
		t.Fatalf("len(IdentityFiles) = %d, want 0", len(rc.IdentityFiles))
	}
}

func TestResolvePartialConfig(t *testing.T) {
	path := tempSSHConfig(t, `
Host partial
    User admin
`)
	r := newResolver(path)
	rc := r.resolve("partial")

	if rc.HostName != "" {
		t.Fatalf("HostName = %q, want empty", rc.HostName)
	}
	if got, want := rc.User, "admin"; got != want {
		t.Fatalf("User = %q, want %q", got, want)
	}
	if rc.Port != 0 {
		t.Fatalf("Port = %d, want 0", rc.Port)
	}
}

func TestResolveInvalidPort(t *testing.T) {
	path := tempSSHConfig(t, `
Host badport
    Port notanumber
`)
	r := newResolver(path)
	rc := r.resolve("badport")

	if rc.Port != 0 {
		t.Fatalf("Port = %d, want 0", rc.Port)
	}
}

func TestResolveUnparseableConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	// Write binary garbage that can't be parsed as SSH config.
	if err := os.WriteFile(path, []byte{0x00, 0x01, 0x02}, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	r := newResolver(path)
	rc := r.resolve("anything")

	if rc.HostName != "" {
		t.Fatalf("HostName = %q, want empty", rc.HostName)
	}
}

func TestApplySSHConfigExplicitParamsOverride(t *testing.T) {
	path := tempSSHConfig(t, `
Host prod
    HostName 10.0.0.1
    User deploy
    Port 2222
    IdentityFile /keys/config.pem
`)
	r := newResolver(path)
	fn := func(params ConnectionParams) ConnectionParams {
		return applyResolved(params, r)
	}

	params := ConnectionParams{
		Host:         "prod",
		User:         "myuser",
		Port:         9999,
		IdentityFile: "/my/key.pem",
	}
	result := fn(params)

	// HostName always overrides (alias resolution)
	if got, want := result.Host, "10.0.0.1"; got != want {
		t.Fatalf("Host = %q, want %q", got, want)
	}
	// Explicit user should NOT be overridden
	if got, want := result.User, "myuser"; got != want {
		t.Fatalf("User = %q, want %q", got, want)
	}
	// Explicit port should NOT be overridden
	if got, want := result.Port, 9999; got != want {
		t.Fatalf("Port = %d, want %d", got, want)
	}
	// Explicit identity file should NOT be overridden
	if got, want := result.IdentityFile, "/my/key.pem"; got != want {
		t.Fatalf("IdentityFile = %q, want %q", got, want)
	}
}

func TestApplySSHConfigFillsEmptyFields(t *testing.T) {
	path := tempSSHConfig(t, `
Host staging
    HostName 10.0.0.2
    User deploy
    Port 2222
    IdentityFile /keys/staging.pem
`)
	r := newResolver(path)
	fn := func(params ConnectionParams) ConnectionParams {
		return applyResolved(params, r)
	}

	params := ConnectionParams{Host: "staging"}
	result := fn(params)

	if got, want := result.Host, "10.0.0.2"; got != want {
		t.Fatalf("Host = %q, want %q", got, want)
	}
	if got, want := result.User, "deploy"; got != want {
		t.Fatalf("User = %q, want %q", got, want)
	}
	if got, want := result.Port, 2222; got != want {
		t.Fatalf("Port = %d, want %d", got, want)
	}
	if got, want := result.IdentityFile, "/keys/staging.pem"; got != want {
		t.Fatalf("IdentityFile = %q, want %q", got, want)
	}
}

func TestApplySSHConfigNoMatch(t *testing.T) {
	path := tempSSHConfig(t, `
Host prod
    HostName 10.0.0.1
`)
	r := newResolver(path)
	fn := func(params ConnectionParams) ConnectionParams {
		return applyResolved(params, r)
	}

	params := ConnectionParams{Host: "unknown-host"}
	result := fn(params)

	if got, want := result.Host, "unknown-host"; got != want {
		t.Fatalf("Host = %q, want %q", got, want)
	}
	if result.User != "" {
		t.Fatalf("User = %q, want empty", result.User)
	}
	if result.Port != 0 {
		t.Fatalf("Port = %d, want 0", result.Port)
	}
}

func TestConnectUsesSSHConfigResolution(t *testing.T) {
	path := tempSSHConfig(t, `
Host myalias
    HostName 10.0.0.99
    User admin
    Port 2222
`)
	r := newResolver(path)

	c := &mockClient{}
	d := &mockDialer{client: c}
	m := NewSSHManager(d)
	m.resolveConfig = func(params ConnectionParams) ConnectionParams {
		return applyResolved(params, r)
	}

	if err := m.Connect(t.Context(), ConnectionParams{Host: "myalias"}); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	if got, want := len(d.params), 1; got != want {
		t.Fatalf("Dial calls = %d, want %d", got, want)
	}
	dialed := d.params[0]
	if got, want := dialed.Host, "10.0.0.99"; got != want {
		t.Fatalf("dialed Host = %q, want %q", got, want)
	}
	if got, want := dialed.User, "admin"; got != want {
		t.Fatalf("dialed User = %q, want %q", got, want)
	}
	if got, want := dialed.Port, 2222; got != want {
		t.Fatalf("dialed Port = %d, want %d", got, want)
	}
}
