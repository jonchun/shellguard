package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDurationUnmarshalYAML_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{`"10s"`, 10 * time.Second},
		{`"500ms"`, 500 * time.Millisecond},
		{`"2m"`, 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var d duration
			if err := yaml.Unmarshal([]byte(tt.input), &d); err != nil {
				t.Fatalf("Unmarshal(%s) error = %v", tt.input, err)
			}
			if got, want := d.Duration(), tt.want; got != want {
				t.Fatalf("Duration() = %v, want %v", got, want)
			}
		})
	}
}

func TestDurationUnmarshalYAML_Invalid(t *testing.T) {
	var d duration
	err := yaml.Unmarshal([]byte(`"notaduration"`), &d)
	if err == nil {
		t.Fatal("Unmarshal(notaduration) expected error, got nil")
	}
}

func TestConfigStructPointerFields(t *testing.T) {
	// Verify that unmarshaling partial YAML leaves unset fields as nil.
	input := `timeout: 30`
	var cfg Config
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if cfg.Timeout == nil {
		t.Fatal("Timeout should not be nil")
	}
	if got, want := *cfg.Timeout, 30; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
	if cfg.MaxOutputBytes != nil {
		t.Fatalf("MaxOutputBytes = %v, want nil", cfg.MaxOutputBytes)
	}
	if cfg.SSH != nil {
		t.Fatalf("SSH = %v, want nil", cfg.SSH)
	}
}

func TestSSHConfigDuration(t *testing.T) {
	input := `
ssh:
  connect_timeout: "5s"
  retries: 3
  retry_backoff: "1s"
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatalf("Unmarshal error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if cfg.SSH.ConnectTimeout == nil {
		t.Fatal("SSH.ConnectTimeout should not be nil")
	}
	if got, want := cfg.SSH.ConnectTimeout.Duration(), 5*time.Second; got != want {
		t.Fatalf("ConnectTimeout = %v, want %v", got, want)
	}
	if got, want := *cfg.SSH.Retries, 3; got != want {
		t.Fatalf("Retries = %d, want %d", got, want)
	}
	if got, want := cfg.SSH.RetryBackoff.Duration(), 1*time.Second; got != want {
		t.Fatalf("RetryBackoff = %v, want %v", got, want)
	}
}

func TestLoadFrom_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `
timeout: 60
max_output_bytes: 131072
max_download_bytes: 1048576
download_dir: "/tmp/downloads"
max_sleep_seconds: 10
manifest_dir: "/tmp/manifests"
ssh:
  connect_timeout: "30s"
  retries: 5
  retry_backoff: "2s"
`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if got, want := *cfg.Timeout, 60; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
	if got, want := *cfg.MaxOutputBytes, 131072; got != want {
		t.Fatalf("MaxOutputBytes = %d, want %d", got, want)
	}
	if got, want := *cfg.MaxDownloadBytes, 1048576; got != want {
		t.Fatalf("MaxDownloadBytes = %d, want %d", got, want)
	}
	if got, want := *cfg.DownloadDir, "/tmp/downloads"; got != want {
		t.Fatalf("DownloadDir = %q, want %q", got, want)
	}
	if got, want := *cfg.MaxSleepSeconds, 10; got != want {
		t.Fatalf("MaxSleepSeconds = %d, want %d", got, want)
	}
	if got, want := *cfg.ManifestDir, "/tmp/manifests"; got != want {
		t.Fatalf("ManifestDir = %q, want %q", got, want)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if got, want := cfg.SSH.ConnectTimeout.Duration(), 30*time.Second; got != want {
		t.Fatalf("SSH.ConnectTimeout = %v, want %v", got, want)
	}
	if got, want := *cfg.SSH.Retries, 5; got != want {
		t.Fatalf("SSH.Retries = %d, want %d", got, want)
	}
	if got, want := cfg.SSH.RetryBackoff.Duration(), 2*time.Second; got != want {
		t.Fatalf("SSH.RetryBackoff = %v, want %v", got, want)
	}
}

func TestLoadFrom_MissingFile(t *testing.T) {
	cfg, err := LoadFrom("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadFrom() error = %v, want nil for missing file", err)
	}
	if cfg.Timeout != nil {
		t.Fatalf("Timeout = %v, want nil for missing file", cfg.Timeout)
	}
}

func TestLoadFrom_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.Timeout != nil {
		t.Fatalf("Timeout = %v, want nil for empty file", cfg.Timeout)
	}
}

func TestLoadFrom_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("timeout: [invalid"), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for invalid YAML, got nil")
	}
}

func TestLoadFrom_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `timeout: 45`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if got, want := *cfg.Timeout, 45; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
	if cfg.MaxOutputBytes != nil {
		t.Fatalf("MaxOutputBytes = %v, want nil", cfg.MaxOutputBytes)
	}
	if cfg.SSH != nil {
		t.Fatalf("SSH = %v, want nil for partial config", cfg.SSH)
	}
}

func TestEnvOverrides_AllVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	t.Setenv("SHELLGUARD_TIMEOUT", "120")
	t.Setenv("SHELLGUARD_MAX_OUTPUT_BYTES", "262144")
	t.Setenv("SHELLGUARD_MAX_DOWNLOAD_BYTES", "2097152")
	t.Setenv("SHELLGUARD_DOWNLOAD_DIR", "/tmp/dl")
	t.Setenv("SHELLGUARD_MAX_SLEEP_SECONDS", "30")
	t.Setenv("SHELLGUARD_SSH_CONNECT_TIMEOUT", "10s")
	t.Setenv("SHELLGUARD_SSH_RETRIES", "7")
	t.Setenv("SHELLGUARD_SSH_RETRY_BACKOFF", "3s")
	t.Setenv("SHELLGUARD_MANIFEST_DIR", "/tmp/mf")

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if got, want := *cfg.Timeout, 120; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
	if got, want := *cfg.MaxOutputBytes, 262144; got != want {
		t.Fatalf("MaxOutputBytes = %d, want %d", got, want)
	}
	if got, want := *cfg.MaxDownloadBytes, 2097152; got != want {
		t.Fatalf("MaxDownloadBytes = %d, want %d", got, want)
	}
	if got, want := *cfg.DownloadDir, "/tmp/dl"; got != want {
		t.Fatalf("DownloadDir = %q, want %q", got, want)
	}
	if got, want := *cfg.MaxSleepSeconds, 30; got != want {
		t.Fatalf("MaxSleepSeconds = %d, want %d", got, want)
	}
	if got, want := *cfg.ManifestDir, "/tmp/mf"; got != want {
		t.Fatalf("ManifestDir = %q, want %q", got, want)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil after env override")
	}
	if got, want := cfg.SSH.ConnectTimeout.Duration(), 10*time.Second; got != want {
		t.Fatalf("SSH.ConnectTimeout = %v, want %v", got, want)
	}
	if got, want := *cfg.SSH.Retries, 7; got != want {
		t.Fatalf("SSH.Retries = %d, want %d", got, want)
	}
	if got, want := cfg.SSH.RetryBackoff.Duration(), 3*time.Second; got != want {
		t.Fatalf("SSH.RetryBackoff = %v, want %v", got, want)
	}
}

func TestEnvOverrides_OverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `timeout: 60`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	t.Setenv("SHELLGUARD_TIMEOUT", "90")

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if got, want := *cfg.Timeout, 90; got != want {
		t.Fatalf("Timeout = %d, want %d (env should override file)", got, want)
	}
}

func TestEnvOverrides_InvalidInt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	t.Setenv("SHELLGUARD_TIMEOUT", "notanumber")

	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for invalid int env var, got nil")
	}
}

func TestEnvOverrides_NoEnvVars(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `timeout: 45`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if got, want := *cfg.Timeout, 45; got != want {
		t.Fatalf("Timeout = %d, want %d (file value should be preserved)", got, want)
	}
	if cfg.MaxOutputBytes != nil {
		t.Fatalf("MaxOutputBytes = %v, want nil (no env set)", cfg.MaxOutputBytes)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	return path
}

func TestLoad_FullPrecedence(t *testing.T) {
	// File sets timeout=60, env sets timeout=120. Env should win.
	content := "timeout: 60\nmax_output_bytes: 131072\n"
	dir := t.TempDir()
	configDir := filepath.Join(dir, "shellguard")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("SHELLGUARD_TIMEOUT", "120")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Timeout == nil || *cfg.Timeout != 120 {
		t.Fatalf("Timeout = %v, want 120 (env should override file)", cfg.Timeout)
	}
	if cfg.MaxOutputBytes == nil || *cfg.MaxOutputBytes != 131072 {
		t.Fatalf("MaxOutputBytes = %v, want 131072 (from file)", cfg.MaxOutputBytes)
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	path := writeConfig(t, `timeout: -1`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative timeout, got nil")
	}
}

func TestValidate_ZeroTimeout(t *testing.T) {
	path := writeConfig(t, `timeout: 0`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for zero timeout, got nil")
	}
}

func TestValidate_NegativeMaxOutputBytes(t *testing.T) {
	path := writeConfig(t, `max_output_bytes: -1`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative max_output_bytes, got nil")
	}
}

func TestValidate_NegativeMaxDownloadBytes(t *testing.T) {
	path := writeConfig(t, `max_download_bytes: -1`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative max_download_bytes, got nil")
	}
}

func TestValidate_NegativeRetries(t *testing.T) {
	path := writeConfig(t, "ssh:\n  retries: -1")
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative retries, got nil")
	}
}

func TestValidate_NegativeMaxSleepSeconds(t *testing.T) {
	path := writeConfig(t, `max_sleep_seconds: -1`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative max_sleep_seconds, got nil")
	}
}

func TestValidate_ZeroMaxSleepSeconds(t *testing.T) {
	path := writeConfig(t, `max_sleep_seconds: 0`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for zero max_sleep_seconds, got nil")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	path := writeConfig(t, `
timeout: 60
max_output_bytes: 65536
max_download_bytes: 0
max_sleep_seconds: 10
ssh:
  retries: 0
`)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if got, want := *cfg.Timeout, 60; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
}

func TestValidate_EmptyConfig(t *testing.T) {
	path := writeConfig(t, "")
	_, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v, want nil for empty config", err)
	}
}

func TestValidate_TimeoutExceedsMax(t *testing.T) {
	path := writeConfig(t, `timeout: 3601`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for timeout exceeding 3600, got nil")
	}
}

func TestValidate_TimeoutAtMax(t *testing.T) {
	path := writeConfig(t, `timeout: 3600`)
	_, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v, want nil for timeout at max", err)
	}
}

func TestValidate_MaxOutputBytesExceedsMax(t *testing.T) {
	path := writeConfig(t, `max_output_bytes: 1073741825`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for max_output_bytes exceeding 1 GB, got nil")
	}
}

func TestValidate_MaxOutputBytesAtMax(t *testing.T) {
	path := writeConfig(t, `max_output_bytes: 1073741824`)
	_, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v, want nil for max_output_bytes at max", err)
	}
}

func TestValidate_MaxDownloadBytesExceedsMax(t *testing.T) {
	path := writeConfig(t, `max_download_bytes: 1073741825`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for max_download_bytes exceeding 1 GB, got nil")
	}
}

func TestValidate_MaxDownloadBytesAtMax(t *testing.T) {
	path := writeConfig(t, `max_download_bytes: 1073741824`)
	_, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v, want nil for max_download_bytes at max", err)
	}
}

func TestValidate_MaxSleepSecondsExceedsMax(t *testing.T) {
	path := writeConfig(t, `max_sleep_seconds: 301`)
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for max_sleep_seconds exceeding 300, got nil")
	}
}

func TestValidate_MaxSleepSecondsAtMax(t *testing.T) {
	path := writeConfig(t, `max_sleep_seconds: 300`)
	_, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v, want nil for max_sleep_seconds at max", err)
	}
}

func TestValidate_NegativeConnectTimeout(t *testing.T) {
	path := writeConfig(t, "ssh:\n  connect_timeout: \"-5s\"")
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative connect_timeout, got nil")
	}
}

func TestValidate_NegativeRetryBackoff(t *testing.T) {
	path := writeConfig(t, "ssh:\n  retry_backoff: \"-1s\"")
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for negative retry_backoff, got nil")
	}
}

func TestValidate_ZeroConnectTimeout(t *testing.T) {
	path := writeConfig(t, "ssh:\n  connect_timeout: \"0s\"")
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for zero connect_timeout, got nil")
	}
}

func TestValidate_ZeroRetryBackoff(t *testing.T) {
	path := writeConfig(t, "ssh:\n  retry_backoff: \"0s\"")
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for zero retry_backoff, got nil")
	}
}

func TestSSHConfigHostKeyChecking(t *testing.T) {
	input := `
ssh:
  host_key_checking: "accept-new"
  known_hosts_file: "/custom/known_hosts"
`
	path := writeConfig(t, input)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if cfg.SSH.HostKeyChecking == nil {
		t.Fatal("SSH.HostKeyChecking should not be nil")
	}
	if got, want := *cfg.SSH.HostKeyChecking, "accept-new"; got != want {
		t.Fatalf("SSH.HostKeyChecking = %q, want %q", got, want)
	}
	if cfg.SSH.KnownHostsFile == nil {
		t.Fatal("SSH.KnownHostsFile should not be nil")
	}
	if got, want := *cfg.SSH.KnownHostsFile, "/custom/known_hosts"; got != want {
		t.Fatalf("SSH.KnownHostsFile = %q, want %q", got, want)
	}
}

func TestSSHConfigHostKeyCheckingStrict(t *testing.T) {
	path := writeConfig(t, "ssh:\n  host_key_checking: \"strict\"")
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if cfg.SSH.HostKeyChecking == nil {
		t.Fatal("SSH.HostKeyChecking should not be nil")
	}
	if got, want := *cfg.SSH.HostKeyChecking, "strict"; got != want {
		t.Fatalf("SSH.HostKeyChecking = %q, want %q", got, want)
	}
}

func TestSSHConfigHostKeyCheckingOff(t *testing.T) {
	path := writeConfig(t, "ssh:\n  host_key_checking: \"off\"")
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if cfg.SSH.HostKeyChecking == nil {
		t.Fatal("SSH.HostKeyChecking should not be nil")
	}
	if got, want := *cfg.SSH.HostKeyChecking, "off"; got != want {
		t.Fatalf("SSH.HostKeyChecking = %q, want %q", got, want)
	}
}

func TestValidate_InvalidHostKeyChecking(t *testing.T) {
	path := writeConfig(t, "ssh:\n  host_key_checking: \"invalid\"")
	_, err := LoadFrom(path)
	if err == nil {
		t.Fatal("LoadFrom() expected error for invalid host_key_checking, got nil")
	}
}

func TestValidate_ValidHostKeyCheckingModes(t *testing.T) {
	modes := []string{"accept-new", "strict", "off"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			path := writeConfig(t, fmt.Sprintf("ssh:\n  host_key_checking: %q", mode))
			cfg, err := LoadFrom(path)
			if err != nil {
				t.Fatalf("LoadFrom() error = %v", err)
			}
			if cfg.SSH == nil {
				t.Fatal("SSH should not be nil")
			}
			if cfg.SSH.HostKeyChecking == nil {
				t.Fatal("SSH.HostKeyChecking should not be nil")
			}
			if got, want := *cfg.SSH.HostKeyChecking, mode; got != want {
				t.Fatalf("SSH.HostKeyChecking = %q, want %q", got, want)
			}
		})
	}
}

func TestEnvOverrides_HostKeyChecking(t *testing.T) {
	path := writeConfig(t, "")

	t.Setenv("SHELLGUARD_SSH_HOST_KEY_CHECKING", "strict")
	t.Setenv("SHELLGUARD_SSH_KNOWN_HOSTS_FILE", "/env/known_hosts")

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil after env override")
	}
	if cfg.SSH.HostKeyChecking == nil {
		t.Fatal("SSH.HostKeyChecking should not be nil after env override")
	}
	if got, want := *cfg.SSH.HostKeyChecking, "strict"; got != want {
		t.Fatalf("SSH.HostKeyChecking = %q, want %q", got, want)
	}
	if cfg.SSH.KnownHostsFile == nil {
		t.Fatal("SSH.KnownHostsFile should not be nil after env override")
	}
	if got, want := *cfg.SSH.KnownHostsFile, "/env/known_hosts"; got != want {
		t.Fatalf("SSH.KnownHostsFile = %q, want %q", got, want)
	}
}

func TestEnvOverrides_HostKeyCheckingOverridesFile(t *testing.T) {
	path := writeConfig(t, "ssh:\n  host_key_checking: \"accept-new\"")

	t.Setenv("SHELLGUARD_SSH_HOST_KEY_CHECKING", "strict")

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if cfg.SSH.HostKeyChecking == nil {
		t.Fatal("SSH.HostKeyChecking should not be nil")
	}
	if got, want := *cfg.SSH.HostKeyChecking, "strict"; got != want {
		t.Fatalf("SSH.HostKeyChecking = %q, want %q (env should override file)", got, want)
	}
}

func TestSSHConfigHostKeyCheckingNilWhenUnset(t *testing.T) {
	input := `
ssh:
  retries: 3
`
	path := writeConfig(t, input)
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}
	if cfg.SSH == nil {
		t.Fatal("SSH should not be nil")
	}
	if cfg.SSH.HostKeyChecking != nil {
		t.Fatalf("SSH.HostKeyChecking = %q, want nil when unset", *cfg.SSH.HostKeyChecking)
	}
	if cfg.SSH.KnownHostsFile != nil {
		t.Fatalf("SSH.KnownHostsFile = %q, want nil when unset", *cfg.SSH.KnownHostsFile)
	}
}
