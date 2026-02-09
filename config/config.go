// Package config loads ShellGuard settings from file and environment.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	configFileName = "config.yaml"
	configDirName  = "shellguard"
)

// duration wraps time.Duration for YAML unmarshaling.
type duration struct {
	d time.Duration
}

func (d *duration) unmarshalText(s string) error {
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.d = parsed
	return nil
}

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	return d.unmarshalText(value.Value)
}

func (d *duration) Duration() time.Duration {
	return d.d
}

// Config for ShellGuard. Pointer fields; nil = unset.
type Config struct {
	Timeout          *int       `yaml:"timeout"`
	MaxOutputBytes   *int       `yaml:"max_output_bytes"`
	MaxDownloadBytes *int       `yaml:"max_download_bytes"`
	DownloadDir      *string    `yaml:"download_dir"`
	MaxSleepSeconds  *int       `yaml:"max_sleep_seconds"`
	SSH              *SSHConfig `yaml:"ssh"`
	ManifestDir      *string    `yaml:"manifest_dir"`
}

// SSHConfig holds SSH-specific configuration.
type SSHConfig struct {
	ConnectTimeout  *duration `yaml:"connect_timeout"`
	Retries         *int      `yaml:"retries"`
	RetryBackoff    *duration `yaml:"retry_backoff"`
	HostKeyChecking *string   `yaml:"host_key_checking"`
	KnownHostsFile  *string   `yaml:"known_hosts_file"`
}

// LoadFrom loads config from path. Missing files return zero Config, nil.
func LoadFrom(path string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return Config{}, fmt.Errorf("read config file: %w", err)
		}
	} else if len(data) > 0 {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse config file: %w", err)
		}
	}

	if err := cfg.applyEnvOverrides(); err != nil {
		return Config{}, err
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func Load() (Config, error) {
	return LoadFrom(defaultConfigPath())
}

func (c *Config) applyEnvOverrides() error {
	if v, ok := os.LookupEnv("SHELLGUARD_TIMEOUT"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse SHELLGUARD_TIMEOUT: %w", err)
		}
		c.Timeout = &n
	}
	if v, ok := os.LookupEnv("SHELLGUARD_MAX_OUTPUT_BYTES"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse SHELLGUARD_MAX_OUTPUT_BYTES: %w", err)
		}
		c.MaxOutputBytes = &n
	}
	if v, ok := os.LookupEnv("SHELLGUARD_MAX_DOWNLOAD_BYTES"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse SHELLGUARD_MAX_DOWNLOAD_BYTES: %w", err)
		}
		c.MaxDownloadBytes = &n
	}
	if v, ok := os.LookupEnv("SHELLGUARD_DOWNLOAD_DIR"); ok {
		c.DownloadDir = &v
	}
	if v, ok := os.LookupEnv("SHELLGUARD_MAX_SLEEP_SECONDS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse SHELLGUARD_MAX_SLEEP_SECONDS: %w", err)
		}
		c.MaxSleepSeconds = &n
	}
	if v, ok := os.LookupEnv("SHELLGUARD_MANIFEST_DIR"); ok {
		c.ManifestDir = &v
	}

	if v, ok := os.LookupEnv("SHELLGUARD_SSH_CONNECT_TIMEOUT"); ok {
		if c.SSH == nil {
			c.SSH = &SSHConfig{}
		}
		d := &duration{}
		if err := d.unmarshalText(v); err != nil {
			return fmt.Errorf("parse SHELLGUARD_SSH_CONNECT_TIMEOUT: %w", err)
		}
		c.SSH.ConnectTimeout = d
	}
	if v, ok := os.LookupEnv("SHELLGUARD_SSH_RETRIES"); ok {
		if c.SSH == nil {
			c.SSH = &SSHConfig{}
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("parse SHELLGUARD_SSH_RETRIES: %w", err)
		}
		c.SSH.Retries = &n
	}
	if v, ok := os.LookupEnv("SHELLGUARD_SSH_RETRY_BACKOFF"); ok {
		if c.SSH == nil {
			c.SSH = &SSHConfig{}
		}
		d := &duration{}
		if err := d.unmarshalText(v); err != nil {
			return fmt.Errorf("parse SHELLGUARD_SSH_RETRY_BACKOFF: %w", err)
		}
		c.SSH.RetryBackoff = d
	}
	if v, ok := os.LookupEnv("SHELLGUARD_SSH_HOST_KEY_CHECKING"); ok {
		if c.SSH == nil {
			c.SSH = &SSHConfig{}
		}
		c.SSH.HostKeyChecking = &v
	}
	if v, ok := os.LookupEnv("SHELLGUARD_SSH_KNOWN_HOSTS_FILE"); ok {
		if c.SSH == nil {
			c.SSH = &SSHConfig{}
		}
		c.SSH.KnownHostsFile = &v
	}

	return nil
}

func (c *Config) validate() error {
	if c.Timeout != nil && *c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %d", *c.Timeout)
	}
	if c.Timeout != nil && *c.Timeout > 3600 {
		return fmt.Errorf("timeout must not exceed 3600 seconds, got %d", *c.Timeout)
	}
	if c.MaxOutputBytes != nil && *c.MaxOutputBytes < 0 {
		return fmt.Errorf("max_output_bytes must be non-negative, got %d", *c.MaxOutputBytes)
	}
	if c.MaxOutputBytes != nil && *c.MaxOutputBytes > 1024*1024*1024 {
		return fmt.Errorf("max_output_bytes must not exceed 1 GB, got %d", *c.MaxOutputBytes)
	}
	if c.MaxDownloadBytes != nil && *c.MaxDownloadBytes < 0 {
		return fmt.Errorf("max_download_bytes must be non-negative, got %d", *c.MaxDownloadBytes)
	}
	if c.MaxDownloadBytes != nil && *c.MaxDownloadBytes > 1024*1024*1024 {
		return fmt.Errorf("max_download_bytes must not exceed 1 GB, got %d", *c.MaxDownloadBytes)
	}
	if c.MaxSleepSeconds != nil && *c.MaxSleepSeconds <= 0 {
		return fmt.Errorf("max_sleep_seconds must be positive, got %d", *c.MaxSleepSeconds)
	}
	if c.MaxSleepSeconds != nil && *c.MaxSleepSeconds > 300 {
		return fmt.Errorf("max_sleep_seconds must not exceed 300, got %d", *c.MaxSleepSeconds)
	}
	if c.SSH != nil {
		if c.SSH.Retries != nil && *c.SSH.Retries < 0 {
			return fmt.Errorf("ssh.retries must be non-negative, got %d", *c.SSH.Retries)
		}
		if c.SSH.ConnectTimeout != nil && c.SSH.ConnectTimeout.Duration() <= 0 {
			return fmt.Errorf("ssh.connect_timeout must be positive, got %v", c.SSH.ConnectTimeout.Duration())
		}
		if c.SSH.RetryBackoff != nil && c.SSH.RetryBackoff.Duration() <= 0 {
			return fmt.Errorf("ssh.retry_backoff must be positive, got %v", c.SSH.RetryBackoff.Duration())
		}
		if c.SSH.HostKeyChecking != nil {
			mode := *c.SSH.HostKeyChecking
			if mode != "accept-new" && mode != "strict" && mode != "off" {
				return fmt.Errorf("ssh.host_key_checking must be one of: accept-new, strict, off; got %q", mode)
			}
		}
	}
	return nil
}

func defaultConfigPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, configDirName, configFileName)
}
