// Package shellguard is an MCP server giving LLM agents read-only shell access over SSH.
package shellguard

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jonchun/shellguard/config"
	"github.com/jonchun/shellguard/manifest"
	"github.com/jonchun/shellguard/server"
	"github.com/jonchun/shellguard/ssh"
)

type Config struct {
	// Manifests is the command registry. If nil, the built-in defaults are loaded.
	Manifests map[string]*manifest.Manifest

	// Executor is the backend for running commands. If nil, a default SSH executor
	// (ssh.SSHManager with default dialer) is created.
	Executor server.Executor

	// Logger is the structured logger passed to Core. If nil, a discard logger is used.
	Logger *slog.Logger

	// Name overrides the MCP server implementation name (default: "shellguard").
	Name string

	// Version overrides the MCP server implementation version (default: "0.1.0").
	Version string
}

// New builds a Core, loading manifests and SSH config from cfg.
func New(cfg Config) (*server.Core, error) {
	userCfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load user config: %w", err)
	}

	registry := cfg.Manifests
	if registry == nil {
		registry, err = manifest.LoadEmbedded()
		if err != nil {
			return nil, fmt.Errorf("load embedded manifests: %w", err)
		}
	}

	if userCfg.ManifestDir != nil {
		userManifests, err := manifest.LoadDir(*userCfg.ManifestDir)
		if err != nil {
			return nil, fmt.Errorf("load user manifests from %s: %w", *userCfg.ManifestDir, err)
		}
		registry = manifest.Merge(registry, userManifests)
	}

	var sshOpts []ssh.Option
	if userCfg.SSH != nil {
		if userCfg.SSH.Retries != nil {
			sshOpts = append(sshOpts, ssh.WithRetries(*userCfg.SSH.Retries))
		}
		if userCfg.SSH.RetryBackoff != nil {
			sshOpts = append(sshOpts, ssh.WithRetryBackoff(userCfg.SSH.RetryBackoff.Duration()))
		}
		if userCfg.SSH.ConnectTimeout != nil {
			sshOpts = append(sshOpts, ssh.WithConnectTimeout(userCfg.SSH.ConnectTimeout.Duration()))
		}
		if userCfg.SSH.HostKeyChecking != nil {
			sshOpts = append(sshOpts, ssh.WithHostKeyChecking(ssh.HostKeyMode(*userCfg.SSH.HostKeyChecking)))
		}
		if userCfg.SSH.KnownHostsFile != nil {
			sshOpts = append(sshOpts, ssh.WithKnownHostsFile(*userCfg.SSH.KnownHostsFile))
		}
	}

	runner := cfg.Executor
	if runner == nil {
		runner = ssh.NewSSHManager(nil, sshOpts...)
	}

	var coreOpts []server.CoreOption
	if userCfg.Timeout != nil {
		coreOpts = append(coreOpts, server.WithDefaultTimeout(*userCfg.Timeout))
	}
	if userCfg.MaxOutputBytes != nil {
		coreOpts = append(coreOpts, server.WithMaxOutputBytes(*userCfg.MaxOutputBytes))
	}
	if userCfg.MaxDownloadBytes != nil {
		coreOpts = append(coreOpts, server.WithMaxDownloadBytes(*userCfg.MaxDownloadBytes))
	}
	if userCfg.DownloadDir != nil {
		coreOpts = append(coreOpts, server.WithDownloadDir(*userCfg.DownloadDir))
	}
	if userCfg.MaxSleepSeconds != nil {
		coreOpts = append(coreOpts, server.WithMaxSleepSeconds(*userCfg.MaxSleepSeconds))
	}

	return server.NewCore(registry, runner, cfg.Logger, coreOpts...), nil
}

// RunStdio creates a server from cfg and runs it over stdin/stdout.
func RunStdio(ctx context.Context, cfg Config, logger *slog.Logger) error {
	if cfg.Logger == nil {
		cfg.Logger = logger
	}
	core, err := New(cfg)
	if err != nil {
		return err
	}
	return server.RunStdio(ctx, core, logger, server.ServerOptions{
		Name:    cfg.Name,
		Version: cfg.Version,
	})
}
