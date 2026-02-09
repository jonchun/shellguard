package ssh

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
)

type resolvedConfig struct {
	HostName      string
	User          string
	Port          int
	IdentityFiles []string
}

type resolver struct {
	config *sshconfig.Config
}

func newResolver(path string) *resolver {
	f, err := os.Open(path)
	if err != nil {
		return &resolver{}
	}
	defer func() { _ = f.Close() }()

	cfg, err := sshconfig.Decode(f)
	if err != nil {
		return &resolver{}
	}
	return &resolver{config: cfg}
}

func defaultResolver() *resolver {
	home, err := os.UserHomeDir()
	if err != nil {
		return &resolver{}
	}
	return newResolver(filepath.Join(home, ".ssh", "config"))
}

func (r *resolver) resolve(alias string) resolvedConfig {
	if r.config == nil {
		return resolvedConfig{}
	}

	var rc resolvedConfig

	if hostName, err := r.config.Get(alias, "HostName"); err == nil && hostName != "" {
		rc.HostName = hostName
	}

	if user, err := r.config.Get(alias, "User"); err == nil && user != "" {
		rc.User = user
	}

	if portStr, err := r.config.Get(alias, "Port"); err == nil && portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
			rc.Port = p
		}
	}

	if identFiles, err := r.config.GetAll(alias, "IdentityFile"); err == nil {
		for _, f := range identFiles {
			rc.IdentityFiles = append(rc.IdentityFiles, expandTilde(f))
		}
	}

	return rc
}

func applyResolved(params ConnectionParams, r *resolver) ConnectionParams {
	resolved := r.resolve(params.Host)

	if resolved.HostName != "" {
		params.Host = resolved.HostName
	}
	if params.User == "" && resolved.User != "" {
		params.User = resolved.User
	}
	if params.Port == 0 && resolved.Port > 0 {
		params.Port = resolved.Port
	}
	if params.IdentityFile == "" && len(resolved.IdentityFiles) > 0 {
		params.IdentityFile = resolved.IdentityFiles[0]
	}

	return params
}

func defaultApplySSHConfig(params ConnectionParams) ConnectionParams {
	return applyResolved(params, defaultResolver())
}

func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}
