# ShellGuard

Stop copy-pasting terminal output into your AI. Let your LLM SSH in and look around.

ShellGuard is an [MCP](https://modelcontextprotocol.io/) server that gives LLM agents read-only bash access to remote servers over SSH. Connect your AI to production, staging, or dev servers and let it run diagnostics, inspect logs, query databases, and troubleshoot -- hands-free.

Commands are restricted to a curated set of read-only tools. Destructive operations are blocked with actionable suggestions so the LLM can self-correct and keep investigating:

- `wget` -> `"Use curl with GET-only policy for network diagnostics"`
- `tail -f` -> `"Follow mode hangs until timeout. Use tail -n 100 for recent lines."`
- `sed` -> `"Stream editing can modify files -- read-only access only. Use grep for searching."`
- `$HOME/file` -> `"Variable expansion will not expand. Use absolute paths."`

## Quick Start

### Install

```bash
brew install jonchun/tap/shellguard
```

Or download the latest binary:

```bash
curl -fsSL https://raw.githubusercontent.com/jonchun/shellguard/main/install.sh | sh
```

Or with Go:

```bash
go install github.com/jonchun/shellguard/cmd/shellguard@latest
```

### Configure with an MCP Client

ShellGuard starts as a stdio MCP server -- no arguments needed. Add it to your MCP client of choice:

<details>
<summary><b>Cursor</b></summary>

Go to: `Settings` -> `Cursor Settings` -> `MCP` -> `Add new global MCP server`

Or paste this into your `~/.cursor/mcp.json` file. You can also install per-project by creating `.cursor/mcp.json` in your project folder. See [Cursor MCP docs](https://docs.cursor.com/context/model-context-protocol) for more info.

```json
{
  "mcpServers": {
    "shellguard": {
      "command": "shellguard"
    }
  }
}
```

</details>

<details>
<summary><b>Claude Desktop</b></summary>

Add the following to your Claude Desktop config file. See [Claude Desktop MCP docs](https://modelcontextprotocol.io/quickstart/user) for more info.

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "shellguard": {
      "command": "shellguard"
    }
  }
}
```

</details>

<details>
<summary><b>Claude Code</b></summary>

Run this command. See [Claude Code MCP docs](https://docs.anthropic.com/en/docs/claude-code/mcp) for more info.

```sh
claude mcp add shellguard -- shellguard
```

</details>

<details>
<summary><b>OpenCode</b></summary>

Add this to your OpenCode configuration file. See [OpenCode MCP docs](https://opencode.ai/docs/mcp-servers) for more info.

```json
{
  "mcp": {
    "shellguard": {
      "type": "local",
      "command": ["shellguard"],
      "enabled": true
    }
  }
}
```

</details>

<details>
<summary><b>VS Code / GitHub Copilot</b></summary>

Add the following to your VS Code `settings.json` or `.vscode/mcp.json`. See [VS Code MCP docs](https://code.visualstudio.com/docs/copilot/chat/mcp-servers) for more info.

#### User settings (`settings.json`)

```json
{
  "mcp": {
    "servers": {
      "shellguard": {
        "type": "stdio",
        "command": "shellguard"
      }
    }
  }
}
```

#### Workspace config (`.vscode/mcp.json`)

```json
{
  "servers": {
    "shellguard": {
      "type": "stdio",
      "command": "shellguard"
    }
  }
}
```

</details>

<details>
<summary><b>Zed</b></summary>

Add the following to your Zed settings file (`~/.config/zed/settings.json`). See [Zed MCP docs](https://zed.dev/docs/assistant/model-context-protocol) for more info.

```json
{
  "context_servers": {
    "shellguard": {
      "command": {
        "path": "shellguard",
        "args": []
      }
    }
  }
}
```

</details>

<details>
<summary><b>Roo Code</b></summary>

Go to: `Roo Code Settings` -> `MCP Servers` -> `Edit MCP Settings`

Or add the following to your Roo Code MCP settings file. See [Roo Code MCP docs](https://docs.roocode.com/features/mcp/using-mcp-in-roo) for more info.

```json
{
  "mcpServers": {
    "shellguard": {
      "command": "shellguard"
    }
  }
}
```

</details>

## What It Does

ShellGuard exposes 7 tools to the LLM:

| Tool            | Description                                                   |
| --------------- | ------------------------------------------------------------- |
| `connect`       | Establish an SSH connection to a remote host                  |
| `execute`       | Run a read-only shell command on the remote host              |
| `list_commands` | List available commands, optionally filtered by category      |
| `disconnect`    | Close SSH connection(s)                                       |
| `provision`     | Deploy diagnostic tools (`rg`, `jq`, `yq`) to the remote host |
| `download_file` | Download a file from the remote host via SFTP (50MB limit)    |
| `sleep`         | Wait between diagnostic checks (max 15s)                      |

The LLM connects to a server, runs commands, and reads the output -- the same workflow you'd do manually, but without the context-switching.

## How It Works

Every command goes through a pipeline before reaching the remote host:

1. **Parse** -- bash is parsed into an AST. Shell tricks (semicolons, redirections, command substitution, etc.) are rejected at the syntax level.
2. **Validate** -- commands, flags, and arguments are checked against a curated allowlist of commands (with an explicit denylist). Default-deny.
3. **Reconstruct** -- arguments are re-quoted to prevent injection.
4. **Execute** -- the command runs over SSH with per-command timeouts and output truncation.

For full details, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Toolkit Provisioning

Remote servers don't always have the tools you want. On `connect`, ShellGuard probes for `rg`, `jq`, and `yq`. If any are missing, the LLM can call `provision` to deploy them:

| Tool           | Version | Architectures   |
| -------------- | ------- | --------------- |
| `rg` (ripgrep) | 14.1.1  | x86_64, aarch64 |
| `jq`           | 1.7.1   | x86_64, aarch64 |
| `yq`           | 4.52.2  | x86_64, aarch64 |

Binaries are downloaded from GitHub Releases with SHA-256 verification, cached locally, and deployed to `~/.shellguard/bin/` on the remote host.

## Library Usage

ShellGuard can be used as a Go library:

```go
package main

import (
    "context"
    "log/slog"
    "os"

    "github.com/jonchun/shellguard"
)

func main() {
    ctx := context.Background()
    logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

    err := shellguard.RunStdio(ctx, shellguard.Config{}, logger)
    if err != nil {
        os.Exit(1)
    }
}
```

See the [Custom Configuration](#custom-configuration) and [Custom Executor](#custom-executor-backend) sections below for advanced usage.

### Custom Configuration

```go
import (
    "github.com/jonchun/shellguard"
    "github.com/jonchun/shellguard/manifest"
    "github.com/jonchun/shellguard/server"
)

manifests, _ := manifest.LoadEmbedded()
// Add or remove commands as needed

core, err := shellguard.New(shellguard.Config{
    Manifests: manifests,         // Custom registry (nil = embedded defaults)
    Executor:  myCustomExecutor,  // Custom backend (nil = SSH)
    Name:      "my-server",       // MCP server name
    Version:   "1.0.0",          // MCP server version
})
```

### Custom Executor Backend

Implement the `server.Executor` interface to use non-SSH backends:

```go
type Executor interface {
    Connect(ctx context.Context, params ssh.ConnectionParams) error
    Execute(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error)
    ExecuteRaw(ctx context.Context, host, command string, timeout time.Duration) (ssh.ExecResult, error)
    SFTPSession(host string) (ssh.SFTPClient, error)
    Disconnect(host string) error
}
```

## Testing

```bash
make test          # Run all tests
make test-race     # Run with race detector
make lint          # Run go vet
```

## Project Structure

```
shellguard/
  shellguard.go          # Top-level constructor (New, RunStdio)
  cmd/shellguard/        # CLI entrypoint
  server/                # MCP server core, tool registration, Executor interface
  parser/                # Shell AST parser (mvdan.cc/sh/v3)
  validator/             # Command/flag/SQL validation engine
  manifest/              # YAML command registry (embed.FS)
    manifests/           # allowed command manifests
    manifests/denied/    # denied command manifests
  ssh/                   # SSH manager, ShellQuote, ReconstructCommand
  output/                # Output truncation (64KB cap)
  toolkit/               # Diagnostic tool provisioning (rg, jq, yq)
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
