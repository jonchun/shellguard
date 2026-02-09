# ShellGuard Architecture

## Overview

ShellGuard is a security-first MCP (Model Context Protocol) server that enables LLM agents to execute read-only shell commands on remote servers over SSH. It implements a defense-in-depth pipeline that parses, validates, and reconstructs every command before execution, ensuring only non-destructive operations reach the remote host.

## System Architecture

```
                         MCP Client (LLM Agent)
                                |
                          stdin/stdout or SSE
                                |
                       +--------v--------+
                       |   MCP Server    |  server package
                       |  (Tool Router)  |
                       +--------+--------+
                                |
                    +-----------+-----------+
                    |                       |
              connect/execute         list/provision
                    |                       |
            +-------v-------+       +-------v-------+
            |  Security     |       |   Toolkit     |
            |  Pipeline     |       |   (SFTP)      |
            +-------+-------+       +---------------+
                    |
       +------------+------------+
       |            |            |
  +----v----+ +----v-----+ +----v--------+
  | Parser  | | Validator| | Reconstructor|
  +---------+ +----------+ +-------------+
                                |
                        +-------v-------+
                        |  SSH Manager  |
                        |  (Executor)   |
                        +-------+-------+
                                |
                          Remote Server
```

## Security Pipeline

Every command passes through four sequential stages before execution. A failure at any stage blocks execution entirely.

### Stage 1: Parser (`parser` package)

Parses shell input using `mvdan.cc/sh/v3`, a proper bash AST parser. The parser accepts only a narrow subset of shell syntax and rejects everything else.

**Allowed:**

- Simple commands with arguments: `ls -la /tmp`
- Pipes: `ps aux | grep nginx | head -5`
- Conditional chaining: `cmd1 && cmd2`, `cmd1 || cmd2`
- Quoted arguments (quotes are stripped to semantic values)

**Blocked (with specific error messages):**

- Semicolons and multi-statement input
- Background execution (`&`)
- All redirections (`>`, `<`, `>>`, `2>&1`, heredocs)
- Variable expansion (`$HOME`, `${PATH}`)
- Command substitution (`$(cmd)`, `` `cmd` ``)
- Process substitution (`<(cmd)`)
- Arithmetic, brace expansion, extended globs
- Control flow (`if`, `for`, `while`, `case`)
- Subshells, blocks, function definitions, coprocesses
- Variable assignments (`FOO=bar`, `PATH=/evil cmd`)

**Output:** A `Pipeline` containing a flat list of `PipelineSegment` values, each with `Command`, `Args []string`, and `Operator` (one of `""`, `"|"`, `"&&"`, `"||"`).

### Stage 2: Validator (`validator` package)

Validates every pipeline segment against the manifest registry. Implements default-deny: a command must have an explicit manifest entry with `deny: false` to be allowed.

**Validation rules:**

| Concern              | How it is handled                                                               |
| -------------------- | ------------------------------------------------------------------------------- |
| Unknown commands     | Rejected (not in registry)                                                      |
| Denied commands      | Rejected with human-readable reason                                             |
| Unknown flags        | Rejected                                                                        |
| Denied flags         | Rejected (e.g., `curl -X`, `find -exec`)                                        |
| Combined short flags | Decomposed and each validated (`-irn` -> `-i`, `-r`, `-n`)                      |
| Flag values          | Checked against `allowed_values` if defined                                     |
| `sudo`               | Unwrapped; inner command recursively validated                                  |
| `xargs`              | Must be piped; inner command recursively validated                              |
| Subcommands          | Composite key lookup (`docker_ps`, `kubectl_get`, `aws_ec2_describe-instances`) |
| Glob in args         | Rejected (won't expand over SSH), except at `regex_arg_position`                |
| Path restrictions    | Checked against `restricted_paths` with normalization                           |
| `psql -c` SQL        | Read-only prefixes only; CTE bodies scanned for DML; multi-statement blocked    |
| `unzip`              | Requires `-l` or `-p` (list or pipe to stdout)                                  |
| `tar -x`             | Requires `-O` (extract to stdout only)                                          |

### Stage 3: Reconstructor (`ssh` package)

Rebuilds the validated pipeline into a safe shell command string using `ShellQuote()`.

**`ShellQuote` rules:**

- Safe tokens (matching `[a-zA-Z0-9_@%+=:,./-]`) pass through unchanged
- All other tokens are wrapped in single quotes with embedded `'` escaped as `'"'"'`
- Empty tokens become `''`

**Additional prefixes injected:**

- `PATH=$HOME/.shellguard/bin:$PATH` when toolkit tools are deployed
- `PGOPTIONS='-c default_transaction_read_only=on'` for psql commands (defense-in-depth)

### Stage 4: Executor (`ssh` package)

Sends the reconstructed command to the remote host via SSH. Output is truncated by the `output` package (64KB cap, 75/25 head/tail split).

## Package Dependency Graph

```
shellguard (root)
  |
  +-- server
  |     +-- parser
  |     +-- validator
  |     |     +-- parser
  |     |     +-- manifest
  |     +-- ssh
  |     |     +-- parser
  |     +-- manifest
  |     +-- output
  |     +-- toolkit
  |           +-- ssh (SFTPClient interface)
  |
  +-- manifest (standalone, YAML + embed)
  +-- parser  (standalone, mvdan.cc/sh/v3)
  +-- output  (standalone, zero deps)
```

## Package Details

### `shellguard` (root package)

Top-level constructor and convenience functions. Provides `New(Config)` to create a `server.Core` with sensible defaults (embedded manifests, SSH executor). `RunStdio()` is a convenience wrapper for subprocess usage.

### `server`

The MCP server core. Wires together all packages and registers 7 MCP tools:

| Tool            | Description                                                         |
| --------------- | ------------------------------------------------------------------- |
| `connect`       | Establish SSH connection to a remote host; probes for toolkit tools |
| `execute`       | Run a command through the security pipeline                         |
| `list_commands` | List allowed commands, optionally filtered by category              |
| `disconnect`    | Close SSH connection(s)                                             |
| `provision`     | Deploy diagnostic tools (`rg`, `jq`, `yq`) to remote host via SFTP  |
| `download_file` | Download a file from remote via SFTP (50MB limit)                   |
| `sleep`         | Local sleep (max 15s) for use between diagnostic checks             |

The `Executor` interface abstracts the execution backend, enabling non-SSH implementations (Docker exec, local exec, test mocks) without modifying the security pipeline.

Supports two MCP transports:

- **stdio** (`RunStdio`) -- for subprocess spawning by MCP clients
- **SSE over HTTP** (`NewHTTPHandler`) -- for networked deployments

### `parser`

Shell AST parser built on `mvdan.cc/sh/v3`. Configured for `LangBash`. The parser walks the AST recursively, handling `CallExpr` (simple commands) and `BinaryCmd` (pipes/chaining). The `wordToString()` function strips quotes and checks word parts for dangerous expansion nodes.

**Known limitation:** Command substitution nested inside double-quoted words (e.g., `"$(whoami)"`) passes through as a literal string argument. This is mitigated by the reconstructor's single-quoting, but represents a trust dependency between parser and reconstructor.

### `manifest`

YAML-based command registry embedded at compile time via `//go:embed`. Defines allowed and denied commands.

**Manifest schema (key fields):**

```yaml
name: curl # Registry key
description: "Transfer data" # Human-readable
category: network # Grouping
timeout: 30 # Max execution seconds
sudo_compatible: false # Allow sudo prefix
deny: false # true = blocked
reason: "" # Required when deny: true
allows_path_args: false # Path argument validation
restricted_paths: [] # Blocked path prefixes
regex_arg_position: null # Position exempt from glob check
flags:
  - flag: "-s"
    description: "Silent mode"
    takes_value: false
    pattern_value: false # Value is glob/regex pattern
    allowed_values: [] # Enumerated valid values
    deny: false
    reason: ""
```

**Subcommand convention:** `docker inspect` -> manifest name `docker_inspect`. AWS uses three levels: `aws ec2 describe-instances` -> `aws_ec2_describe-instances`.

### `validator`

Multi-stage command validation engine. Key internal components:

- **`validateSegment()`** -- dispatches to sudo/xargs/subcommand/standard handlers
- **`validateArgs()`** -- iterates arguments, classifying flags vs positional args
- **`validateSQL()`** -- read-only SQL enforcement for psql, including CTE body scanning
- **`checkRestrictedPath()`** -- normalized path comparison against blocked prefixes

### `ssh`

SSH connection manager with retry logic. Key components:

- **`SSHManager`** -- manages concurrent connections with mutex-protected state. Supports connection-per-host with implicit single-host resolution.
- **`XCryptoDialer`** -- default SSH dialer using `golang.org/x/crypto/ssh`. Note: host key verification is currently disabled.
- **`ShellQuote()` / `ReconstructCommand()`** -- the critical security boundary that neutralizes shell metacharacters.

**Retry logic:** Retries on transient errors (connection reset, broken pipe, timeout, EOF) with configurable count and exponential backoff.

### `output`

Output truncation with a head+tail strategy. At the default 64KB limit, keeps 48KB from the head and 16KB from the tail, with a truncation notice in between. This preserves both the beginning of output (column headers, initial results) and the end (summary lines, error messages).

### `toolkit`

Provisions three diagnostic tools onto remote servers:

| Tool           | Version | Source                   |
| -------------- | ------- | ------------------------ |
| `rg` (ripgrep) | 14.1.1  | GitHub Releases (tar.gz) |
| `jq`           | 1.7.1   | GitHub Releases (binary) |
| `yq`           | 4.52.2  | GitHub Releases (binary) |

**Flow:** Probe remote (`command -v`) -> identify missing tools + arch -> download locally with SHA-256 verification -> upload via SFTP to `~/.shellguard/bin/` -> set `0755` permissions.

Supports `x86_64` and `aarch64`. Binaries are cached locally at `~/.cache/shellguard/toolkit/<arch>/<tool>`.

## Security Model

ShellGuard enforces a **read-only, observational posture** through layered defenses:

1. **Syntax restriction** (parser) -- eliminates shell features that enable code execution, data exfiltration, or state mutation at the syntax level
2. **Command allowlisting** (validator + manifest) -- only explicitly approved commands pass; flags are individually controlled; SQL is validated for read-only semantics
3. **Argument neutralization** (reconstructor) -- single-quote wrapping ensures shell metacharacters in arguments are never interpreted
4. **Runtime safety** (executor) -- per-command timeouts prevent hangs; output truncation prevents memory exhaustion; read-only PostgreSQL transactions provide database-level defense-in-depth

**Trust boundaries:**

- The `Operator` field in `PipelineSegment` is inserted into reconstructed commands without quoting. Reconstruction trusts the parser to produce only safe operators (`|`, `&&`, `||`).
- The `Pipeline` struct must not be mutated between validation and reconstruction (no immutability enforcement exists).

## Testing Strategy

The project has extensive test coverage across multiple dimensions:

| Test Type            | Location                                                                                                                                              | Coverage                                                                                  |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Unit tests           | `*_test.go` in each package                                                                                                                           | Core logic, edge cases                                                                    |
| Security tests       | `parser/security_test.go` (40 attack vectors), `validator/attack_vectors_test.go` (20 categories), `ssh/reconstruct_security_test.go` (20 categories) | Per-layer attack surface                                                                  |
| Cross-layer security | `security_pipeline_test.go`                                                                                                                           | End-to-end injection, semantic gaps between layers                                        |
| Integration tests    | `integration_shellguard_test.go`                                                                                                                      | Full pipeline allow/deny, binary lifecycle                                                |
| Fuzz tests           | `parser/fuzz_test.go`, `ssh/fuzz_test.go`                                                                                                             | Crash detection, invariant checking, round-trip consistency, quoting structure validation |

## External Dependencies

| Dependency                               | Purpose                                            |
| ---------------------------------------- | -------------------------------------------------- |
| `mvdan.cc/sh/v3`                         | Bash syntax parser (proper AST, not regex)         |
| `golang.org/x/crypto`                    | SSH client implementation                          |
| `github.com/pkg/sftp`                    | SFTP file transfers                                |
| `gopkg.in/yaml.v3`                       | Manifest YAML parsing                              |
| `github.com/modelcontextprotocol/go-sdk` | MCP server framework (tools, stdio/SSE transports) |
