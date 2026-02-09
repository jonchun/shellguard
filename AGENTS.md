# AGENTS.md

Instructions for AI coding agents working in this repository.

## Build & Test Commands

```bash
make build          # Static binary to ./bin/shellguard (CGO_ENABLED=0)
make test           # go test ./... -count=1
make test-race      # go test ./... -race -count=1
make lint           # golangci-lint run ./...
```

Run a single test:

```bash
go test ./parser -run TestParseSimpleCommand -count=1
```

Run a single fuzz test:

```bash
go test ./parser -fuzz FuzzParse -fuzztime=30s
```

## Project Structure

```
shellguard.go                    # Root package: Config, New(), RunStdio()
cmd/shellguard/                  # CLI entry point
server/                          # MCP server core, tool registration, Executor interface
parser/                          # Shell AST parser (mvdan.cc/sh/v3)
validator/                       # Command/flag allowlist validation
ssh/                             # SSH manager, ShellQuote, ReconstructCommand
manifest/                        # YAML command registry (embed.FS)
  manifests/                     # Allowed command manifests
  manifests/denied/              # Denied command manifests
output/                          # Output truncation (64KB cap)
toolkit/                         # Diagnostic tool provisioning (rg, jq, yq)
```

Dependency flow: `server` depends on all other packages. `validator` depends on
`parser` and `manifest`. `ssh` (reconstruct) depends on `parser`. `manifest`,
`parser`, and `output` are standalone with zero internal dependencies.

## Code Style

### Imports

Two groups separated by a blank line: stdlib first, then everything else
(third-party and internal mixed together, alphabetically sorted).

```go
import (
    "context"
    "fmt"

    "github.com/jonchun/shellguard/manifest"
    "github.com/jonchun/shellguard/parser"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)
```

When a third-party package name conflicts with a local package, alias the
third-party one (e.g., `gossh "golang.org/x/crypto/ssh"` in `ssh/ssh.go`).

### Error Handling

Three patterns, each used in specific contexts:

1. **Custom error types** for user-facing validation/parse errors. Each domain
   package has its own (ParseError, ValidationError, ManifestError), all with a
   `Message string` field and `Error() string` method.

2. **`fmt.Errorf` with `%w`** for wrapping operational/infrastructure errors.
   Message format: `"lowercase context: %w"`.

3. **`errors.New`** for simple invariant violations (`"host is required"`).

Use `_ = expr` to explicitly discard intentionally ignored errors.

### Naming

- **Exported types**: PascalCase nouns (`Pipeline`, `ExecResult`, `Manifest`)
- **Interfaces**: capability names (`Executor`, `Dialer`, `SFTPClient`)
- **Input/output structs**: suffixed (`ConnectInput`, `DownloadResult`, `ProbeResult`)
- **Functions**: verb-first (`Parse`, `ValidatePipeline`, `ReconstructCommand`)
- **Unexported functions**: camelCase (`walkStmt`, `validateSegment`, `collisionSafePath`)
- **Unexported constants**: camelCase (`maxDownloadBytes`, `defaultTimeout`)
- **Exported constants**: PascalCase (`DefaultMaxBytes`, `RemoteBinDir`)
- **Sets**: `map[string]struct{}` for set semantics, `map[string]bool` for boolean state

### Struct Tags

MCP tool inputs use both `json` and `jsonschema` tags:

```go
type ConnectInput struct {
    Host string `json:"host" jsonschema:"Hostname or IP address"`
    Port int    `json:"port,omitempty" jsonschema:"SSH port (default 22)"`
}
```

- `json`: snake_case, `omitempty` for optional fields
- `jsonschema`: human-readable description (used by MCP SDK for schema generation)
- `yaml`: snake_case, used on manifest structs only

### General Patterns

- `context.Context` as first parameter in all async/network functions
- Mutex: always `mu.Lock()` + `defer mu.Unlock()`. Use `RLock`/`RUnlock` where possible
- Slice pre-allocation: `make([]T, 0, len(source))` consistently
- No `log` package; `log/slog` passed via dependency injection
- Functional options for configurable constructors (`WithRetries`, `WithRetryBackoff`)
- Function fields on `Core` struct for pipeline stage injection (enables test swapping
  without mock interfaces)

## Testing Conventions

### Libraries

Standard library `testing` only. No testify, no gomock. All mocks are hand-written.
Assertions use `t.Fatalf`/`t.Errorf` with `got`/`want`:

```go
if got, want := len(p.Segments), 1; got != want {
    t.Fatalf("len(Segments) = %d, want %d", got, want)
}
```

### Test Organization

- Unit tests: `_test.go` in same package
- Security tests: dedicated files (`security_test.go`, `attack_vectors_test.go`)
- Cross-layer tests: root-level `security_pipeline_test.go` in `package shellguard_test`
- Fuzz tests: `fuzz_test.go` per package

### Naming

- Unit tests: `TestParseSimpleCommand`, `TestConnectStoresConnection`
- Security tests: `TestSec_` prefix (`TestSec_ShellQuote_CommandSubstitution`)
- Cross-layer tests: `TestCrossLayer_`, `TestE2E_` prefixes
- Fuzz tests: `FuzzParse`, `FuzzShellQuoteIdempotent`

### Helpers

Always call `t.Helper()` in test helper functions. Common helpers:

- `mustParse()` / `mustParseErr()` in parser tests
- `testRegistry()` / `validateOne()` in validator tests
- `expectReject()` / `expectAllow()` in attack vector tests
- `fullPipeline()` / `mustReject()` / `mustAccept()` in cross-layer tests

### Fuzz Tests

Include rich seed corpora covering normal inputs, attack vectors, edge cases,
and unicode. Post-fuzz invariant checking is expected (non-empty segments, valid
operators, balanced quotes, idempotency, round-trip consistency).

## Manifest Conventions

Command manifests are YAML files in `manifest/manifests/` (allowed) and
`manifest/manifests/denied/` (denied), embedded at compile time via `//go:embed`.

Subcommand naming: `docker_ps`, `kubectl_get`, `systemctl_show`. AWS uses three
levels: `aws_ec2_describe-instances`.

Denied manifests require `deny: true` and a `reason:` field. Denied flags within
allowed commands also require a `reason:`.
