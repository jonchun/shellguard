# Secrets Protection Design

## Problem

Shellguard currently has zero protection against reading sensitive files or
leaking secrets. Any allowed command (`cat`, `grep`, `head`, `printenv`, etc.)
can freely access `.env`, private keys, cloud credentials, and similar files.
The `download_file` tool has no path validation at all.

### Threat Model

1. **Malicious exfiltration** — prompt injection or model misbehavior causes the
   LLM to issue tool calls that read secrets (e.g., `cat .env`, `printenv`)
2. **Accidental exposure** — the LLM innocently reads secrets during
   debugging/exploration and includes them in responses, exposing them in
   logs/chat history
3. **Privacy** — users don't want secrets sent to LLM API endpoints at all

All three concerns demand the same solution: **local heuristics that block or
redact secrets before they ever leave the machine.** No network calls, no LLM
involvement.

## Architecture

A new standalone `secrets` package (zero internal dependencies) provides two
capabilities integrated into the existing pipeline:

```
User Input
    │
    ▼
  Parse (parser)
    │
    ▼
  Validate (validator)          ← existing manifest-based validation
    │
    ▼
  CheckSecrets (secrets)        ← NEW: rejects sensitive file access
    │
    ▼
  Reconstruct (ssh)
    │
    ▼
  Execute (ssh)
    │
    ▼
  Truncate (output)
    │
    ▼
  ScrubSecrets (secrets)        ← NEW: redacts secrets from output
    │
    ▼
  Return to LLM
```

Both stages are function fields on `Core` for test injection, following the
existing pattern (`Parse`, `Validate`, `Reconstruct`, `Truncate`).

## Phase 1: Pre-execution Path Checking

### Sensitive Path Patterns

Default patterns are hardcoded in the package. Users can override via config.

| Category          | Patterns                                                                                  |
| ----------------- | ----------------------------------------------------------------------------------------- |
| Env files         | `.env`, `.env.*` (`.env.local`, `.env.production`, etc.)                                  |
| SSH keys          | `.ssh/id_*`, `.ssh/authorized_keys`, `.ssh/known_hosts`                                   |
| TLS/Certs         | `*.pem`, `*.key`, `*.pfx`, `*.p12`                                                        |
| Cloud credentials | `.aws/credentials`, `.aws/config`, `.gcloud/credentials.db`, `.azure/`, `.config/gcloud/` |
| K8s/Docker        | `.kube/config`, `.docker/config.json`                                                     |
| App credentials   | `credentials.json`, `service-account*.json`, `.netrc`, `.pgpass`, `.my.cnf`               |
| Git               | `.git-credentials`, `.gitconfig`                                                          |
| System            | `/etc/shadow`, `/etc/gshadow`, `/etc/master.passwd`                                       |
| Generic           | `*secret*`, `*credential*`, `*token*` in filenames                                        |

### How It Works

A new function `secrets.CheckPipeline(pipeline, config)` is called from
`Core.Execute()` between `Validate` and `Reconstruct`. For each segment's args:

1. Normalize the path (`path.Clean`, resolve `~`, strip trailing slashes)
2. Check the **basename** against filename patterns (`.env`, `id_rsa`, etc.)
3. Check the **full path** against directory patterns (`.ssh/`, `.aws/`, etc.)
4. If a match is found, return a `SecretsError` with the specific pattern matched

### Special Command Handling

- **`printenv` with no args** — blocked (dumps all env vars including secrets)
- **`printenv VAR_NAME`** — blocked if `VAR_NAME` matches sensitive env var
  patterns: `*KEY*`, `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*CREDENTIAL*`, `*AUTH*`
- **`download_file`** — `remotePath` checked against the same pattern set in
  `Core.DownloadFile()`

### Configuration

```go
type SecretsConfig struct {
    // AllowedPaths overrides default blocking for specific paths.
    // e.g., [".env.example", "/app/config/credentials.json"]
    AllowedPaths []string `yaml:"allowed_paths"`

    // AdditionalPatterns adds more patterns to the default set.
    AdditionalPatterns []string `yaml:"additional_patterns"`

    // DisablePathCheck disables pre-execution path checking entirely.
    DisablePathCheck bool `yaml:"disable_path_check"`

    // DisableOutputScrub disables post-execution output scrubbing.
    DisableOutputScrub bool `yaml:"disable_output_scrub"`
}
```

Hard block by default. Users can allowlist specific paths if they explicitly
choose to allow access.

## Phase 2: Post-execution Output Scrubbing

Catches secrets that appear in command output — e.g., `grep -r "database"
/app/config/` might return lines containing connection strings with embedded
passwords.

### Patterns (High Confidence — Low False Positive Risk)

| Pattern            | Example                                           | Redacted to                            |
| ------------------ | ------------------------------------------------- | -------------------------------------- |
| AWS Access Key     | `AKIA1234567890ABCDEF`                            | `AKIA***REDACTED***`                   |
| AWS Secret Key     | 40-char base64 after `aws_secret_access_key`      | `***REDACTED***`                       |
| GitHub tokens      | `ghp_xxxx`, `gho_xxxx`, `ghs_xxxx`, `github_pat_` | `ghp_***REDACTED***`                   |
| Stripe/OpenAI keys | `sk-xxxx`, `sk_live_xxxx`, `pk_live_xxxx`         | `sk-***REDACTED***`                    |
| Private key blocks | `-----BEGIN (RSA\|EC\|OPENSSH) PRIVATE KEY-----`  | `***REDACTED_PRIVATE_KEY***`           |
| Bearer tokens      | `Authorization: Bearer xxxx`                      | `Authorization: Bearer ***REDACTED***` |

### Patterns (Medium Confidence — Tightened to Reduce False Positives)

| Pattern                                              | Tightening Heuristic                                                                                                                      |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| JWTs (`eyJ...`)                                      | Require all 3 dot-separated segments to be valid base64 AND total length > 30 chars                                                       |
| Connection strings (`postgresql://user:pass@host`)   | Only redact the password portion between `://user:` and `@`                                                                               |
| Generic key-value (`password=`, `secret=`, `token=`) | Require value portion to look like a secret: min length, mixed case/digits, not a common word. `password_policy=strict` should NOT match. |

### Implementation

`secrets.ScrubOutput(text string) string` applies all compiled regex patterns.
Patterns are compiled once at package init. Output is already capped at 64KB by
the truncation stage, so running ~10-15 compiled regexes is sub-millisecond.

## Integration Points (Changes to Existing Code)

### `shellguard.go`

Add `SecretsConfig` to `Config` struct. Pass it through to `Core`.

### `server/server.go`

Add two function fields to `Core`:

```go
type Core struct {
    // ... existing fields ...
    CheckSecrets func(*parser.Pipeline) error  // default: secrets.CheckPipeline
    ScrubSecrets func(string) string           // default: secrets.ScrubOutput
}
```

Update `Core.Execute()`:

```go
func (c *Core) Execute(ctx context.Context, in ExecuteInput) (output.CommandResult, error) {
    pipeline, err := c.Parse(in.Command)
    // ...
    err = c.Validate(pipeline, c.Registry)
    // ...
    err = c.CheckSecrets(pipeline)               // NEW
    // ...
    cmd := c.Reconstruct(pipeline, ...)
    result := c.Runner.Execute(ctx, host, cmd, timeout)
    truncated := c.Truncate(...)
    // Scrub both stdout and stderr                // NEW
    truncated.Stdout = c.ScrubSecrets(truncated.Stdout)
    truncated.Stderr = c.ScrubSecrets(truncated.Stderr)
    return truncated, nil
}
```

Update `Core.DownloadFile()` to check `remotePath` against secrets patterns.

### No changes to `validator/` or `output/`

Secrets checking is a separate stage, keeping clean separation of concerns.

## Package Layout

```
secrets/
  secrets.go          # Core types, SecretsConfig, constructor, SecretsError
  paths.go            # Sensitive path patterns, CheckPipeline(), CheckPath()
  scrub.go            # Output scrubbing patterns, ScrubOutput()
  paths_test.go       # Path checking unit tests
  scrub_test.go       # Output scrubbing unit tests + false-positive regression
  security_test.go    # Attack vector tests (bypass attempts)
  fuzz_test.go        # Fuzz tests for both path checking and scrubbing
```

## Testing Strategy

Following existing conventions: `testing` only, no testify, `got`/`want`
assertions, `t.Helper()` in helpers.

### Path Tests (`paths_test.go`)

Table-driven tests covering all pattern categories:

- **Blocked:** `cat .env`, `head .ssh/id_rsa`, `grep -r foo credentials.json`,
  `printenv`, `printenv AWS_SECRET_KEY`
- **Allowed:** `cat README.md`, `head main.go`, `printenv PATH`, `printenv HOME`
- **Allowlist override:** `.env.example` in allowed list → `cat .env.example` passes
- **Path normalization:** `../../.env`, `./foo/../.env`, `~/.ssh/id_rsa`

### Scrub Tests (`scrub_test.go`)

Table-driven with input/expected output pairs:

- **Positive:** Each pattern category with realistic examples
- **False-positive regression:** `token_count=5`, `password_policy=strict`,
  `secret_garden.txt`, base64 strings that start with `eyJ` but aren't JWTs

### Security Tests (`security_test.go`)

`TestSec_` prefix. Bypass attempts:

- Path traversal: `../../.env`, `/app/../../../etc/shadow`
- Encoding tricks: URL-encoded paths, unicode homoglyphs
- Indirect access: `find / -name .env`, `grep -rl password /etc/`
- Argument hiding: flags that take path values (`grep -f .env foo.txt`)

### Fuzz Tests (`fuzz_test.go`)

- `FuzzCheckPath` — random strings never panic, always return valid error or nil
- `FuzzScrubOutput` — random input never panics, output length ≤ input length +
  redaction marker overhead

### Cross-layer Tests (`security_pipeline_test.go`)

Add cases to existing test file:

- `cat .env` → rejected
- `cat README.md` → allowed
- `printenv` (bare) → rejected
- `printenv PATH` → allowed
- `head .aws/credentials` → rejected

## Resolved Questions

1. **`grep -f .env`** — **Yes, check all flag values against sensitive path
   patterns.** Any flag value matching a sensitive pattern gets blocked. This is
   simple and catches `grep -f .env`, `xargs --arg-file=.env`, etc. False
   positives are rare since most flag values are format strings, counts, etc.

2. **Symlinks** — **Accepted limitation, documented.** We cannot resolve symlinks
   before execution since the file is on a remote host. The heuristic only
   checks the path string as written. Defense-in-depth comes from the output
   scrubbing phase, which catches secrets regardless of how they were accessed.

3. **`find -name .env`** — **Yes, check `-name` and `-iname` flag values against
   sensitive filename patterns.** While `find` doesn't read secrets directly, it
   reveals their locations to the LLM. Blocking discovery of sensitive filenames
   prevents the LLM from learning where secrets live and then accessing them
   with a follow-up command.
