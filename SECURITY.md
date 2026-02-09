# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use [GitHub's private vulnerability reporting](https://github.com/jonchun/shellguard/security/advisories/new)
to submit a report. If that is unavailable, email **git@jonathanchun.com** with
the subject line `[ShellGuard Security]`.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- The version or commit hash you tested against

You should receive an acknowledgment within 72 hours. Once the issue is
confirmed, a fix will be developed privately and released as soon as practical.
Credit will be given unless you prefer to remain anonymous.

Please practice responsible disclosure: allow a reasonable window for a fix
before publishing details publicly.

## Supported Versions

Only the latest release on the `main` branch receives security updates.
There is no backport policy for older versions.

## Threat Model and Design Philosophy

ShellGuard is designed for a specific context: it sits between an LLM (via MCP)
and a remote host where the LLM has been prompted to operate in read-only,
diagnostic mode. The LLM is already instructed not to take destructive actions.
ShellGuard exists as a **fail-safe** -- a guardrail that catches mistakes, not a
fortress designed to withstand a dedicated adversary with direct access to the
tool.

In normal operation, the LLM cooperates with the security policy. It will not
attempt to `rm -rf /` or exfiltrate data because its system prompt tells it not
to. ShellGuard's job is to enforce that contract mechanically so that prompt
injection, model misbehavior, or accidental misuse cannot silently escalate into
destructive actions. Think of it as a seatbelt, not an armored vehicle.

**What ShellGuard is designed to stop:**

- An LLM that has been prompt-injected into running destructive commands
- Accidental execution of dangerous operations during legitimate diagnostics
- Shell injection through malformed or adversarial input strings
- Escalation from read-only diagnostics to write operations

**What ShellGuard does not claim to stop:**

- A skilled human attacker with direct access to the MCP tool who is
  deliberately crafting bypass attempts. The allowlist and parser are thorough
  but not formally verified.
- Information disclosure through allowed read-only commands (this is by design
  -- diagnostics require reading system state)
- Attacks that operate entirely within the bounds of allowed commands (e.g.,
  reading sensitive files with `cat`, querying metadata endpoints with `curl`)

The security model is defense-in-depth: multiple independent layers each reduce
risk, but no single layer is assumed to be impenetrable.

## Security Model Overview

ShellGuard gates shell command execution on remote hosts through a four-stage
defense-in-depth pipeline. Every command must pass all four stages sequentially;
a failure at any stage blocks execution entirely.

```
Input ─► Parse ─► Validate ─► Reconstruct ─► Execute
```

### Stage 1 -- Parse

The parser (`parser/`) converts raw shell input into a structured AST using
[mvdan.cc/sh/v3](https://github.com/mvdan/sh), a proper bash parser -- not
regex. It enforces hard limits (64 KB input, 32 pipe segments, 1024 args per
segment) and rejects dangerous shell constructs at the syntax level:

- Command substitution (`$(...)`, `` `...` ``)
- Variable expansion (`$HOME`, `${VAR}`)
- Process substitution (`<(...)`, `>(...)`)
- Arithmetic expansion (`$((...))`)
- Redirections (`>`, `>>`, `<`, `2>&1`)
- Background execution (`&`)
- Control flow (`if`, `while`, `for`, `case`)
- Function definitions, subshells, brace groups
- Multi-statement input (`;` as statement separator)
- Extended globs, brace expansion

Only simple commands connected by `|`, `&&`, or `||` are accepted.

### Stage 2 -- Validate

The validator (`validator/`) checks every parsed pipeline segment against a
YAML-based command registry using **default-deny** semantics. A command must be
explicitly allowlisted to execute. Currently 84 commands are allowed and 95 are
explicitly denied with human-readable reasons.

Key behaviors:

- Individual flags are validated per command. Denied flags include a reason.
- `sudo` is restricted to `sudo [-u user] <command>` with recursive validation
  of the inner command. All other sudo flags are rejected.
- `xargs` requires a pipe and recursively validates its inner command.
- Subcommands (e.g., `docker ps`, `kubectl get`, `aws ec2 describe-instances`)
  are resolved to composite manifest keys.
- SQL passed to `psql -c` is validated: only `SELECT`, `EXPLAIN`, `SHOW`,
  `WITH` (read-only CTEs), and psql backslash commands are allowed.
- Path arguments are normalized and checked against per-command restricted paths.
- Glob patterns in positional arguments are rejected unless explicitly allowed.

### Stage 3 -- Reconstruct

The reconstructor (`ssh/`) rebuilds the validated pipeline into a safe shell
command string. `ShellQuote` is the critical security boundary: every token that
is not strictly alphanumeric plus a small safe character set is wrapped in
single quotes with proper escaping. This neutralizes any shell metacharacters
that might have passed through as literal argument values.

Pipeline operators (`|`, `&&`, `||`) are inserted verbatim between segments.
This is a deliberate trust boundary -- reconstruction trusts the parser to have
produced only safe operators.

### Stage 4 -- Execute

The reconstructed command is sent to the remote host over SSH. Output is
truncated at 64 KB (75% head / 25% tail split) to prevent unbounded responses.

## Known Security Boundaries and Accepted Risks

### SSRF via curl

`curl` is allowed with a GET-only policy (write methods like `-X POST`, `-d`,
`--data`, `-T` are denied). However, there is no URL validation. An LLM client
could be manipulated into constructing requests to internal endpoints:

- Cloud metadata services (e.g., `http://169.254.169.254/`)
- Internal services on `localhost` or private IP ranges

The mitigation is that command substitution is blocked, so URLs cannot be
dynamically constructed from host data. The risk of LLM-directed SSRF remains.

### Environment variable disclosure

`printenv` and `cat /proc/self/environ` are allowed by design for diagnostics.
These can expose database credentials, API keys, and other secrets stored in
environment variables.

### Operator trust boundary

The `Operator` field in pipeline segments is inserted into reconstructed
commands without quoting. Reconstruction trusts the parser to produce only `|`,
`&&`, or `||`. If the `Pipeline` struct were mutated between validation and
reconstruction, arbitrary operators could be injected. No immutability
enforcement exists on the struct (TOCTOU gap), but in practice the struct is
created and consumed within a single synchronous call path.

### Parser-reconstructor cross-layer dependency

The parser strips quotes and normalizes tokens to their semantic values. If a
double-quoted string containing `$(cmd)` reaches the parser, it is preserved as
a literal string (the parser does not reject it in all code paths for
double-quoted content). The reconstructor's single-quoting neutralizes this, but
it represents a defense-in-depth dependency rather than independent rejection.

### Docker format strings

`docker inspect --format` accepts arbitrary Go templates, which can call
built-in template functions. This is constrained to read-only inspection but
could be used to extract information in unexpected ways.

## SSH Host Key Verification

ShellGuard supports three host key verification modes:

| Mode | Behavior |
|------|----------|
| `accept-new` (default) | Trust-on-first-use. Accept unknown hosts on first connection, reject changed keys on subsequent connections. |
| `strict` | Require the host key to already exist in `known_hosts`. Reject unknown hosts. |
| `off` | Disable host key verification entirely. **Not recommended.** |

The default `accept-new` mode provides TOFU (Trust-On-First-Use) security,
which protects against MITM attacks after the initial connection but not during
the first connection to an unknown host. For environments where host keys can be
pre-distributed, `strict` mode is recommended.

Known host keys are persisted to a `known_hosts` file and checked on subsequent
connections. A mismatch between a stored key and the key presented by the server
will reject the connection with a `HostKeyError`.

## Security Testing

ShellGuard maintains dedicated security test suites across all pipeline stages:

| Test file | Scope |
|-----------|-------|
| `parser/security_test.go` | 40 attack vector categories against the parser |
| `validator/attack_vectors_test.go` | 20 attack vector categories against the validator |
| `ssh/reconstruct_security_test.go` | 20 attack vector categories against ShellQuote and reconstruction |
| `security_pipeline_test.go` | 19 cross-layer test groups exercising the full pipeline end-to-end |
| `ssh/hostkey_security_test.go` | Host key verification security scenarios |

Attack vectors tested include: shell injection, command substitution bypass,
variable expansion, null byte injection, Unicode homoglyphs and control
characters, sudo escalation, SQL injection through psql, subcommand confusion,
flag smuggling, path traversal, TOCTOU operator injection, and resource
exhaustion.

Fuzz tests (`parser/fuzz_test.go`, `ssh/fuzz_test.go`) run with rich seed
corpora covering normal inputs, attack payloads, edge cases, and Unicode. Fuzz
invariants include non-empty segments, valid operators, balanced quoting,
idempotent `ShellQuote`, and round-trip consistency.
