# Secrets Protection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add local heuristic-based secrets protection that blocks sensitive file access pre-execution and scrubs known secret patterns from output post-execution.

**Architecture:** New standalone `secrets` package with two function fields on `Core` (`CheckSecrets`, `ScrubSecrets`). Path checking runs between Validate and Reconstruct. Output scrubbing runs after Truncate. Config wired through `config.Config` -> `server.CoreOption`.

**Tech Stack:** Go stdlib only (regexp, path, strings). No new dependencies.

---

### Task 1: Create `secrets` package — types and error

**Files:**

- Create: `secrets/secrets.go`

**Step 1: Write the failing test**

Create `secrets/secrets_test.go`:

```go
package secrets

import (
	"testing"
)

func TestSecretsError(t *testing.T) {
	err := &SecretsError{Message: "access to '.env' is blocked"}
	if got, want := err.Error(), "access to '.env' is blocked"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestNewChecker_Defaults(t *testing.T) {
	c := NewChecker(Config{})
	if c == nil {
		t.Fatal("NewChecker returned nil")
	}
}

func TestNewChecker_DisablePathCheck(t *testing.T) {
	c := NewChecker(Config{DisablePathCheck: true})
	// Should not error on a sensitive path when disabled
	if err := c.CheckPath(".env"); err != nil {
		t.Fatalf("CheckPath with disabled check: got error %v, want nil", err)
	}
}

func TestNewChecker_DisableOutputScrub(t *testing.T) {
	c := NewChecker(Config{DisableOutputScrub: true})
	input := "AKIAIOSFODNN7EXAMPLE"
	if got := c.ScrubOutput(input); got != input {
		t.Fatalf("ScrubOutput with disabled scrub = %q, want %q", got, input)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./secrets/ -run TestSecretsError -count=1`
Expected: FAIL (package doesn't exist)

**Step 3: Write minimal implementation**

Create `secrets/secrets.go`:

```go
// Package secrets provides local heuristic-based protection against
// sensitive file access and secret leakage. It blocks commands that
// reference sensitive files and scrubs known secret patterns from output.
//
// Symlink-based bypasses are out of scope: we cannot resolve symlinks on
// a remote host without executing a command. Defense-in-depth comes from
// the output scrubbing phase, which catches secrets regardless of how
// they were accessed.
package secrets

import (
	"github.com/jonchun/shellguard/parser"
)

// SecretsError is returned when a command references a sensitive path
// or environment variable.
type SecretsError struct {
	Message string
}

func (e *SecretsError) Error() string { return e.Message }

// Config controls secrets protection behavior.
type Config struct {
	// AllowedPaths overrides default blocking for specific paths.
	// e.g., [".env.example", "/app/config/credentials.json"]
	AllowedPaths []string

	// AdditionalPatterns adds more basename patterns to the default set.
	AdditionalPatterns []string

	// DisablePathCheck disables pre-execution path checking entirely.
	DisablePathCheck bool

	// DisableOutputScrub disables post-execution output scrubbing.
	DisableOutputScrub bool
}

// Checker performs secrets protection checks.
type Checker struct {
	cfg            Config
	allowedPathSet map[string]struct{}
}

// NewChecker creates a Checker with the given config.
func NewChecker(cfg Config) *Checker {
	allowed := make(map[string]struct{}, len(cfg.AllowedPaths))
	for _, p := range cfg.AllowedPaths {
		allowed[p] = struct{}{}
	}
	return &Checker{
		cfg:            cfg,
		allowedPathSet: allowed,
	}
}

// CheckPipeline checks all segments in a pipeline for sensitive path access.
// Returns a SecretsError if any argument references a sensitive file.
func (c *Checker) CheckPipeline(pipeline *parser.Pipeline) error {
	if c.cfg.DisablePathCheck {
		return nil
	}
	for _, seg := range pipeline.Segments {
		if err := c.checkSegment(seg); err != nil {
			return err
		}
	}
	return nil
}

// CheckPath checks a single path string against sensitive patterns.
// Used by download_file and other direct path checks.
func (c *Checker) CheckPath(p string) error {
	if c.cfg.DisablePathCheck {
		return nil
	}
	return c.matchPath(p)
}

// ScrubOutput redacts known secret patterns from text.
// Returns the text with secrets replaced by redaction markers.
func (c *Checker) ScrubOutput(text string) string {
	if c.cfg.DisableOutputScrub {
		return text
	}
	return scrubOutput(text)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./secrets/ -count=1`
Expected: PASS (after adding stub methods in next tasks)

**Step 5: Commit**

```bash
git add secrets/
git commit -m "feat(secrets): add package skeleton with types, config, and Checker"
```

---

### Task 2: Implement sensitive path matching

**Files:**

- Create: `secrets/paths.go`
- Create: `secrets/paths_test.go`

**Step 1: Write the failing tests**

Create `secrets/paths_test.go`:

```go
package secrets

import (
	"testing"

	"github.com/jonchun/shellguard/parser"
)

func TestCheckPath_EnvFiles(t *testing.T) {
	c := NewChecker(Config{})
	cases := []struct {
		path    string
		blocked bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.production", true},
		{"/app/.env", true},
		{"../../.env", true},
		{"./foo/../.env", true},
		{".envrc", false},            // not .env pattern
		{".environment", false},      // not .env pattern
		{"env", false},               // no dot prefix
		{"README.md", false},
		{"main.go", false},
	}
	for _, tc := range cases {
		err := c.CheckPath(tc.path)
		if tc.blocked && err == nil {
			t.Errorf("CheckPath(%q): expected block, got nil", tc.path)
		}
		if !tc.blocked && err != nil {
			t.Errorf("CheckPath(%q): expected allow, got %v", tc.path, err)
		}
	}
}

func TestCheckPath_SSHKeys(t *testing.T) {
	c := NewChecker(Config{})
	cases := []struct {
		path    string
		blocked bool
	}{
		{".ssh/id_rsa", true},
		{".ssh/id_ed25519", true},
		{".ssh/id_ecdsa", true},
		{".ssh/authorized_keys", true},
		{".ssh/known_hosts", true},
		{"/home/user/.ssh/id_rsa", true},
		{".ssh/config", false},  // ssh config is not a secret
	}
	for _, tc := range cases {
		err := c.CheckPath(tc.path)
		if tc.blocked && err == nil {
			t.Errorf("CheckPath(%q): expected block, got nil", tc.path)
		}
		if !tc.blocked && err != nil {
			t.Errorf("CheckPath(%q): expected allow, got %v", tc.path, err)
		}
	}
}

func TestCheckPath_TLSCerts(t *testing.T) {
	c := NewChecker(Config{})
	blocked := []string{"server.key", "cert.pem", "keystore.pfx", "cert.p12"}
	for _, p := range blocked {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("CheckPath(%q): expected block, got nil", p)
		}
	}
	// .crt files are public certificates, not secrets
	if err := c.CheckPath("server.crt"); err != nil {
		t.Errorf("CheckPath(server.crt): expected allow, got %v", err)
	}
}

func TestCheckPath_CloudCredentials(t *testing.T) {
	c := NewChecker(Config{})
	blocked := []string{
		".aws/credentials",
		".aws/config",
		"/home/user/.aws/credentials",
		".kube/config",
		".docker/config.json",
		".config/gcloud/credentials.db",
		".config/gcloud/application_default_credentials.json",
	}
	for _, p := range blocked {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("CheckPath(%q): expected block, got nil", p)
		}
	}
}

func TestCheckPath_AppCredentials(t *testing.T) {
	c := NewChecker(Config{})
	blocked := []string{
		"credentials.json",
		"service-account.json",
		"service-account-key.json",
		".netrc",
		".pgpass",
		".my.cnf",
		".git-credentials",
	}
	for _, p := range blocked {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("CheckPath(%q): expected block, got nil", p)
		}
	}
}

func TestCheckPath_SystemFiles(t *testing.T) {
	c := NewChecker(Config{})
	blocked := []string{"/etc/shadow", "/etc/gshadow", "/etc/master.passwd"}
	for _, p := range blocked {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("CheckPath(%q): expected block, got nil", p)
		}
	}
}

func TestCheckPath_AllowedPaths(t *testing.T) {
	c := NewChecker(Config{
		AllowedPaths: []string{".env.example", "/app/credentials.json"},
	})
	// These should be allowed because they're in the allowlist
	allowed := []string{".env.example", "/app/credentials.json"}
	for _, p := range allowed {
		if err := c.CheckPath(p); err != nil {
			t.Errorf("CheckPath(%q) with allowlist: expected allow, got %v", p, err)
		}
	}
	// Regular sensitive files should still be blocked
	if err := c.CheckPath(".env"); err == nil {
		t.Error("CheckPath(.env) with unrelated allowlist: expected block, got nil")
	}
}

func TestCheckPath_PathNormalization(t *testing.T) {
	c := NewChecker(Config{})
	// All of these should resolve to .env and be blocked
	blocked := []string{
		"../../.env",
		"./foo/../.env",
		"foo/bar/../../.env",
		"/app/config/../.env",
	}
	for _, p := range blocked {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("CheckPath(%q): expected block after normalization, got nil", p)
		}
	}
}

func TestCheckPipeline_BasicCommands(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name    string
		command string
		args    []string
		blocked bool
	}{
		{"cat .env", "cat", []string{".env"}, true},
		{"cat README.md", "cat", []string{"README.md"}, false},
		{"head .ssh/id_rsa", "head", []string{".ssh/id_rsa"}, true},
		{"grep pattern .env", "grep", []string{"-i", "pattern", ".env"}, true},
		{"grep pattern file.txt", "grep", []string{"-i", "pattern", "file.txt"}, false},
		{"grep -f .env file.txt", "grep", []string{"-f", ".env", "file.txt"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: tc.command, Args: tc.args},
			}}
			err := c.CheckPipeline(p)
			if tc.blocked && err == nil {
				t.Errorf("expected block, got nil")
			}
			if !tc.blocked && err != nil {
				t.Errorf("expected allow, got %v", err)
			}
		})
	}
}

func TestCheckPipeline_Printenv(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name    string
		args    []string
		blocked bool
	}{
		{"bare printenv", nil, true},
		{"printenv PATH", []string{"PATH"}, false},
		{"printenv HOME", []string{"HOME"}, false},
		{"printenv AWS_SECRET_KEY", []string{"AWS_SECRET_KEY"}, true},
		{"printenv DATABASE_PASSWORD", []string{"DATABASE_PASSWORD"}, true},
		{"printenv API_TOKEN", []string{"API_TOKEN"}, true},
		{"printenv AUTH_KEY", []string{"AUTH_KEY"}, true},
		{"printenv MY_CREDENTIAL", []string{"MY_CREDENTIAL"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "printenv", Args: tc.args},
			}}
			err := c.CheckPipeline(p)
			if tc.blocked && err == nil {
				t.Errorf("expected block, got nil")
			}
			if !tc.blocked && err != nil {
				t.Errorf("expected allow, got %v", err)
			}
		})
	}
}

func TestCheckPipeline_FindName(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name    string
		args    []string
		blocked bool
	}{
		{"find -name .env", []string{"/", "-name", ".env"}, true},
		{"find -iname .env", []string{"/", "-iname", ".env"}, true},
		{"find -name id_rsa", []string{"/", "-name", "id_rsa"}, true},
		{"find -name README.md", []string{"/", "-name", "README.md"}, false},
		{"find -type f", []string{"/", "-type", "f"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "find", Args: tc.args},
			}}
			err := c.CheckPipeline(p)
			if tc.blocked && err == nil {
				t.Errorf("expected block, got nil")
			}
			if !tc.blocked && err != nil {
				t.Errorf("expected allow, got %v", err)
			}
		})
	}
}

func TestCheckPath_AdditionalPatterns(t *testing.T) {
	c := NewChecker(Config{
		AdditionalPatterns: []string{"*.secret", "vault-token"},
	})
	if err := c.CheckPath("app.secret"); err == nil {
		t.Error("CheckPath(app.secret) with additional pattern: expected block, got nil")
	}
	if err := c.CheckPath("vault-token"); err == nil {
		t.Error("CheckPath(vault-token) with additional pattern: expected block, got nil")
	}
	// Regular files still allowed
	if err := c.CheckPath("README.md"); err != nil {
		t.Errorf("CheckPath(README.md): expected allow, got %v", err)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./secrets/ -run TestCheckPath -count=1`
Expected: FAIL (matchPath, checkSegment not implemented)

**Step 3: Write implementation**

Create `secrets/paths.go`:

```go
package secrets

import (
	"fmt"
	"path"
	"strings"

	"github.com/jonchun/shellguard/parser"
)

// sensitiveBasenames are exact filename matches checked against path.Base().
var sensitiveBasenames = map[string]struct{}{
	".env":            {},
	".netrc":          {},
	".pgpass":         {},
	".my.cnf":         {},
	".git-credentials": {},
	".gitconfig":      {},
	"credentials.json": {},
	"shadow":          {},
	"gshadow":         {},
	"master.passwd":   {},
}

// sensitiveBasePrefixes are checked with strings.HasPrefix on the basename.
var sensitiveBasePrefixes = []string{
	".env.",               // .env.local, .env.production, etc.
	"service-account",     // service-account.json, service-account-key.json
}

// sensitiveBaseExtensions are checked against the file extension.
var sensitiveBaseExtensions = map[string]struct{}{
	".pem": {},
	".key": {},
	".pfx": {},
	".p12": {},
}

// sensitivePathPrefixes are checked with strings.HasPrefix on the cleaned full path.
// These catch directory-based patterns like .aws/credentials.
var sensitivePathPrefixes = []string{
	".ssh/id_",
	".ssh/authorized_keys",
	".ssh/known_hosts",
	".aws/",
	".kube/config",
	".docker/config.json",
	".config/gcloud/",
	".azure/",
}

// sensitiveAbsolutePaths are checked with exact match or prefix match.
var sensitiveAbsolutePaths = []string{
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/master.passwd",
}

// sensitiveEnvVarSubstrings are checked against env var names (case-insensitive).
// Used to block `printenv SECRET_KEY` style access.
var sensitiveEnvVarSubstrings = []string{
	"KEY",
	"SECRET",
	"TOKEN",
	"PASSWORD",
	"CREDENTIAL",
	"AUTH",
}

// findNameFlags are find flags whose values should be checked against sensitive
// filename patterns.
var findNameFlags = map[string]struct{}{
	"-name":  {},
	"-iname": {},
}

// checkSegment checks a single pipeline segment for sensitive path access.
func (c *Checker) checkSegment(seg parser.PipelineSegment) error {
	// Special case: printenv
	if seg.Command == "printenv" {
		return c.checkPrintenv(seg.Args)
	}

	// Special case: find -name / -iname
	if seg.Command == "find" {
		if err := c.checkFindArgs(seg.Args); err != nil {
			return err
		}
	}

	// Check all args (both positional and flag values) against sensitive patterns
	for _, arg := range seg.Args {
		if err := c.matchPath(arg); err != nil {
			return err
		}
	}
	return nil
}

// checkPrintenv validates printenv commands.
// Bare printenv (no args) is blocked because it dumps all env vars.
// printenv with a sensitive var name pattern is blocked.
func (c *Checker) checkPrintenv(args []string) error {
	if len(args) == 0 {
		return &SecretsError{
			Message: "bare 'printenv' is blocked: it dumps all environment variables which may contain secrets. Use 'printenv VAR_NAME' for specific variables.",
		}
	}
	for _, arg := range args {
		upper := strings.ToUpper(arg)
		for _, sub := range sensitiveEnvVarSubstrings {
			if strings.Contains(upper, sub) {
				return &SecretsError{
					Message: fmt.Sprintf("access to environment variable '%s' is blocked: variable name matches sensitive pattern '%s'.", arg, sub),
				}
			}
		}
	}
	return nil
}

// checkFindArgs checks find's -name/-iname values against sensitive filename patterns.
func (c *Checker) checkFindArgs(args []string) error {
	for i, arg := range args {
		if _, ok := findNameFlags[arg]; ok && i+1 < len(args) {
			nameVal := args[i+1]
			if err := c.matchFilename(nameVal); err != nil {
				return &SecretsError{
					Message: fmt.Sprintf("find %s '%s' is blocked: searching for sensitive filenames reveals secret locations.", arg, nameVal),
				}
			}
		}
	}
	return nil
}

// matchPath checks a path string against all sensitive patterns.
func (c *Checker) matchPath(p string) error {
	cleaned := path.Clean(p)
	basename := path.Base(cleaned)

	// Check allowlist first (exact match on cleaned path or basename)
	if _, ok := c.allowedPathSet[cleaned]; ok {
		return nil
	}
	if _, ok := c.allowedPathSet[basename]; ok {
		return nil
	}
	// Also check the original (un-cleaned) path against allowlist
	if _, ok := c.allowedPathSet[p]; ok {
		return nil
	}

	// Check absolute paths
	for _, abs := range sensitiveAbsolutePaths {
		if cleaned == abs || strings.HasPrefix(cleaned, abs+"/") {
			return &SecretsError{
				Message: fmt.Sprintf("access to '%s' is blocked: matches sensitive path pattern.", p),
			}
		}
	}

	// Check directory-based patterns (match anywhere in path)
	for _, prefix := range sensitivePathPrefixes {
		if strings.HasSuffix(cleaned, "/"+prefix) || strings.Contains(cleaned, "/"+prefix) || strings.HasPrefix(cleaned, prefix) {
			return &SecretsError{
				Message: fmt.Sprintf("access to '%s' is blocked: matches sensitive path pattern.", p),
			}
		}
	}

	// Check basename patterns
	if err := c.matchFilename(basename); err != nil {
		return &SecretsError{
			Message: fmt.Sprintf("access to '%s' is blocked: matches sensitive filename pattern.", p),
		}
	}

	return nil
}

// matchFilename checks a filename against sensitive basename patterns.
// Returns non-nil if the filename matches a sensitive pattern.
func (c *Checker) matchFilename(name string) error {
	// Exact basename match
	if _, ok := sensitiveBasenames[name]; ok {
		return &SecretsError{Message: name}
	}

	// Prefix match (e.g., .env.local)
	for _, prefix := range sensitiveBasePrefixes {
		if strings.HasPrefix(name, prefix) {
			return &SecretsError{Message: name}
		}
	}

	// Extension match (e.g., .pem, .key)
	ext := path.Ext(name)
	if _, ok := sensitiveBaseExtensions[ext]; ok {
		return &SecretsError{Message: name}
	}

	// Additional user-configured patterns
	for _, pattern := range c.cfg.AdditionalPatterns {
		if matchGlobPattern(name, pattern) {
			return &SecretsError{Message: name}
		}
	}

	return nil
}

// matchGlobPattern performs simple glob matching supporting only * wildcards.
// *.secret matches foo.secret; vault-* matches vault-token.
func matchGlobPattern(name, pattern string) bool {
	if !strings.Contains(pattern, "*") {
		return name == pattern
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(name, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, pattern[:len(pattern)-1])
	}
	// Middle wildcard: split on first *
	parts := strings.SplitN(pattern, "*", 2)
	return strings.HasPrefix(name, parts[0]) && strings.HasSuffix(name, parts[1])
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./secrets/ -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add secrets/
git commit -m "feat(secrets): implement sensitive path matching with allowlist"
```

---

### Task 3: Implement output scrubbing

**Files:**

- Create: `secrets/scrub.go`
- Create: `secrets/scrub_test.go`

**Step 1: Write the failing tests**

Create `secrets/scrub_test.go`:

```go
package secrets

import (
	"strings"
	"testing"
)

func TestScrubOutput_AWSAccessKey(t *testing.T) {
	c := NewChecker(Config{})
	input := "key=AKIAIOSFODNN7EXAMPLE"
	got := c.ScrubOutput(input)
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS access key not redacted: %q", got)
	}
	if !strings.Contains(got, "AKIA") {
		t.Fatal("redacted output should preserve AKIA prefix")
	}
}

func TestScrubOutput_AWSSecretKey(t *testing.T) {
	c := NewChecker(Config{})
	input := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	got := c.ScrubOutput(input)
	if strings.Contains(got, "wJalrXUtnFEMI") {
		t.Fatalf("AWS secret key not redacted: %q", got)
	}
}

func TestScrubOutput_GitHubToken(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name  string
		input string
	}{
		{"ghp", "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678"},
		{"gho", "token=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678"},
		{"ghs", "token=ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678"},
		{"github_pat", "token=github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabc"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ScrubOutput(tc.input)
			prefix := tc.input[6:10] // extract prefix like ghp_
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("GitHub token not redacted: %q", got)
			}
			_ = prefix
		})
	}
}

func TestScrubOutput_GenericAPIKey(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name  string
		input string
	}{
		// NOTE: test values use "FAKE" prefix to avoid push protection false positives.
		// Real implementation should use values that match the actual key format.
		{"sk-prefix", `key=sk-` + strings.Repeat("x", 30)},
		{"sk_live_prefix", `key=sk_live` + "_" + strings.Repeat("x", 30)},
		{"pk_live_prefix", `key=pk_live` + "_" + strings.Repeat("x", 30)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ScrubOutput(tc.input)
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("API key not redacted: %q", got)
			}
		})
	}
}

func TestScrubOutput_PrivateKeyBlock(t *testing.T) {
	c := NewChecker(Config{})
	input := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU4n2tCAr6WECn3ByOlMacCOo6EUg6H2HhAqAZj5bN6/AVIupMfn
-----END RSA PRIVATE KEY-----`
	got := c.ScrubOutput(input)
	if strings.Contains(got, "MIIEpAIBAAK") {
		t.Fatalf("private key not redacted: %q", got)
	}
	if !strings.Contains(got, "REDACTED_PRIVATE_KEY") {
		t.Fatalf("expected REDACTED_PRIVATE_KEY marker in output: %q", got)
	}
}

func TestScrubOutput_BearerToken(t *testing.T) {
	c := NewChecker(Config{})
	input := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	got := c.ScrubOutput(input)
	if strings.Contains(got, "eyJhbGci") {
		t.Fatalf("bearer token not redacted: %q", got)
	}
}

func TestScrubOutput_ConnectionString(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name  string
		input string
	}{
		{"postgres", "DATABASE_URL=postgresql://admin:supersecret123@db.example.com:5432/mydb"},
		{"mysql", "MYSQL_URL=mysql://root:p4ssw0rd@localhost:3306/app"},
		{"mongodb", "MONGO_URL=mongodb://user:hunter2@mongo.example.com:27017/admin"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ScrubOutput(tc.input)
			// The password should be redacted but the rest of the URL preserved
			if !strings.Contains(got, "REDACTED") {
				t.Fatalf("connection string password not redacted: %q", got)
			}
		})
	}
}

func TestScrubOutput_KeyValueSecrets(t *testing.T) {
	c := NewChecker(Config{})
	tests := []struct {
		name    string
		input   string
		redact  bool
	}{
		{"password with secret value", "password=Xk9#mP2$vL7nQ", true},
		{"secret with long value", "secret=aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u", true},
		{"password_policy not redacted", "password_policy=strict", false},
		{"token_count not redacted", "token_count=5", false},
		{"password_length not redacted", "password_length=16", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ScrubOutput(tc.input)
			hasRedacted := strings.Contains(got, "REDACTED")
			if tc.redact && !hasRedacted {
				t.Fatalf("expected redaction in %q, got %q", tc.input, got)
			}
			if !tc.redact && hasRedacted {
				t.Fatalf("false positive: %q was redacted to %q", tc.input, got)
			}
		})
	}
}

func TestScrubOutput_JWT(t *testing.T) {
	c := NewChecker(Config{})
	// Valid JWT structure (3 base64 segments, long enough)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	got := c.ScrubOutput(jwt)
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("JWT not redacted: %q", got)
	}
}

func TestScrubOutput_FalsePositiveRegression(t *testing.T) {
	c := NewChecker(Config{})
	// These should NOT be redacted
	safe := []string{
		"token_count=5",
		"password_policy=strict",
		"max_secret_length=256",
		"no secrets here, just normal text",
		"HOSTNAME=ip-172-31-0-1",
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	for _, input := range safe {
		got := c.ScrubOutput(input)
		if got != input {
			t.Errorf("false positive: %q was changed to %q", input, got)
		}
	}
}

func TestScrubOutput_NoChange(t *testing.T) {
	c := NewChecker(Config{})
	input := "total 42\ndrwxr-xr-x 5 root root 4096 Jan 1 00:00 .\ndrwxr-xr-x 3 root root 4096 Jan 1 00:00 .."
	got := c.ScrubOutput(input)
	if got != input {
		t.Fatalf("clean output was modified:\ngot:  %q\nwant: %q", got, input)
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./secrets/ -run TestScrub -count=1`
Expected: FAIL (scrubOutput not implemented)

**Step 3: Write implementation**

Create `secrets/scrub.go`:

```go
package secrets

import (
	"regexp"
	"strings"
)

// Compiled regex patterns for secret detection.
// Patterns are ordered from most specific (lowest false positive) to least.
var scrubPatterns []scrubPattern

type scrubPattern struct {
	re          *regexp.Regexp
	replacement string
	name        string
}

func init() {
	scrubPatterns = []scrubPattern{
		// Private key blocks (multi-line)
		{
			re:          regexp.MustCompile(`(?s)-----BEGIN[A-Z\s]*PRIVATE KEY-----.*?-----END[A-Z\s]*PRIVATE KEY-----`),
			replacement: "***REDACTED_PRIVATE_KEY***",
			name:        "private_key",
		},
		// AWS Access Key IDs: AKIA followed by exactly 16 alphanumeric chars
		{
			re:          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			replacement: "AKIA***REDACTED***",
			name:        "aws_access_key",
		},
		// AWS Secret Access Keys: 40-char base64 string after known key names
		{
			re:          regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
			replacement: "${1}=***REDACTED***",
			name:        "aws_secret_key",
		},
		// GitHub tokens: ghp_, gho_, ghs_, ghu_, github_pat_
		{
			re:          regexp.MustCompile(`(ghp_|gho_|ghs_|ghu_|github_pat_)[A-Za-z0-9_]{20,}`),
			replacement: "***REDACTED_GITHUB_TOKEN***",
			name:        "github_token",
		},
		// Stripe / OpenAI style keys: sk_live_, pk_live_, sk-proj-, sk-
		{
			re:          regexp.MustCompile(`(sk_live_|pk_live_|rk_live_|sk-proj-|sk-)[A-Za-z0-9_-]{20,}`),
			replacement: "***REDACTED_API_KEY***",
			name:        "api_key",
		},
		// Bearer token in Authorization header
		{
			re:          regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)\S{20,}`),
			replacement: "${1}***REDACTED***",
			name:        "bearer_token",
		},
		// Connection strings with embedded passwords: scheme://user:pass@host
		{
			re:          regexp.MustCompile(`((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:]+:)([^@]{3,})(@)`),
			replacement: "${1}***REDACTED***${3}",
			name:        "connection_string",
		},
		// JWTs: three dot-separated base64url segments, total > 30 chars
		{
			re:          regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			replacement: "***REDACTED_JWT***",
			name:        "jwt",
		},
		// Generic key-value secrets: password=, secret=, token=, api_key=
		// Only match values that look like secrets (min 8 chars, mixed charset)
		{
			re:          regexp.MustCompile(`(?i)\b(password|secret|api_key|apikey|access_token|auth_token|private_key)\s*[=:]\s*(\S{8,})`),
			replacement: "${1}=***REDACTED***",
			name:        "key_value",
		},
	}
}

// scrubOutput applies all compiled regex patterns to redact secrets.
func scrubOutput(text string) string {
	result := text
	for _, p := range scrubPatterns {
		if p.name == "key_value" {
			result = p.re.ReplaceAllStringFunc(result, func(match string) string {
				return scrubKeyValue(match, p.re)
			})
		} else {
			result = p.re.ReplaceAllString(result, p.replacement)
		}
	}
	return result
}

// scrubKeyValue applies extra heuristics to key-value matches to reduce
// false positives. Only redacts if the value looks like an actual secret
// (not a common word or simple number).
func scrubKeyValue(match string, re *regexp.Regexp) string {
	subs := re.FindStringSubmatch(match)
	if len(subs) < 3 {
		return match
	}
	value := subs[2]

	// Skip if the value is a common non-secret word
	if isCommonWord(value) {
		return match
	}

	// Skip if the value is all digits (likely a count, port, etc.)
	if isAllDigits(value) {
		return match
	}

	// Skip if the value has no mixed charset (all lowercase, all uppercase)
	// Real secrets almost always have mixed chars
	if !hasMixedCharset(value) {
		return match
	}

	return re.ReplaceAllString(match, "${1}=***REDACTED***")
}

func isCommonWord(s string) bool {
	common := map[string]struct{}{
		"true": {}, "false": {}, "yes": {}, "no": {}, "none": {},
		"null": {}, "enabled": {}, "disabled": {}, "strict": {},
		"required": {}, "optional": {}, "default": {},
	}
	_, ok := common[strings.ToLower(s)]
	return ok
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func hasMixedCharset(s string) bool {
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	// At least 2 of 4 categories
	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSpecial {
		count++
	}
	return count >= 2
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./secrets/ -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add secrets/
git commit -m "feat(secrets): implement output scrubbing with pattern-based redaction"
```

---

### Task 4: Add security tests and fuzz tests

**Files:**

- Create: `secrets/security_test.go`
- Create: `secrets/fuzz_test.go`

**Step 1: Write security tests**

Create `secrets/security_test.go`:

```go
package secrets

import (
	"testing"

	"github.com/jonchun/shellguard/parser"
)

// TestSec_PathTraversal verifies path normalization catches traversal bypasses.
func TestSec_PathTraversal(t *testing.T) {
	c := NewChecker(Config{})
	attacks := []string{
		"../../.env",
		"../../../etc/shadow",
		"/app/../../../etc/shadow",
		"./foo/../.env",
		"foo/bar/../../.env",
		"./.env",
		"/app/config/../.env",
	}
	for _, p := range attacks {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("BYPASS: path traversal %q was not blocked", p)
		}
	}
}

// TestSec_FlagValueBypass verifies flag values are checked for sensitive paths.
func TestSec_FlagValueBypass(t *testing.T) {
	c := NewChecker(Config{})
	attacks := []struct {
		name string
		cmd  string
		args []string
	}{
		{"grep -f .env", "grep", []string{"-f", ".env", "foo.txt"}},
		{"grep --file=.env", "grep", []string{"--file=.env", "foo.txt"}},
		{"cat with traversal", "cat", []string{"../../.env"}},
		{"head with key file", "head", []string{".ssh/id_rsa"}},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: tc.cmd, Args: tc.args},
			}}
			if err := c.CheckPipeline(p); err == nil {
				t.Errorf("BYPASS: %s was not blocked", tc.name)
			}
		})
	}
}

// TestSec_FindNameBypass verifies find -name checks for sensitive patterns.
func TestSec_FindNameBypass(t *testing.T) {
	c := NewChecker(Config{})
	attacks := []struct {
		name string
		args []string
	}{
		{"find -name .env", []string{"/", "-name", ".env"}},
		{"find -iname .env", []string{"/", "-iname", ".env"}},
		{"find -name id_rsa", []string{"/", "-name", "id_rsa"}},
		{"find -name credentials.json", []string{"/", "-name", "credentials.json"}},
		{"find with -type before -name", []string{"/", "-type", "f", "-name", ".env"}},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "find", Args: tc.args},
			}}
			if err := c.CheckPipeline(p); err == nil {
				t.Errorf("BYPASS: %s was not blocked", tc.name)
			}
		})
	}
}

// TestSec_PrintenvBypass verifies printenv is properly restricted.
func TestSec_PrintenvBypass(t *testing.T) {
	c := NewChecker(Config{})
	attacks := []struct {
		name string
		args []string
	}{
		{"bare printenv", nil},
		{"printenv empty", []string{}},
		{"AWS_SECRET_ACCESS_KEY", []string{"AWS_SECRET_ACCESS_KEY"}},
		{"DATABASE_PASSWORD", []string{"DATABASE_PASSWORD"}},
		{"GITHUB_TOKEN", []string{"GITHUB_TOKEN"}},
		{"AUTH_HEADER", []string{"AUTH_HEADER"}},
		{"API_KEY", []string{"API_KEY"}},
		{"PRIVATE_KEY", []string{"PRIVATE_KEY"}},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Pipeline{Segments: []parser.PipelineSegment{
				{Command: "printenv", Args: tc.args},
			}}
			if err := c.CheckPipeline(p); err == nil {
				t.Errorf("BYPASS: printenv %v was not blocked", tc.args)
			}
		})
	}
}

// TestSec_AllowlistDoesNotWeaken verifies allowlist only affects specified paths.
func TestSec_AllowlistDoesNotWeaken(t *testing.T) {
	c := NewChecker(Config{
		AllowedPaths: []string{".env.example"},
	})
	// Allowed path should pass
	if err := c.CheckPath(".env.example"); err != nil {
		t.Fatalf("allowlisted .env.example was blocked: %v", err)
	}
	// Other sensitive paths must still be blocked
	stillBlocked := []string{".env", ".env.local", ".ssh/id_rsa", "/etc/shadow"}
	for _, p := range stillBlocked {
		if err := c.CheckPath(p); err == nil {
			t.Errorf("BYPASS: allowlist weakened protection for %q", p)
		}
	}
}

// TestSec_MultiSegmentPipeline verifies all segments are checked.
func TestSec_MultiSegmentPipeline(t *testing.T) {
	c := NewChecker(Config{})
	// .env appears in second segment
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{
		{Command: "cat", Args: []string{"README.md"}, Operator: "|"},
		{Command: "grep", Args: []string{"-f", ".env"}},
	}}
	if err := c.CheckPipeline(p); err == nil {
		t.Error("BYPASS: .env in second pipeline segment was not blocked")
	}
}
```

**Step 2: Write fuzz tests**

Create `secrets/fuzz_test.go`:

```go
package secrets

import (
	"testing"
)

func FuzzCheckPath(f *testing.F) {
	c := NewChecker(Config{})

	// Seed corpus
	seeds := []string{
		".env", ".env.local", "README.md", ".ssh/id_rsa",
		"../../.env", "/etc/shadow", "credentials.json",
		"main.go", "foo/bar/baz", "", ".", "..", "/",
		".aws/credentials", "server.key", "cert.pem",
		"service-account.json", ".netrc", ".pgpass",
		"日本語ファイル.txt", "file with spaces",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic
		_ = c.CheckPath(input)
	})
}

func FuzzScrubOutput(f *testing.F) {
	c := NewChecker(Config{})

	seeds := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12345678",
		"password=hunter2",
		"normal output with no secrets",
		"-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END RSA PRIVATE KEY-----",
		"postgresql://user:pass@host:5432/db",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
		"",
		"token_count=5",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic
		got := c.ScrubOutput(input)
		// Output should never be empty if input is non-empty
		// (scrubbing replaces, never deletes entire output)
		if len(input) > 0 && len(got) == 0 {
			t.Errorf("ScrubOutput produced empty output for non-empty input %q", input)
		}
	})
}
```

**Step 3: Run all tests**

Run: `go test ./secrets/ -count=1 -v`
Expected: PASS

Run: `go test ./secrets/ -fuzz FuzzCheckPath -fuzztime=10s`
Expected: No panics

Run: `go test ./secrets/ -fuzz FuzzScrubOutput -fuzztime=10s`
Expected: No panics

**Step 4: Commit**

```bash
git add secrets/
git commit -m "test(secrets): add security and fuzz tests"
```

---

### Task 5: Add `SecretsConfig` to `config.Config` and wire through

**Files:**

- Modify: `config/config.go:44-52` (add Secrets field to Config struct)
- Modify: `config/config.go:98-133` (add env override for disable flags)

**Step 1: Write the failing test**

Add to `config/config_test.go`:

```go
func TestSecretsConfig_EnvOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SHELLGUARD_SECRETS_DISABLE_PATH_CHECK", "true")
	t.Setenv("SHELLGUARD_SECRETS_DISABLE_OUTPUT_SCRUB", "true")

	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.Secrets == nil {
		t.Fatal("Secrets config is nil after env override")
	}
	if !cfg.Secrets.DisablePathCheck {
		t.Error("DisablePathCheck should be true")
	}
	if !cfg.Secrets.DisableOutputScrub {
		t.Error("DisableOutputScrub should be true")
	}
}

func TestSecretsConfig_YAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
secrets:
  allowed_paths:
    - .env.example
    - /app/test-credentials.json
  additional_patterns:
    - "*.secret"
  disable_path_check: false
  disable_output_scrub: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFrom(path)
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.Secrets == nil {
		t.Fatal("Secrets config is nil")
	}
	if got, want := len(cfg.Secrets.AllowedPaths), 2; got != want {
		t.Fatalf("AllowedPaths length = %d, want %d", got, want)
	}
	if got, want := len(cfg.Secrets.AdditionalPatterns), 1; got != want {
		t.Fatalf("AdditionalPatterns length = %d, want %d", got, want)
	}
}
```

**Step 2: Run to verify failure**

Run: `go test ./config/ -run TestSecretsConfig -count=1`
Expected: FAIL (Secrets field doesn't exist)

**Step 3: Implement**

Add `SecretsConfig` struct and `Secrets` field to `config/config.go`:

In the Config struct (after `ManifestDir`):

```go
Secrets *SecretsConfig `yaml:"secrets"`
```

Add the SecretsConfig struct (after SSHConfig):

```go
// SecretsConfig controls secrets protection behavior.
type SecretsConfig struct {
	AllowedPaths       []string `yaml:"allowed_paths"`
	AdditionalPatterns []string `yaml:"additional_patterns"`
	DisablePathCheck   bool     `yaml:"disable_path_check"`
	DisableOutputScrub bool     `yaml:"disable_output_scrub"`
}
```

Add env overrides in `applyEnvOverrides()`:

```go
if v, ok := os.LookupEnv("SHELLGUARD_SECRETS_DISABLE_PATH_CHECK"); ok {
	if c.Secrets == nil {
		c.Secrets = &SecretsConfig{}
	}
	c.Secrets.DisablePathCheck = v == "true" || v == "1"
}
if v, ok := os.LookupEnv("SHELLGUARD_SECRETS_DISABLE_OUTPUT_SCRUB"); ok {
	if c.Secrets == nil {
		c.Secrets = &SecretsConfig{}
	}
	c.Secrets.DisableOutputScrub = v == "true" || v == "1"
}
```

**Step 4: Run tests**

Run: `go test ./config/ -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add config/
git commit -m "feat(config): add SecretsConfig with YAML and env override support"
```

---

### Task 6: Wire `Checker` into `server.Core`

**Files:**

- Modify: `server/server.go:50-70` (add CheckSecrets and ScrubSecrets fields to Core)
- Modify: `server/server.go:108-128` (add WithSecretsChecker option)
- Modify: `server/server.go:130-155` (set defaults in NewCore)
- Modify: `server/server.go:227-287` (add CheckSecrets and ScrubSecrets calls in Execute)
- Modify: `server/server.go:381-477` (add CheckPath call in DownloadFile)
- Modify: `shellguard.go:34-108` (wire SecretsConfig from user config)

**Step 1: Add fields and option to server.go**

Add to Core struct (after line 57, after Truncate):

```go
CheckSecrets func(*parser.Pipeline) error
ScrubSecrets func(string) string
```

Add new CoreOption (after WithMaxSleepSeconds):

```go
func WithSecretsChecker(checker *secrets.Checker) CoreOption {
	return func(c *Core) {
		c.CheckSecrets = checker.CheckPipeline
		c.ScrubSecrets = checker.ScrubOutput
	}
}
```

Add import for secrets package.

In NewCore, set default no-op functions (after line 141):

```go
CheckSecrets: func(_ *parser.Pipeline) error { return nil },
ScrubSecrets: func(s string) string { return s },
```

**Step 2: Add CheckSecrets call in Execute**

After the Validate block (after line 256), add:

```go
if err := c.CheckSecrets(pipeline); err != nil {
	c.logger.InfoContext(ctx, "execute",
		"command", in.Command,
		"host", in.Host,
		"outcome", "rejected",
		"stage", "secrets",
		"error", err.Error(),
		"duration_ms", time.Since(start).Milliseconds(),
	)
	return output.CommandResult{}, err
}
```

**Step 3: Add ScrubSecrets call in Execute**

After the Truncate call (after line 285), before the return:

```go
truncated.Stdout = c.ScrubSecrets(truncated.Stdout)
truncated.Stderr = c.ScrubSecrets(truncated.Stderr)
```

**Step 4: Add CheckPath call in DownloadFile**

After the empty path check (after line 383), add:

```go
// Check remote path against sensitive patterns.
// Build a single-segment pipeline to reuse CheckSecrets.
dlPipeline := &parser.Pipeline{Segments: []parser.PipelineSegment{
	{Command: "download_file", Args: []string{in.RemotePath}},
}}
if err := c.CheckSecrets(dlPipeline); err != nil {
	return DownloadResult{}, err
}
```

**Step 5: Wire in shellguard.go**

In `shellguard.go`, after loading user config and before building coreOpts, add:

```go
// Build secrets checker from user config.
var secretsCfg secrets.Config
if userCfg.Secrets != nil {
	secretsCfg = secrets.Config{
		AllowedPaths:       userCfg.Secrets.AllowedPaths,
		AdditionalPatterns: userCfg.Secrets.AdditionalPatterns,
		DisablePathCheck:   userCfg.Secrets.DisablePathCheck,
		DisableOutputScrub: userCfg.Secrets.DisableOutputScrub,
	}
}
secretsChecker := secrets.NewChecker(secretsCfg)
```

And append to coreOpts:

```go
coreOpts = append(coreOpts, server.WithSecretsChecker(secretsChecker))
```

Add import for secrets package.

**Step 6: Run all tests**

Run: `make test`
Expected: PASS

**Step 7: Commit**

```bash
git add server/ shellguard.go
git commit -m "feat: wire secrets checker into Core pipeline (execute + download_file)"
```

---

### Task 7: Add cross-layer integration tests

**Files:**

- Modify: `security_pipeline_test.go` (add secrets test group)
- Modify: `integration_shellguard_test.go` (if needed for execute-level tests)

**Step 1: Write cross-layer tests**

Add a new test group to `security_pipeline_test.go`. These tests verify the full
parse -> validate -> secrets check flow using the same `fullPipeline` helper,
extended to include secrets checking.

Since `fullPipeline` currently only runs parse -> validate -> reconstruct, we need
a variant that also runs secrets checks. Add a helper:

```go
func fullPipelineWithSecrets(t *testing.T, registry map[string]*manifest.Manifest, checker *secrets.Checker, input string) (string, error) {
	t.Helper()
	pipeline, err := parser.Parse(input)
	if err != nil {
		return "", err
	}
	if err := validator.ValidatePipeline(pipeline, registry); err != nil {
		return "", err
	}
	if err := checker.CheckPipeline(pipeline); err != nil {
		return "", err
	}
	reconstructed := ssh.ReconstructCommand(pipeline, false, false)
	return reconstructed, nil
}
```

Then add the test group:

```go
// 20. Secrets Protection
func TestCrossLayer_SecretsProtection(t *testing.T) {
	registry := loadRegistry(t)
	checker := secrets.NewChecker(secrets.Config{})

	t.Run("blocks cat .env", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "cat .env")
		if err == nil {
			t.Fatal("expected cat .env to be rejected")
		}
	})
	t.Run("allows cat README.md", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "cat README.md")
		if err != nil {
			t.Fatalf("expected cat README.md to be allowed, got: %v", err)
		}
	})
	t.Run("blocks head .ssh/id_rsa", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "head .ssh/id_rsa")
		if err == nil {
			t.Fatal("expected head .ssh/id_rsa to be rejected")
		}
	})
	t.Run("blocks bare printenv", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "printenv")
		if err == nil {
			t.Fatal("expected bare printenv to be rejected")
		}
	})
	t.Run("allows printenv PATH", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "printenv PATH")
		if err != nil {
			t.Fatalf("expected printenv PATH to be allowed, got: %v", err)
		}
	})
	t.Run("blocks printenv AWS_SECRET_KEY", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "printenv AWS_SECRET_KEY")
		if err == nil {
			t.Fatal("expected printenv AWS_SECRET_KEY to be rejected")
		}
	})
	t.Run("blocks head .aws/credentials", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "head .aws/credentials")
		if err == nil {
			t.Fatal("expected head .aws/credentials to be rejected")
		}
	})
	t.Run("blocks grep -f .env", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "grep -f .env file.txt")
		if err == nil {
			t.Fatal("expected grep -f .env to be rejected")
		}
	})
	t.Run("blocks cat /etc/shadow", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "cat /etc/shadow")
		if err == nil {
			t.Fatal("expected cat /etc/shadow to be rejected")
		}
	})
	t.Run("blocks find -name .env", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "find / -name .env")
		if err == nil {
			t.Fatal("expected find -name .env to be rejected")
		}
	})
	t.Run("allows find -name README.md", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "find / -name README.md")
		if err != nil {
			t.Fatalf("expected find -name README.md to be allowed, got: %v", err)
		}
	})
	t.Run("blocks sensitive path in second pipe segment", func(t *testing.T) {
		_, err := fullPipelineWithSecrets(t, registry, checker, "ls -la | grep .env")
		if err == nil {
			t.Fatal("expected .env in second pipe segment to be rejected")
		}
	})
}
```

Add import for `secrets` package.

**Step 2: Run all tests**

Run: `make test`
Expected: PASS

Run: `make lint`
Expected: PASS

**Step 3: Commit**

```bash
git add security_pipeline_test.go
git commit -m "test: add cross-layer secrets protection integration tests"
```

---

### Task 8: Final verification

**Step 1: Run full test suite**

Run: `make test`
Expected: PASS

**Step 2: Run tests with race detector**

Run: `make test-race`
Expected: PASS

**Step 3: Run linter**

Run: `make lint`
Expected: PASS

**Step 4: Build**

Run: `make build`
Expected: Binary at `./bin/shellguard`

**Step 5: Run fuzz tests**

Run: `go test ./secrets/ -fuzz FuzzCheckPath -fuzztime=30s`
Run: `go test ./secrets/ -fuzz FuzzScrubOutput -fuzztime=30s`
Expected: No panics or failures

**Step 6: Final commit if any fixups needed, then push**

```bash
git push
```
