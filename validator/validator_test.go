package validator

import (
	"testing"

	"github.com/jonchun/shellguard/manifest"
	"github.com/jonchun/shellguard/parser"
)

func testRegistry(t *testing.T) map[string]*manifest.Manifest {
	t.Helper()
	registry, err := manifest.LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}
	return registry
}

func validateOne(t *testing.T, command string, args ...string) error {
	t.Helper()
	p := &parser.Pipeline{Segments: []parser.PipelineSegment{{Command: command, Args: args}}}
	return ValidatePipeline(p, testRegistry(t))
}

func TestAllowsSimpleCommand(t *testing.T) {
	if err := validateOne(t, "ls", "/tmp"); err != nil {
		t.Fatalf("validate ls: %v", err)
	}
}

func TestRejectsDeniedCommand(t *testing.T) {
	err := validateOne(t, "rm", "/tmp/file")
	if err == nil {
		t.Fatal("expected deny error for rm")
	}
}

func TestRejectsUnknownCommand(t *testing.T) {
	err := validateOne(t, "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected unknown command error")
	}
}

func TestRejectsDeniedFlag(t *testing.T) {
	err := validateOne(t, "tail", "-f", "/var/log/syslog")
	if err == nil {
		t.Fatal("expected denied flag error")
	}
}

func TestRejectsUnknownFlag(t *testing.T) {
	err := validateOne(t, "grep", "--nope", "error", "/var/log/syslog")
	if err == nil {
		t.Fatal("expected unknown flag error")
	}
}

func TestAllowsCombinedShortFlags(t *testing.T) {
	if err := validateOne(t, "grep", "-irn", "error", "/var/log/syslog"); err != nil {
		t.Fatalf("validate grep combined flags: %v", err)
	}
}

func TestSudoAllowsValidCommand(t *testing.T) {
	if err := validateOne(t, "sudo", "ls", "/tmp"); err != nil {
		t.Fatalf("sudo ls should be allowed: %v", err)
	}
}

func TestSudoUAllowsValidCommand(t *testing.T) {
	if err := validateOne(t, "sudo", "-u", "postgres", "psql", "-c", "SELECT 1"); err != nil {
		t.Fatalf("sudo -u postgres psql should be allowed: %v", err)
	}
}

func TestSudoRejectsDeniedCommand(t *testing.T) {
	err := validateOne(t, "sudo", "rm", "/tmp/file")
	if err == nil {
		t.Fatal("expected sudo rm to be rejected")
	}
}

func TestSudoURejectsDeniedCommand(t *testing.T) {
	err := validateOne(t, "sudo", "-u", "nobody", "rm", "/tmp/file")
	if err == nil {
		t.Fatal("expected sudo -u nobody rm to be rejected")
	}
}

func TestSudoRejectsUnknownCommand(t *testing.T) {
	err := validateOne(t, "sudo", "definitely-not-a-command")
	if err == nil {
		t.Fatal("expected sudo with unknown command to be rejected")
	}
}

func TestSudoRejectsNoArgs(t *testing.T) {
	err := validateOne(t, "sudo")
	if err == nil {
		t.Fatal("expected bare sudo to be rejected")
	}
}

func TestSudoURejectsNoCommand(t *testing.T) {
	err := validateOne(t, "sudo", "-u", "postgres")
	if err == nil {
		t.Fatal("expected sudo -u with no command to be rejected")
	}
}

func TestValidatesSubcommands(t *testing.T) {
	if err := validateOne(t, "docker", "ps"); err != nil {
		t.Fatalf("validate docker ps: %v", err)
	}

	err := validateOne(t, "docker", "run", "alpine")
	if err == nil {
		t.Fatal("expected docker run to be rejected")
	}
}

func TestValidatesAwsServiceSubcommands(t *testing.T) {
	if err := validateOne(t, "aws", "ec2", "describe-instances"); err != nil {
		t.Fatalf("validate aws ec2 describe-instances: %v", err)
	}
}

func TestPsqlRequiresCFlag(t *testing.T) {
	err := validateOne(t, "psql", "-d", "app")
	if err == nil {
		t.Fatal("expected psql without -c to be rejected")
	}
}

func TestPsqlSQLReadOnlyEnforced(t *testing.T) {
	if err := validateOne(t, "psql", "-c", "SELECT 1"); err != nil {
		t.Fatalf("expected SELECT to pass: %v", err)
	}

	err := validateOne(t, "psql", "-c", "DELETE FROM users")
	if err == nil {
		t.Fatal("expected DELETE to be rejected")
	}
}

func TestGlobRules(t *testing.T) {
	if err := validateOne(t, "find", "/var/log", "-name", "*.log"); err != nil {
		t.Fatalf("find -name *.log should be allowed: %v", err)
	}

	err := validateOne(t, "grep", "error", "*.log")
	if err == nil {
		t.Fatal("expected positional glob to be rejected")
	}
}

func TestRestrictedPathRejected(t *testing.T) {
	err := validateOne(t, "find", "/proc/kcore")
	if err == nil {
		t.Fatal("expected restricted path to be rejected")
	}
}

func TestUnzipRequiresSafeMode(t *testing.T) {
	err := validateOne(t, "unzip", "archive.zip")
	if err == nil {
		t.Fatal("expected unzip without -l/-p to be rejected")
	}

	if err := validateOne(t, "unzip", "-l", "archive.zip"); err != nil {
		t.Fatalf("unzip -l should be allowed: %v", err)
	}
}

func TestTarExtractRequiresStdout(t *testing.T) {
	err := validateOne(t, "tar", "-xf", "archive.tar")
	if err == nil {
		t.Fatal("expected tar -x without -O to be rejected")
	}

	if err := validateOne(t, "tar", "-xf", "archive.tar", "-O"); err != nil {
		t.Fatalf("tar -xf archive.tar -O should be allowed: %v", err)
	}
}

func TestNumericCountShorthandAllowed(t *testing.T) {
	if err := validateOne(t, "head", "-20", "/var/log/syslog"); err != nil {
		t.Fatalf("head -20 should be allowed: %v", err)
	}
}
