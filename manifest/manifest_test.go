package manifest

import "testing"

func mustLoadEmbedded(t *testing.T) map[string]*Manifest {
	t.Helper()

	registry, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded() error = %v", err)
	}
	return registry
}

func TestLoadEmbeddedCountAndNameMatch(t *testing.T) {
	registry := mustLoadEmbedded(t)

	if got, want := len(registry), 178; got != want {
		t.Fatalf("len(registry) = %d, want %d", got, want)
	}

	for name, m := range registry {
		if m.Name != name {
			t.Fatalf("manifest key/name mismatch: key=%q name=%q", name, m.Name)
		}
	}
}

func TestLoadEmbeddedSchemaSkipped(t *testing.T) {
	registry := mustLoadEmbedded(t)
	if _, ok := registry["_schema"]; ok {
		t.Fatal("_schema should never be loaded as a manifest")
	}
}

func TestDenyManifestReasonsAndCount(t *testing.T) {
	registry := mustLoadEmbedded(t)

	denyCount := 0
	for name, m := range registry {
		if !m.Deny {
			continue
		}
		denyCount++
		if m.Reason == "" {
			t.Fatalf("deny manifest %q missing reason", name)
		}
	}

	if got, want := denyCount, 95; got != want {
		t.Fatalf("deny manifest count = %d, want %d", got, want)
	}
}

func TestDeniedFlagsHaveReasons(t *testing.T) {
	registry := mustLoadEmbedded(t)

	for name, m := range registry {
		for _, f := range m.Flags {
			if f.Deny && f.Reason == "" {
				t.Fatalf("denied flag %q in %q missing reason", f.Flag, name)
			}
		}
	}
}

func TestPatternValueFlagsRequireTakesValue(t *testing.T) {
	registry := mustLoadEmbedded(t)

	for name, m := range registry {
		for _, f := range m.Flags {
			if f.PatternValue && !f.TakesValue {
				t.Fatalf("flag %q in %q has pattern_value but not takes_value", f.Flag, name)
			}
		}
	}
}

func TestGetFlag(t *testing.T) {
	registry := mustLoadEmbedded(t)
	find, ok := registry["find"]
	if !ok {
		t.Fatal(`missing "find" manifest`)
	}

	if got := find.GetFlag("-name"); got == nil {
		t.Fatal("find.GetFlag(-name) = nil")
	}
	if got := find.GetFlag("--definitely-missing"); got != nil {
		t.Fatal("find.GetFlag(missing) should be nil")
	}
}

func TestDefaultTimeoutAndStdoutAndRegexPosition(t *testing.T) {
	m, err := parseManifest(map[string]any{
		"name": "ls",
	}, "test.yaml")
	if err != nil {
		t.Fatalf("parseManifest() error = %v", err)
	}

	if got, want := m.Timeout, 30; got != want {
		t.Fatalf("Timeout = %d, want %d", got, want)
	}
	if !m.Stdout {
		t.Fatal("Stdout default should be true")
	}
	if m.RegexArgPosition != nil {
		t.Fatal("RegexArgPosition should default to nil")
	}
}

func TestRegexArgPositionZeroPreserved(t *testing.T) {
	m, err := parseManifest(map[string]any{
		"name":               "grep",
		"regex_arg_position": 0,
	}, "test.yaml")
	if err != nil {
		t.Fatalf("parseManifest() error = %v", err)
	}

	if m.RegexArgPosition == nil {
		t.Fatal("RegexArgPosition should not be nil")
	}
	if got, want := *m.RegexArgPosition, 0; got != want {
		t.Fatalf("*RegexArgPosition = %d, want %d", got, want)
	}
}

func TestKeyFlagsExist(t *testing.T) {
	registry := mustLoadEmbedded(t)

	keyFlags := map[string][]string{
		"grep":       {"-C", "-A", "-B", "-i", "-r", "-v", "-c", "-l", "-n", "-E", "-P", "-h", "-w"},
		"ls":         {"-l", "-a", "-h", "-t", "-R", "-1"},
		"find":       {"-name", "-type", "-mtime", "-size", "-maxdepth", "-path", "-iname", "-o", "-print0"},
		"psql":       {"-c", "-t", "-d", "-p", "-U", "-A", "-F", "-x"},
		"tail":       {"-f", "--follow"},
		"journalctl": {"-f", "--follow"},
		"curl":       {"-X", "--request", "-d", "--data", "--data-binary", "--data-urlencode", "-o", "--output", "-O", "--remote-name", "-T", "--upload-file"},
	}

	for command, flags := range keyFlags {
		m, ok := registry[command]
		if !ok {
			t.Fatalf("missing manifest %q", command)
		}
		for _, f := range flags {
			if m.GetFlag(f) == nil {
				t.Fatalf("%s missing flag %s", command, f)
			}
		}
	}
}

func TestDestructiveSubcommandsAbsent(t *testing.T) {
	registry := mustLoadEmbedded(t)

	absent := []string{
		"docker_run", "docker_exec", "docker_rm", "docker_stop", "docker_kill", "docker_start",
		"docker_build", "docker_pull", "docker_push", "docker_cp",
		"kubectl_exec", "kubectl_apply", "kubectl_delete", "kubectl_edit", "kubectl_patch", "kubectl_create", "kubectl_run", "kubectl_cp",
		"systemctl_start", "systemctl_stop", "systemctl_restart", "systemctl_enable", "systemctl_disable", "systemctl_reload", "systemctl_daemon-reload", "systemctl_mask",
	}

	for _, name := range absent {
		if _, ok := registry[name]; ok {
			t.Fatalf("destructive subcommand %q should not exist in manifests", name)
		}
	}
}
