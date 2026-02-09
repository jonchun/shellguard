// Package manifest loads and merges YAML command registries.
package manifest

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

const defaultTimeout = 30

// SubcommandCommands identifies commands that use subcommand-style dispatch
// (e.g. "docker ps", "kubectl get"). Both the validator and server packages
// reference this map so they stay in sync.
var SubcommandCommands = map[string]bool{
	"docker":    true,
	"kubectl":   true,
	"svn":       true,
	"systemctl": true,
	"aws":       true,
}

//go:embed manifests/*.yaml manifests/denied/*.yaml
var manifestsFS embed.FS

type ManifestError struct {
	Message string
}

func (e *ManifestError) Error() string {
	return e.Message
}

type Flag struct {
	Flag          string   `yaml:"flag"`
	Description   string   `yaml:"description"`
	TakesValue    bool     `yaml:"takes_value"`
	PatternValue  bool     `yaml:"pattern_value"`
	AllowedValues []string `yaml:"allowed_values"`
	Deny          bool     `yaml:"deny"`
	Reason        string   `yaml:"reason"`
}

type Manifest struct {
	Name             string   `yaml:"name"`
	Description      string   `yaml:"description"`
	Category         string   `yaml:"category"`
	Timeout          int      `yaml:"timeout"`
	Deny             bool     `yaml:"deny"`
	Reason           string   `yaml:"reason"`
	Flags            []Flag   `yaml:"flags"`
	AllowsPathArgs   bool     `yaml:"allows_path_args"`
	RestrictedPaths  []string `yaml:"restricted_paths"`
	Stdin            bool     `yaml:"stdin"`
	Stdout           bool     `yaml:"stdout"`
	RegexArgPosition *int     `yaml:"regex_arg_position"`
}

func (m *Manifest) GetFlag(name string) *Flag {
	for i := range m.Flags {
		if m.Flags[i].Flag == name {
			return &m.Flags[i]
		}
	}
	return nil
}

func LoadEmbedded() (map[string]*Manifest, error) {
	return loadFromFS(manifestsFS, "manifests")
}

// LoadDir loads manifests from dir (recursive). Skips _-prefixed and non-YAML files.
func LoadDir(dir string) (map[string]*Manifest, error) {
	registry, err := loadFromFS(os.DirFS(dir), ".")
	if err != nil {
		return nil, fmt.Errorf("walk manifest directory %s: %w", dir, err)
	}
	return registry, nil
}

// loadFromFS walks root within fsys, loading all YAML manifests into a registry.
// Skips directories, non-.yaml files, and files prefixed with "_".
func loadFromFS(fsys fs.FS, root string) (map[string]*Manifest, error) {
	registry := make(map[string]*Manifest)

	err := fs.WalkDir(fsys, root, func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if path.Ext(filePath) != ".yaml" {
			return nil
		}
		if strings.HasPrefix(path.Base(filePath), "_") {
			return nil
		}

		b, readErr := fs.ReadFile(fsys, filePath)
		if readErr != nil {
			return fmt.Errorf("read manifest %s: %w", filePath, readErr)
		}

		var data map[string]any
		if unmarshalErr := yaml.Unmarshal(b, &data); unmarshalErr != nil {
			return &ManifestError{
				Message: fmt.Sprintf("invalid YAML in %s: %v", filePath, unmarshalErr),
			}
		}

		manifest, parseErr := parseManifest(data, filePath)
		if parseErr != nil {
			return parseErr
		}
		registry[manifest.Name] = manifest
		return nil
	})
	if err != nil {
		return nil, err
	}

	return registry, nil
}

// Merge combines base and overlay; overlay wins on conflict. Does not mutate inputs.
func Merge(base, overlay map[string]*Manifest) map[string]*Manifest {
	merged := make(map[string]*Manifest, len(base)+len(overlay))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overlay {
		merged[k] = v
	}
	return merged
}

func parseManifest(data map[string]any, filePath string) (*Manifest, error) {
	if data == nil {
		return nil, &ManifestError{Message: fmt.Sprintf("manifest %s is not a YAML mapping", filePath)}
	}

	name, ok := stringValue(data, "name")
	if !ok || name == "" {
		return nil, &ManifestError{Message: fmt.Sprintf("manifest %s missing required 'name' field", filePath)}
	}

	flags, err := parseFlags(data["flags"], filePath)
	if err != nil {
		return nil, err
	}

	timeout := defaultTimeout
	if rawTimeout, ok := data["timeout"]; ok {
		parsed, ok := intValueFromAny(rawTimeout)
		if !ok {
			return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: 'timeout' must be an int", filePath)}
		}
		timeout = parsed
	}

	stdout := true
	if rawStdout, ok := data["stdout"]; ok {
		parsed, ok := boolValueFromAny(rawStdout)
		if !ok {
			return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: 'stdout' must be a bool", filePath)}
		}
		stdout = parsed
	}

	regexPos, err := optionalInt(data, "regex_arg_position", filePath)
	if err != nil {
		return nil, err
	}

	restrictedPaths, err := stringSliceValue(data, "restricted_paths", filePath)
	if err != nil {
		return nil, err
	}

	return &Manifest{
		Name:             name,
		Description:      defaultString(data, "description"),
		Category:         defaultString(data, "category"),
		Timeout:          timeout,
		Deny:             defaultBool(data, "deny"),
		Reason:           defaultString(data, "reason"),
		Flags:            flags,
		AllowsPathArgs:   defaultBool(data, "allows_path_args"),
		RestrictedPaths:  restrictedPaths,
		Stdin:            defaultBool(data, "stdin"),
		Stdout:           stdout,
		RegexArgPosition: regexPos,
	}, nil
}

func parseFlags(raw any, filePath string) ([]Flag, error) {
	if raw == nil {
		return nil, nil
	}

	rawFlags, ok := raw.([]any)
	if !ok {
		return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: 'flags' must be a list", filePath)}
	}

	flags := make([]Flag, 0, len(rawFlags))
	for _, rawFlag := range rawFlags {
		flagMap, ok := rawFlag.(map[string]any)
		if !ok {
			return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: flag entry must be a mapping", filePath)}
		}

		flag, ok := stringValue(flagMap, "flag")
		if !ok || flag == "" {
			return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: flag entry missing 'flag' field", filePath)}
		}

		allowedValues, err := stringSliceValue(flagMap, "allowed_values", filePath)
		if err != nil {
			return nil, err
		}

		flags = append(flags, Flag{
			Flag:          flag,
			Description:   defaultString(flagMap, "description"),
			TakesValue:    defaultBool(flagMap, "takes_value"),
			PatternValue:  defaultBool(flagMap, "pattern_value"),
			AllowedValues: allowedValues,
			Deny:          defaultBool(flagMap, "deny"),
			Reason:        defaultString(flagMap, "reason"),
		})
	}

	return flags, nil
}

func defaultString(values map[string]any, key string) string {
	v, ok := stringValue(values, key)
	if !ok {
		return ""
	}
	return v
}

func defaultBool(values map[string]any, key string) bool {
	raw, ok := values[key]
	if !ok {
		return false
	}
	parsed, ok := boolValueFromAny(raw)
	if !ok {
		return false
	}
	return parsed
}

func stringValue(values map[string]any, key string) (string, bool) {
	raw, ok := values[key]
	if !ok || raw == nil {
		return "", false
	}
	v, ok := raw.(string)
	return v, ok
}

func optionalInt(values map[string]any, key string, filePath string) (*int, error) {
	raw, ok := values[key]
	if !ok || raw == nil {
		return nil, nil
	}
	v, ok := intValueFromAny(raw)
	if !ok {
		return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: '%s' must be an int", filePath, key)}
	}
	return &v, nil
}

func intValueFromAny(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		converted := int(n)
		if float64(converted) != n {
			return 0, false
		}
		return converted, true
	default:
		return 0, false
	}
}

func boolValueFromAny(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

func stringSliceValue(values map[string]any, key string, filePath string) ([]string, error) {
	raw, ok := values[key]
	if !ok || raw == nil {
		return nil, nil
	}

	switch typed := raw.(type) {
	case []string:
		result := slices.Clone(typed)
		return result, nil
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: '%s' must be a string list", filePath, key)}
			}
			result = append(result, s)
		}
		return result, nil
	default:
		return nil, &ManifestError{Message: fmt.Sprintf("manifest %s: '%s' must be a string list", filePath, key)}
	}
}
