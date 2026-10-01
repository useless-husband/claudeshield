// Package settings edits Claude Code's settings files: it wires claudeshield's
// hooks into ~/.claude/settings.json (and takes them out again), and writes a
// sensitive workspace's sandbox and permission rules.
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/config"
)

// Events are the hook events claudeshield registers, with their CLI argument
// and timeout in seconds. Timeouts stay below Claude Code's own limits
// (30 s for UserPromptSubmit), and a timed-out PreToolUse hook does not block,
// so they are generous enough never to be hit in normal use.
var Events = []struct {
	Name    string
	Arg     string
	Matcher string
	Timeout int
}{
	{"SessionStart", "session-start", "", 30},
	{"UserPromptSubmit", "prompt", "", 25},
	{"PreToolUse", "pre-tool", "*", 20},
	{"PostToolUse", "post-tool", "*", 20},
}

// PrivacyEnv are the variables install adds to settings.json's env block:
// no /feedback uploads (transcripts kept 5 years), no session-quality
// transcript prompt, no error reports.
var PrivacyEnv = map[string]string{
	"DISABLE_FEEDBACK_COMMAND":            "1",
	"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
	"DISABLE_ERROR_REPORTING":             "1",
}

// HookConfig returns the "hooks" object for an executable.
func HookConfig(exe string) map[string]any {
	hooks := map[string]any{}
	for _, e := range Events {
		group := map[string]any{"hooks": []any{map[string]any{
			"type": "command", "command": exe, "args": []any{"hook", e.Arg}, "timeout": e.Timeout,
		}}}
		if e.Matcher != "" {
			group["matcher"] = e.Matcher
		}
		hooks[e.Name] = []any{group}
	}
	return hooks
}

// Read loads a settings file; missing means empty.
func Read(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// Write saves a settings file (2-space indent, keys sorted by encoding/json).
func Write(path string, m map[string]any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return config.WriteFileAtomic(path, buf.Bytes(), mode)
}

// IsOurs reports whether a hook handler is one of claudeshield's.
func IsOurs(h map[string]any) bool {
	cmd, _ := h["command"].(string)
	if filepath.Base(strings.Fields(cmd + " x")[0]) != "claudeshield" {
		return false
	}
	args, _ := h["args"].([]any)
	if len(args) > 0 {
		return fmt.Sprint(args[0]) == "hook"
	}
	return strings.Contains(cmd, " hook ")
}

// removeOurs deletes claudeshield handlers (and groups left empty) from a hooks object.
func removeOurs(hooks map[string]any) {
	for event, v := range hooks {
		groups, _ := v.([]any)
		var keep []any
		for _, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				keep = append(keep, g)
				continue
			}
			hl, _ := gm["hooks"].([]any)
			var hk []any
			for _, h := range hl {
				if hm, ok := h.(map[string]any); ok && IsOurs(hm) {
					continue
				}
				hk = append(hk, h)
			}
			if len(hk) == 0 {
				continue
			}
			cp := map[string]any{}
			for k, x := range gm {
				cp[k] = x
			}
			cp["hooks"] = hk
			keep = append(keep, cp)
		}
		if len(keep) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = keep
		}
	}
}

// Install adds claudeshield's hooks and privacy variables to a settings file,
// after copying the original to backupDir. It returns the backup path and the
// env keys it added (only keys that were absent are added and recorded).
func Install(path, exe, backupDir string, now time.Time) (backup string, addedEnv []string, err error) {
	m, err := Read(path)
	if err != nil {
		return "", nil, err
	}
	if b, err := os.ReadFile(path); err == nil {
		backup = filepath.Join(backupDir, "settings.json."+now.UTC().Format("20060102T150405Z"))
		if err := config.WriteFileAtomic(backup, b, 0o600); err != nil {
			return "", nil, err
		}
	}
	hooks, _ := m["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	removeOurs(hooks)
	for event, groups := range HookConfig(exe) {
		existing, _ := hooks[event].([]any)
		hooks[event] = append(existing, groups.([]any)...)
	}
	m["hooks"] = hooks
	env, _ := m["env"].(map[string]any)
	if env == nil {
		env = map[string]any{}
	}
	keys := make([]string, 0, len(PrivacyEnv))
	for k := range PrivacyEnv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, ok := env[k]; !ok {
			env[k] = PrivacyEnv[k]
			addedEnv = append(addedEnv, k)
		}
	}
	m["env"] = env
	return backup, addedEnv, Write(path, m)
}

// Uninstall removes claudeshield's hooks and the env keys install added.
func Uninstall(path string, addedEnv []string) error {
	m, err := Read(path)
	if err != nil {
		return err
	}
	if hooks, ok := m["hooks"].(map[string]any); ok {
		removeOurs(hooks)
		if len(hooks) == 0 {
			delete(m, "hooks")
		}
	}
	if env, ok := m["env"].(map[string]any); ok {
		for _, k := range addedEnv {
			if fmt.Sprint(env[k]) == PrivacyEnv[k] {
				delete(env, k)
			}
		}
		if len(env) == 0 {
			delete(m, "env")
		}
	}
	return Write(path, m)
}

// Installed checks that every event has a claudeshield handler whose
// executable exists. A missing executable is the dangerous case: Claude Code
// treats an unstartable hook as a non-blocking error and carries on.
func Installed(path string) (bool, string) {
	m, err := Read(path)
	if err != nil {
		return false, err.Error()
	}
	hooks, _ := m["hooks"].(map[string]any)
	var missing []string
	for _, e := range Events {
		found := false
		groups, _ := hooks[e.Name].([]any)
		for _, g := range groups {
			gm, _ := g.(map[string]any)
			hl, _ := gm["hooks"].([]any)
			for _, h := range hl {
				hm, _ := h.(map[string]any)
				if hm == nil || !IsOurs(hm) {
					continue
				}
				cmd, _ := hm["command"].(string)
				if st, err := os.Stat(cmd); err == nil && st.Mode()&0o111 != 0 {
					found = true
				} else {
					missing = append(missing, e.Name+" → "+cmd+" (not executable)")
					found = true
				}
			}
		}
		if !found {
			missing = append(missing, e.Name)
		}
	}
	if len(missing) > 0 {
		return false, strings.Join(missing, ", ")
	}
	return true, ""
}

// WorkspaceSettings are the rules `claudeshield init` writes into a sensitive
// workspace's .claude/settings.local.json:
//
//   - sandbox on, with no unsandboxed escape hatch, so every shell command
//     runs under the OS sandbox (macOS Seatbelt);
//   - protected paths unreadable by the sandbox and by Claude's file tools;
//   - the network allowlist pre-seeded with the workspace's allowed hosts.
func WorkspaceSettings(ws config.Workspace, ownDirs ...string) map[string]any {
	var denyRead []any
	var deny []any
	// claudeshield's state (token tables hold the real values) is off limits
	// to every sandboxed process, however a command spells the path.
	for _, d := range ownDirs {
		if d != "" {
			denyRead = append(denyRead, d)
			deny = append(deny, "Read(/"+d+"/**)", "Edit(/"+d+"/**)")
		}
	}
	for _, g := range ws.Protect {
		g = strings.TrimPrefix(strings.TrimSpace(g), "./")
		if g == "" {
			continue
		}
		abs := filepath.Join(ws.Root, filepath.FromSlash(g))
		deny = append(deny, "Read(/"+abs+")", "Edit(/"+abs+")")
		// The sandbox takes paths; "raw/**" protects the directory "raw".
		dir := strings.TrimSuffix(strings.TrimSuffix(abs, "/**"), "/*")
		denyRead = append(denyRead, dir)
	}
	hosts := []any{}
	for _, h := range ws.AllowHosts {
		hosts = append(hosts, h)
	}
	return map[string]any{
		"sandbox": map[string]any{
			"enabled":                  true,
			"allowUnsandboxedCommands": false,
			"filesystem":               map[string]any{"denyRead": denyRead},
			"network":                  map[string]any{"allowedDomains": hosts},
		},
		"permissions": map[string]any{"deny": deny},
	}
}

// MergeWorkspaceSettings merges WorkspaceSettings into an existing
// settings.local.json, keeping unrelated keys and de-duplicating lists.
func MergeWorkspaceSettings(path string, ws config.Workspace, ownDirs ...string) error {
	m, err := Read(path)
	if err != nil {
		return err
	}
	merge(m, WorkspaceSettings(ws, ownDirs...))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return Write(path, m)
}

func merge(dst, src map[string]any) {
	for k, sv := range src {
		switch s := sv.(type) {
		case map[string]any:
			d, ok := dst[k].(map[string]any)
			if !ok {
				d = map[string]any{}
				dst[k] = d
			}
			merge(d, s)
		case []any:
			d, _ := dst[k].([]any)
			seen := map[string]bool{}
			for _, x := range d {
				seen[fmt.Sprint(x)] = true
			}
			for _, x := range s {
				if !seen[fmt.Sprint(x)] {
					d = append(d, x)
					seen[fmt.Sprint(x)] = true
				}
			}
			if d == nil {
				d = []any{}
			}
			dst[k] = d
		default:
			dst[k] = sv
		}
	}
}
