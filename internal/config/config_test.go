package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"raw/**", "raw/a.txt", true},
		{"raw/**", "raw/x/y/z.csv", true},
		{"raw/**", "raw", true},
		{"raw/**", "rawdata/a", false},
		{"*.pdf", "a.pdf", true},
		{"*.pdf", "x/a.pdf", false},
		{"**/*.pdf", "x/y/a.pdf", true},
		{"contracts/*.docx", "contracts/a.docx", true},
		{"contracts/*.docx", "contracts/sub/a.docx", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pat, c.path); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v", c.pat, c.path, got)
		}
	}
}

func TestFindWorkspaceWalksUp(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, WorkspaceFile), []byte(`{"version":1,"protect":["raw/**"]}`), 0o600)
	deep := filepath.Join(root, "a", "b")
	os.MkdirAll(deep, 0o700)
	ws, ok, err := FindWorkspace(deep)
	if err != nil || !ok || ws.Root != Canonical(root) {
		t.Fatalf("ws=%+v ok=%v err=%v", ws, ok, err)
	}
	if !ws.Protected(filepath.Join(root, "raw", "x.csv")) || ws.Protected(filepath.Join(root, "a", "x.csv")) {
		t.Fatal("Protected wrong")
	}
	if !ws.Contains(filepath.Join(root, "a")) || ws.Contains(filepath.Dir(root)) {
		t.Fatal("Contains wrong")
	}
	if _, ok, _ := FindWorkspace(t.TempDir()); ok {
		t.Fatal("found a workspace where there is none")
	}
}

func TestBadMarkerStillCountsAsWorkspace(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, WorkspaceFile), []byte(`{oops`), 0o600)
	_, ok, err := FindWorkspace(root)
	var bad *BadWorkspaceError
	if !ok || !errors.As(err, &bad) {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestSandboxStrict(t *testing.T) {
	root := t.TempDir()
	ws := Workspace{Root: root}
	if ws.SandboxStrict("") {
		t.Fatal("no settings is not strict")
	}
	os.MkdirAll(filepath.Join(root, ".claude"), 0o700)
	os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(`{"sandbox":{"enabled":true}}`), 0o600)
	if ws.SandboxStrict("") {
		t.Fatal("escape hatch still open")
	}
	os.WriteFile(filepath.Join(root, ".claude", "settings.local.json"), []byte(`{"sandbox":{"allowUnsandboxedCommands":false}}`), 0o600)
	if !ws.SandboxStrict("") {
		t.Fatal("project + local should combine to strict")
	}
	os.WriteFile(filepath.Join(root, ".claude", "settings.local.json"), []byte(`{"sandbox":{"allowUnsandboxedCommands":false,"autoAllowBashIfSandboxed":false}}`), 0o600)
	if ws.SandboxStrict("") {
		t.Fatal("without auto-allow the wrapper would prompt every time")
	}
	os.WriteFile(filepath.Join(root, ".claude", "settings.local.json"), []byte(`{"sandbox":{"allowUnsandboxedCommands":false}}`), 0o600)
	user := filepath.Join(t.TempDir(), "settings.json")
	os.WriteFile(user, []byte(`{"sandbox":{"excludedCommands":["docker *"]}}`), 0o600)
	if ws.SandboxStrict(user) {
		t.Fatal("a user-level excluded command runs outside the sandbox")
	}
}

func TestGlobalRoundTrip(t *testing.T) {
	p := Paths{State: t.TempDir()}
	g, err := LoadGlobal(p)
	if err != nil || !g.MaskingOn() || g.TLSHosts()[0] != "api.anthropic.com" || g.VaultVolume() != "ClaudeVault" {
		t.Fatalf("defaults wrong: %+v %v", g, err)
	}
	off := false
	g.GlobalMasking = &off
	g.AllowHosts = []string{"x.example"}
	if err := SaveGlobal(p, g); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p.GlobalFile())
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	g2, _ := LoadGlobal(p)
	if g2.MaskingOn() || g2.AllowHosts[0] != "x.example" {
		t.Fatalf("round trip: %+v", g2)
	}
}
