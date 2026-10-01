package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sandbox points HOME, the state dir and Claude's config dir at a temp tree.
func sandbox(t *testing.T) (home string) {
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDESHIELD_HOME", filepath.Join(home, ".claudeshield"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, ".claude"))
	t.Setenv("CLAUDESHIELD_LANG", "en")
	t.Setenv("NO_COLOR", "1")
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	return home
}

func runCLI(t *testing.T, dir string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	if dir != "" {
		old, _ := os.Getwd()
		os.Chdir(dir)
		defer os.Chdir(old)
	}
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const sample = `客戶：王小明
身分證：A123456789
電話：0912-345-678
信箱：wang@acme-holdings.com.tw
報價：NT$1,250,000
`

func TestInitScanMaskUnmask(t *testing.T) {
	home := sandbox(t)
	ws := filepath.Join(home, "clients")
	if code, out, errs := runCLI(t, "", "", "init", ws); code != 0 {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	for _, f := range []string{".claudeshield.json", ".claude/settings.local.json"} {
		if _, err := os.Stat(filepath.Join(ws, f)); err != nil {
			t.Fatalf("init did not create %s", f)
		}
	}
	if st, err := os.Stat(filepath.Join(ws, "raw")); err != nil || !st.IsDir() {
		t.Fatal("init did not create raw/")
	}

	src := filepath.Join(ws, "raw", "letter.txt")
	os.WriteFile(src, []byte(sample), 0o600)
	code, out, _ := runCLI(t, ws, "", "scan", src)
	if code != 1 || !strings.Contains(out, "5 value(s) would be masked") || strings.Contains(out, "A123456789") {
		t.Fatalf("scan: %d\n%s", code, out)
	}

	dst := filepath.Join(ws, "work", "letter.txt")
	if code, _, errs := runCLI(t, ws, "", "mask", src, "-o", dst); code != 0 {
		t.Fatalf("mask: %s", errs)
	}
	masked, _ := os.ReadFile(dst)
	for _, v := range []string{"王小明", "A123456789", "0912-345-678", "wang@acme", "1,250,000"} {
		if strings.Contains(string(masked), v) {
			t.Fatalf("%q survived masking:\n%s", v, masked)
		}
	}
	if code, _, errs := runCLI(t, ws, "", "unmask", dst, "--in-place"); code != 0 {
		t.Fatalf("unmask: %s", errs)
	}
	back, _ := os.ReadFile(dst)
	if string(back) != sample {
		t.Fatalf("round trip differs:\n%s", back)
	}

	// mask refuses to write into the protected area
	if code, _, _ := runCLI(t, ws, "", "mask", src, "-o", filepath.Join(ws, "raw", "copy.txt")); code == 0 {
		t.Fatal("mask into raw/ accepted")
	}

	_, out, _ = runCLI(t, ws, "", "map")
	if !strings.Contains(out, "⟦TWID_001⟧") || strings.Contains(out, "A123456789") {
		t.Fatalf("map should list tokens with values hidden:\n%s", out)
	}
}

func TestInstallUninstall(t *testing.T) {
	home := sandbox(t)
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	os.WriteFile(settingsPath, []byte(`{"model":"opus"}`), 0o600)
	if code, out, errs := runCLI(t, home, "", "install"); code != 0 {
		t.Fatalf("install: %s %s", out, errs)
	}
	b, _ := os.ReadFile(settingsPath)
	var s map[string]any
	json.Unmarshal(b, &s)
	hooks := s["hooks"].(map[string]any)
	for _, ev := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "MessageDisplay"} {
		if hooks[ev] == nil {
			t.Fatalf("missing %s hook", ev)
		}
	}
	exe := filepath.Join(home, ".claudeshield", "bin", "claudeshield")
	if !strings.Contains(string(b), exe) {
		t.Fatalf("hooks do not point at the installed copy %s:\n%s", exe, b)
	}
	if _, err := os.Stat(filepath.Join(home, ".claudeshield", "baseline.json")); err != nil {
		t.Fatal("install did not record an extension baseline")
	}
	if code, _, errs := runCLI(t, home, "", "uninstall"); code != 0 {
		t.Fatalf("uninstall: %s", errs)
	}
	b, _ = os.ReadFile(settingsPath)
	if strings.Contains(string(b), "claudeshield") || !strings.Contains(string(b), "opus") {
		t.Fatalf("after uninstall:\n%s", b)
	}
}

func TestHookThroughCLI(t *testing.T) {
	home := sandbox(t)
	in := `{"session_id":"x","cwd":"` + home + `","hook_event_name":"PostToolUse","tool_name":"Bash",` +
		`"tool_input":{"command":"cat .env"},"tool_response":{"stdout":"KEY=sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789","stderr":"","interrupted":false,"isImage":false}}`
	code, out, _ := runCLI(t, home, in, "hook", "post-tool")
	if code != 0 || !strings.Contains(out, "⟦APIKEY_001⟧") || strings.Contains(out, "sk-ant-api03") {
		t.Fatalf("hook: %d %s", code, out)
	}
}

func TestCorruptConfigFailsHooksClosedInWorkspace(t *testing.T) {
	home := sandbox(t)
	ws := filepath.Join(home, "ws")
	runCLI(t, "", "", "init", ws)
	os.MkdirAll(filepath.Join(home, ".claudeshield"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".claudeshield", "config.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := `{"session_id":"x","cwd":"` + ws + `","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"` + ws + `/a.txt"}}`
	code, out, errs := runCLI(t, ws, in, "hook", "pre-tool")
	if !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Fatalf("got code=%d out=%q err=%q", code, out, errs)
	}
}

func TestCheckJSON(t *testing.T) {
	home := sandbox(t)
	code, out, errs := runCLI(t, home, "", "check", "--offline", "--json")
	var r map[string]any
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("not JSON (%d): %s %s", code, out, errs)
	}
	if _, ok := r["findings"]; !ok {
		t.Fatalf("no findings: %s", out)
	}
}

func TestPreview(t *testing.T) {
	for in, want := range map[string]string{"abc": "•••", "A123456789": "A••••••••9", "wang@acme-holdings.com.tw": "wan••••••.tw"} {
		if got := preview(in); got != want {
			t.Errorf("preview(%q) = %q, want %q", in, got, want)
		}
	}
}
