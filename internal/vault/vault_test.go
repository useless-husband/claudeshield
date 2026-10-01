package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/useless-husband/claudeshield/internal/config"
)

func TestRunningClaude(t *testing.T) {
	ps := `  1 /sbin/launchd
 292 claude
 400 /Users/x/.local/share/claude/versions/2.1.287
 57835 /Applications/Claude.app/Contents/MacOS/Claude
 900 /usr/bin/claudeshield
 901 /bin/zsh`
	got := strings.Join(RunningClaude(ps), ",")
	if got != "292 claude,400 2.1.287,57835 Claude" {
		t.Fatalf("got %q", got)
	}
}

func TestIsMountPoint(t *testing.T) {
	if !IsMountPoint("/") && !IsMountPoint("/System/Volumes/Data") {
		t.Skip("no mount point to compare with")
	}
	if IsMountPoint(t.TempDir()) {
		t.Fatal("a temp dir is not a mount point")
	}
}

// The hdiutil tests create, attach and detach real encrypted images. They are
// opt-in (CLAUDESHIELD_HDIUTIL_TESTS=1) because they touch /Volumes.
func realVault(t *testing.T) (config.Paths, config.Global) {
	if os.Getenv("CLAUDESHIELD_HDIUTIL_TESTS") != "1" {
		t.Skip("set CLAUDESHIELD_HDIUTIL_TESTS=1 to run hdiutil tests")
	}
	home := t.TempDir()
	p := config.Paths{Home: home, State: filepath.Join(home, ".claudeshield"), ClaudeDir: filepath.Join(home, ".claude"), VolumesDir: "/Volumes"}
	g := config.Global{Vault: config.VaultConfig{Image: filepath.Join(p.State, "v.sparsebundle"), Volume: fmt.Sprintf("CSTest%d", os.Getpid())}}
	if err := Create(g.Vault.Image, g.Vault.Volume, "64m", []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Close(p, g, true) })
	return p, g
}

func TestCreateOpenCloseWithRealImage(t *testing.T) {
	p, g := realVault(t)
	if err := Open(p, g, []byte("wrong")); err != ErrWrongPassword {
		t.Fatalf("wrong password: err=%v", err)
	}
	if Mounted(p, g) {
		t.Fatal("mounted after wrong password")
	}
	if err := Open(p, g, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	if !Mounted(p, g) {
		t.Fatal("not mounted")
	}
	// The image's band files never contain plaintext.
	marker := "CLAUDESHIELD-PLAINTEXT-MARKER-7f3a"
	os.WriteFile(filepath.Join(MountPoint(p, g), "claude", "probe.txt"), []byte(strings.Repeat(marker, 100)), 0o600)
	if err := Close(p, g, false); err != nil {
		t.Fatal(err)
	}
	filepath.Walk(g.Vault.Image, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			b, _ := os.ReadFile(path)
			if strings.Contains(string(b), marker) {
				t.Errorf("plaintext found in %s", path)
			}
		}
		return nil
	})
}

func TestMigrateAndRestoreWithRealImage(t *testing.T) {
	p, g := realVault(t)
	if err := Open(p, g, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(p.ClaudeDir, "projects", "-x")
	os.MkdirAll(proj, 0o700)
	os.WriteFile(filepath.Join(proj, "s.jsonl"), []byte(`{"secret":"A123456789"}`+"\n"), 0o600)
	os.Symlink("s.jsonl", filepath.Join(proj, "link"))
	os.WriteFile(filepath.Join(p.ClaudeDir, "history.jsonl"), []byte("h\n"), 0o600)

	plans := MigratePlan(p, g, []string{"projects", "plans"}, []string{"history.jsonl"})
	if err := Migrate(p, g, plans, func(string) {}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"projects", "plans", "history.jsonl"} {
		fi, err := os.Lstat(filepath.Join(p.ClaudeDir, n))
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s is not a symlink after migrate", n)
		}
	}
	if b, err := os.ReadFile(filepath.Join(proj, "s.jsonl")); err != nil || !strings.Contains(string(b), "A123456789") {
		t.Fatalf("data not readable through link: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(p.ClaudeDir, "projects.claudeshield-old")); err == nil {
		t.Fatal("plaintext original left behind")
	}
	// Running again is a no-op.
	if err := Migrate(p, g, MigratePlan(p, g, []string{"projects", "plans"}, []string{"history.jsonl"}), func(string) {}); err != nil {
		t.Fatal(err)
	}

	// Closed vault: the link dangles and nothing can be written through it.
	if err := Close(p, g, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.ClaudeDir, "history.jsonl"), []byte("leak"), 0o600); err == nil {
		t.Fatal("write through a closed vault's link succeeded")
	}
	if err := os.MkdirAll(filepath.Join(p.ClaudeDir, "projects", "-y"), 0o700); err == nil {
		t.Fatal("mkdir through a closed vault's link succeeded")
	}

	if err := Open(p, g, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	if err := Restore(p, g, MigratePlan(p, g, []string{"projects", "plans"}, []string{"history.jsonl"}), func(string) {}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(filepath.Join(p.ClaudeDir, "projects"))
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		t.Fatal("restore did not bring back a real directory")
	}
	if l, err := os.Readlink(filepath.Join(proj, "link")); err != nil || l != "s.jsonl" {
		t.Fatalf("symlink inside tree not preserved: %q %v", l, err)
	}
}
