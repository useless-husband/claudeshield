package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/useless-husband/claudeshield/internal/config"
)

// Hdiutil runs hdiutil; tests replace it.
var Hdiutil = func(stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("hdiutil", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// DefaultImage is where `vault create` puts the image unless told otherwise.
func DefaultImage(p config.Paths) string {
	return filepath.Join(p.State, "ClaudeVault.sparsebundle")
}

// Create makes an AES-256 encrypted, APFS-formatted sparse bundle. Sparse
// bundles grow as data is added, so the size is a ceiling, not an allocation.
// The image is made of many small band files, which suits Time Machine: a
// backup copies only changed bands, and every band is ciphertext.
func Create(image, volume, sizeSpec string, password []byte) error {
	if exists(image) {
		return fmt.Errorf("%s already exists", image)
	}
	if err := os.MkdirAll(filepath.Dir(image), 0o700); err != nil {
		return err
	}
	// -stdinpass reads until NUL or EOF; no trailing newline may be sent.
	out, err := Hdiutil(password, "create", "-quiet", "-size", sizeSpec, "-type", "SPARSEBUNDLE", "-fs", "APFS",
		"-volname", volume, "-encryption", "AES-256", "-stdinpass", image)
	if err != nil {
		return fmt.Errorf("hdiutil create: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Open attaches the image. -owners on enforces file ownership on the volume.
// (-nobrowse would hide it from Finder, but macOS 27 deprecates that flag on
// hdiutil and prints a warning, so the volume stays visible.)
func Open(p config.Paths, g config.Global, password []byte) error {
	if Mounted(p, g) {
		return nil
	}
	out, err := Hdiutil(password, "attach", "-owners", "on", "-stdinpass", g.Vault.Image)
	if err != nil {
		if strings.Contains(out, "Authentication error") {
			return ErrWrongPassword
		}
		return fmt.Errorf("hdiutil attach: %v: %s", err, strings.TrimSpace(out))
	}
	if !Mounted(p, g) {
		return fmt.Errorf("attached, but %s is not a mount point (volume name changed?)", MountPoint(p, g))
	}
	return os.MkdirAll(filepath.Join(MountPoint(p, g), "claude"), 0o700)
}

// ErrWrongPassword is returned when hdiutil rejects the passphrase.
var ErrWrongPassword = errors.New("wrong password")

// Close detaches the volume. hdiutil refuses while files are open, which is
// what we want: closing under a running Claude Code would lose writes.
func Close(p config.Paths, g config.Global, force bool) error {
	if !Mounted(p, g) {
		return nil
	}
	args := []string{"detach", "-quiet", MountPoint(p, g)}
	if force {
		args = append(args, "-force")
	}
	out, err := Hdiutil(nil, args...)
	if err != nil {
		return fmt.Errorf("hdiutil detach: %v: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// Plan describes one item migrate would move.
type Plan struct {
	Name    string // relative to ~/.claude
	Src     string
	Dst     string
	Exists  bool // the source exists and has data
	Linked  bool // already a symlink into the vault
	IsFile  bool
	Entries int
	Bytes   int64
}

// MigratePlan lists what would move for the given names.
func MigratePlan(p config.Paths, g config.Global, dirs, files []string) []Plan {
	mp := MountPoint(p, g)
	var plans []Plan
	for _, names := range []struct {
		list   []string
		isFile bool
	}{{dirs, false}, {files, true}} {
		for _, n := range names.list {
			pl := Plan{Name: n, Src: filepath.Join(p.ClaudeDir, n), Dst: filepath.Join(mp, "claude", n), IsFile: names.isFile}
			if fi, err := os.Lstat(pl.Src); err == nil {
				if fi.Mode()&os.ModeSymlink != 0 {
					if t, err := os.Readlink(pl.Src); err == nil && strings.HasPrefix(t, mp+"/") {
						pl.Linked = true
					}
				} else {
					pl.Exists = true
					pl.Entries, pl.Bytes = treeSize(pl.Src)
				}
			}
			plans = append(plans, pl)
		}
	}
	return plans
}

func treeSize(root string) (int, int64) {
	var n int
	var b int64
	filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
			if fi, err := d.Info(); err == nil {
				b += fi.Size()
			}
		}
		return nil
	})
	return n, b
}

// Migrate moves each planned item into the vault and leaves a symlink behind.
//
// Order per item: copy to <dst>.partial, verify file count and bytes, rename
// into place, move the original aside, create the symlink, then delete the
// original. A failure at any step leaves either the original in place or the
// verified copy linked, never neither.
//
// Because /Volumes is owned by root, once the vault is detached the links
// point at a path no ordinary process can create, so Claude Code cannot fall
// back to writing plaintext there.
func Migrate(p config.Paths, g config.Global, plans []Plan, progress func(string)) error {
	if !Mounted(p, g) {
		return errors.New("vault is not open")
	}
	for _, pl := range plans {
		if pl.Linked {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(pl.Dst), 0o700); err != nil {
			return err
		}
		if pl.Exists {
			if exists(pl.Dst) {
				return fmt.Errorf("%s already exists in the vault; refusing to overwrite", pl.Dst)
			}
			progress(pl.Name)
			partial := pl.Dst + ".partial"
			os.RemoveAll(partial)
			if err := copyTree(pl.Src, partial); err != nil {
				os.RemoveAll(partial)
				return fmt.Errorf("copy %s: %w", pl.Name, err)
			}
			if n, b := treeSize(partial); n != pl.Entries || b != pl.Bytes {
				os.RemoveAll(partial)
				return fmt.Errorf("copy of %s does not match (%d files/%d bytes vs %d/%d); nothing was changed", pl.Name, n, b, pl.Entries, pl.Bytes)
			}
			if err := os.Rename(partial, pl.Dst); err != nil {
				return err
			}
			aside := pl.Src + ".claudeshield-old"
			if err := os.Rename(pl.Src, aside); err != nil {
				return err
			}
			if err := os.Symlink(pl.Dst, pl.Src); err != nil {
				os.Rename(aside, pl.Src) // put the original back
				return err
			}
			if err := os.RemoveAll(aside); err != nil {
				return fmt.Errorf("linked %s, but could not delete the plaintext original %s: %w", pl.Name, aside, err)
			}
			continue
		}
		// Nothing there yet: create it inside the vault so future data lands there.
		if pl.IsFile {
			f, err := os.OpenFile(pl.Dst, os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			f.Close()
		} else if err := os.MkdirAll(pl.Dst, 0o700); err != nil {
			return err
		}
		if _, err := os.Lstat(pl.Src); err == nil {
			continue // something appeared meanwhile; leave it for the next run
		}
		if err := os.Symlink(pl.Dst, pl.Src); err != nil {
			return err
		}
	}
	return nil
}

// Restore reverses Migrate: copies data back out of the vault and removes the links.
func Restore(p config.Paths, g config.Global, plans []Plan, progress func(string)) error {
	if !Mounted(p, g) {
		return errors.New("vault is not open")
	}
	for _, pl := range plans {
		if !pl.Linked {
			continue
		}
		progress(pl.Name)
		tmp := pl.Src + ".claudeshield-restore"
		os.RemoveAll(tmp)
		if err := copyTree(pl.Dst, tmp); err != nil {
			os.RemoveAll(tmp)
			return err
		}
		if err := os.Remove(pl.Src); err != nil { // the symlink
			return err
		}
		if err := os.Rename(tmp, pl.Src); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies files, directories and symlinks, preserving permissions.
func copyTree(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return copyFile(src, dst, fi)
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			return os.MkdirAll(target, info.Mode().Perm()|0o700)
		case info.Mode()&os.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(t, target)
		case info.Mode().IsRegular():
			return copyFile(p, target, info)
		}
		return nil // sockets, fifos: skip
	})
}

func copyFile(src, dst string, fi fs.FileInfo) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// RunningClaude lists PIDs of Claude Code processes (CLI or desktop), which
// must be closed before migrating.
func RunningClaude(psOutput string) []string {
	var pids []string
	for _, line := range strings.Split(psOutput, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		cmd := f[1]
		base := filepath.Base(cmd)
		if base == "claude" || strings.Contains(cmd, "/.local/share/claude/versions/") || strings.Contains(cmd, "/Claude.app/Contents/MacOS/Claude") {
			pids = append(pids, f[0]+" "+base)
		}
	}
	sort.Strings(pids)
	return pids
}
