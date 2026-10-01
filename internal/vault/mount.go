// Package vault manages the encrypted disk image that holds Claude Code's
// transcripts and claudeshield's token maps.
package vault

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/useless-husband/claudeshield/internal/config"
)

// MountPoint is where the vault volume appears when attached.
func MountPoint(p config.Paths, g config.Global) string {
	return filepath.Join(p.VolumesDir, g.VaultVolume())
}

// Configured reports whether the user has created a vault.
func Configured(g config.Global) bool { return g.Vault.Image != "" }

// Mounted reports whether the vault volume is attached. A directory that
// exists but sits on the same device as its parent is not a mount: on macOS
// /Volumes is root-owned, so an ordinary process cannot fake one there, but a
// test or a misconfigured VolumesDir could.
func Mounted(p config.Paths, g config.Global) bool {
	return IsMountPoint(MountPoint(p, g))
}

// IsMountPoint compares the device of dir with the device of its parent.
func IsMountPoint(dir string) bool {
	var st, pst syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return false
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return false
	}
	if err := syscall.Stat(filepath.Dir(dir), &pst); err != nil {
		return false
	}
	return st.Dev != pst.Dev
}

// DataDir is claudeshield's own folder inside the vault.
func DataDir(p config.Paths, g config.Global) string {
	return filepath.Join(MountPoint(p, g), "claudeshield")
}

// exists is a small helper shared by the vault commands.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// ErrClosed means a vault is configured but not attached.
var ErrClosed = errors.New("vault closed")

// MapPath is the token table for a workspace (or the "global" table when
// inWS is false). With a vault configured it lives inside the vault, and a
// closed vault is an error: never a silent fallback to an unencrypted file.
func MapPath(p config.Paths, g config.Global, ws config.Workspace, inWS bool) (string, error) {
	id := "global"
	if inWS && ws.Root != "" {
		id = ws.ID()
	}
	if Configured(g) {
		if !Mounted(p, g) {
			return "", ErrClosed
		}
		return filepath.Join(DataDir(p, g), "maps", id+".json"), nil
	}
	return filepath.Join(p.State, "maps", id+".json"), nil
}
