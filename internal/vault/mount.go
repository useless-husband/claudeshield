// Package vault manages the encrypted disk image that holds Claude Code's
// transcripts and claudeshield's token maps.
package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
// /Volumes is root-owned, so an ordinary process cannot fake one there, but
// any disk image can be attached under the vault's name. The marker file
// written at creation ties the mounted volume to this configuration.
func Mounted(p config.Paths, g config.Global) bool {
	mp := MountPoint(p, g)
	if !IsMountPoint(mp) {
		return false
	}
	if g.Vault.ID == "" {
		return true // created before markers existed; BackedBy still checks the image
	}
	b, err := os.ReadFile(MarkerPath(mp))
	return err == nil && strings.TrimSpace(string(b)) == g.Vault.ID
}

// MarkerPath is the identity file inside a mounted vault.
func MarkerPath(mountPoint string) string { return filepath.Join(mountPoint, ".claudeshield-id") }

// NewID returns a random vault identity.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// WriteMarker writes the identity file into the mounted volume.
func WriteMarker(mountPoint, id string) error {
	return os.WriteFile(MarkerPath(mountPoint), []byte(id+"\n"), 0o600)
}

// BackedBy asks hdiutil which image backs the vault's mount point and
// compares it with the configured image. ok is false when another image is
// attached there. err is set when the mount point is not attached at all or
// hdiutil's answer could not be read.
func BackedBy(p config.Paths, g config.Global) (ok bool, image string, err error) {
	out, err := Hdiutil(nil, "info", "-plist")
	if err != nil {
		return false, "", err
	}
	image, found := imageForMount(out, MountPoint(p, g))
	if !found {
		return false, "", errors.New("mount point not listed by hdiutil")
	}
	return config.Canonical(image) == config.Canonical(g.Vault.Image), image, nil
}

var plistKV = regexp.MustCompile(`<key>(image-path|mount-point)</key>\s*<string>([^<]*)</string>`)

// imageForMount scans hdiutil's plist: each image's path precedes the mount
// points of its entities.
func imageForMount(plist, mountPoint string) (string, bool) {
	current := ""
	for _, m := range plistKV.FindAllStringSubmatch(plist, -1) {
		switch m[1] {
		case "image-path":
			current = m[2]
		case "mount-point":
			if m[2] == mountPoint {
				return current, true
			}
		}
	}
	return "", false
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
