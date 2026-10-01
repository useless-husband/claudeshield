// Package config locates claudeshield's own files and Claude Code's, and loads
// the two configuration files: the global one in ~/.claudeshield/config.json
// and the per-workspace .claudeshield.json that marks a folder as sensitive.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/detect"
)

// WorkspaceFile is the marker file name.
const WorkspaceFile = ".claudeshield.json"

// Paths holds every location claudeshield reads or writes. Tests build one
// pointing into a temp dir; production code uses Default().
type Paths struct {
	Home         string // the user's home directory
	State        string // ~/.claudeshield
	ClaudeDir    string // ~/.claude (or CLAUDE_CONFIG_DIR)
	ClaudeJSON   string // ~/.claude.json
	ManagedDir   string // /Library/Application Support/ClaudeCode
	VolumesDir   string // /Volumes
	Executable   string // absolute path of this binary, for hook commands
	ClaudeBinary string // optional override for the claude executable
}

// Default resolves the real locations, honouring CLAUDESHIELD_HOME and
// CLAUDE_CONFIG_DIR.
func Default() Paths {
	home, _ := os.UserHomeDir()
	p := Paths{
		Home:       home,
		State:      filepath.Join(home, ".claudeshield"),
		ClaudeDir:  filepath.Join(home, ".claude"),
		ClaudeJSON: filepath.Join(home, ".claude.json"),
		ManagedDir: "/Library/Application Support/ClaudeCode",
		VolumesDir: "/Volumes",
	}
	if v := os.Getenv("CLAUDESHIELD_HOME"); v != "" {
		p.State = v
	}
	if v := os.Getenv("CLAUDE_CONFIG_DIR"); v != "" {
		p.ClaudeDir = v
		p.ClaudeJSON = filepath.Join(v, ".claude.json")
	}
	if exe, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		p.Executable = exe
	}
	return p
}

// GlobalFile is ~/.claudeshield/config.json.
func (p Paths) GlobalFile() string { return filepath.Join(p.State, "config.json") }

// BaselineFile stores the approved inventory of extensions.
func (p Paths) BaselineFile() string { return filepath.Join(p.State, "baseline.json") }

// PinsFile stores learned TLS pins.
func (p Paths) PinsFile() string { return filepath.Join(p.State, "pins.json") }

// SessionDir holds per-session preflight results.
func (p Paths) SessionDir() string { return filepath.Join(p.State, "sessions") }

// EventLog is the append-only decision log (never contains sensitive values).
func (p Paths) EventLog() string { return filepath.Join(p.State, "events.log") }

// Global is ~/.claudeshield/config.json.
type Global struct {
	Lang string `json:"lang,omitempty"`
	// GlobalMasking runs the Basic detector in every session. Pointer so that
	// "absent" means the default (on) and an explicit false sticks.
	GlobalMasking *bool    `json:"global_masking,omitempty"`
	AllowHosts    []string `json:"allow_hosts,omitempty"`
	// Allow lists values never masked in ordinary sessions (same syntax as
	// the workspace allow list).
	Allow []string `json:"allow,omitempty"`
	// Acknowledged maps a finding ID to the fingerprint the user accepted.
	// If the underlying value changes, the fingerprint no longer matches and
	// the finding blocks again.
	Acknowledged map[string]string `json:"acknowledged,omitempty"`
	Account      AccountState      `json:"account"`
	Vault        VaultConfig       `json:"vault"`
	TLS          TLSConfig         `json:"tls"`
	Installed    *InstallRecord    `json:"installed,omitempty"`
}

// AccountState records the user's own confirmation of a setting claudeshield
// cannot read locally (the consumer "Help improve Claude" switch).
type AccountState struct {
	TrainingOffConfirmedAt time.Time `json:"training_off_confirmed_at,omitempty"`
}

// VaultConfig points at the encrypted disk image.
type VaultConfig struct {
	Image  string `json:"image,omitempty"`  // path to the .sparsebundle
	Volume string `json:"volume,omitempty"` // volume name, mounted at /Volumes/<name>
}

// TLSConfig lists hosts to verify and extra trusted root pins.
type TLSConfig struct {
	Hosts      []string `json:"hosts,omitempty"`
	ExtraRoots []string `json:"extra_roots_spki_sha256,omitempty"`
}

// InstallRecord remembers what install wrote, so uninstall removes exactly that.
type InstallRecord struct {
	At         time.Time `json:"at"`
	Executable string    `json:"executable"`
	Settings   string    `json:"settings"`
	Backup     string    `json:"backup"`
}

// MaskingOn reports whether the Basic detector runs in every session.
func (g Global) MaskingOn() bool { return g.GlobalMasking == nil || *g.GlobalMasking }

// TLSHosts returns the hosts whose certificate chains are checked.
func (g Global) TLSHosts() []string {
	if len(g.TLS.Hosts) > 0 {
		return g.TLS.Hosts
	}
	return []string{"api.anthropic.com"}
}

// VaultVolume returns the vault volume name.
func (g Global) VaultVolume() string {
	if g.Vault.Volume != "" {
		return g.Vault.Volume
	}
	return "ClaudeVault"
}

// LoadGlobal reads the global config; a missing file is the zero config.
func LoadGlobal(p Paths) (Global, error) {
	var g Global
	b, err := os.ReadFile(p.GlobalFile())
	if errors.Is(err, fs.ErrNotExist) {
		return g, nil
	}
	if err != nil {
		return g, err
	}
	if err := json.Unmarshal(b, &g); err != nil {
		return g, err
	}
	return g, nil
}

// SaveGlobal writes the global config atomically with mode 0600.
func SaveGlobal(p Paths, g Global) error {
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(p.GlobalFile(), append(b, '\n'), 0o600)
}

// WriteFileAtomic writes via a temp file and rename, creating parent dirs 0700.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Workspace is a folder marked sensitive by a .claudeshield.json file.
type Workspace struct {
	Root            string              `json:"-"`
	Version         int                 `json:"version"`
	Categories      map[string]bool     `json:"categories,omitempty"`
	Terms           map[string][]string `json:"terms,omitempty"`
	InternalDomains []string            `json:"internal_domains,omitempty"`
	Allow           []string            `json:"allow,omitempty"`
	AllowHosts      []string            `json:"allow_hosts,omitempty"`
	// Protect lists globs (relative to Root) Claude may not touch at all, for
	// originals that must never be read even in masked form.
	Protect []string `json:"protect,omitempty"`
	// BinaryReads allows Read on PDFs, images and office files, whose content
	// claudeshield cannot mask. Off by default.
	BinaryReads bool `json:"binary_reads,omitempty"`
}

// DefaultWorkspace is what `claudeshield init` writes.
func DefaultWorkspace() Workspace {
	return Workspace{
		Version:    1,
		Categories: map[string]bool{"secret": true, "pii": true, "finance": true, "doc": true},
		Terms:      map[string][]string{"CLIENT": {}, "PROJECT": {}},
		Protect:    []string{"raw/**"},
	}
}

// FindWorkspace walks up from dir looking for the marker file. It stops at
// the filesystem root. ok is false when dir is not inside a workspace.
func FindWorkspace(dir string) (Workspace, bool, error) {
	if dir == "" {
		return Workspace{}, false, nil
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return Workspace{}, false, err
	}
	for {
		f := filepath.Join(dir, WorkspaceFile)
		b, err := os.ReadFile(f)
		if err == nil {
			var w Workspace
			if err := json.Unmarshal(b, &w); err != nil {
				return Workspace{}, true, &BadWorkspaceError{Path: f, Err: err}
			}
			w.Root = dir
			return w, true, nil
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			return Workspace{}, false, err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return Workspace{}, false, nil
		}
		dir = parent
	}
}

// BadWorkspaceError means a marker exists but cannot be parsed. Callers must
// treat the folder as sensitive anyway: a typo must not switch protection off.
type BadWorkspaceError struct {
	Path string
	Err  error
}

func (e *BadWorkspaceError) Error() string { return e.Path + ": " + e.Err.Error() }

// ID is a stable identifier for the workspace's token map.
func (w Workspace) ID() string {
	h := sha256.Sum256([]byte(w.Root))
	return hex.EncodeToString(h[:8])
}

// DetectorConfig builds the Strict detector config for this workspace.
func (w Workspace) DetectorConfig() detect.Config {
	c := detect.Config{
		Profile:         detect.Strict,
		Terms:           w.Terms,
		InternalDomains: w.InternalDomains,
		Allow:           append(append([]string(nil), detect.DefaultAllow...), w.Allow...),
	}
	if len(w.Categories) > 0 {
		c.Categories = map[detect.Category]bool{}
		for k, v := range w.Categories {
			c.Categories[detect.Category(strings.ToLower(k))] = v
		}
	}
	return c
}

// Protected reports whether an absolute path falls under one of the Protect globs.
func (w Workspace) Protected(abs string) bool {
	rel, err := filepath.Rel(w.Root, abs)
	if err != nil || strings.HasPrefix(rel, "..") {
		return false
	}
	rel = filepath.ToSlash(rel)
	for _, g := range w.Protect {
		if MatchGlob(g, rel) {
			return true
		}
	}
	return false
}

// Contains reports whether abs is inside the workspace.
func (w Workspace) Contains(abs string) bool {
	rel, err := filepath.Rel(w.Root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// MatchGlob matches slash-separated paths with "*" (one segment) and "**"
// (any number of segments, including none).
func MatchGlob(pattern, path string) bool {
	return matchSegs(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(path, "/"))
}

func matchSegs(p, s []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			for i := 0; i <= len(s); i++ {
				if matchSegs(p[1:], s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 {
			return false
		}
		if ok, _ := filepath.Match(p[0], s[0]); !ok {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}
