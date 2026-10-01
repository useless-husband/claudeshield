// Package preflight checks, before and during a session, that the path from
// this machine to Anthropic has not been redirected or intercepted, that the
// local transcript store is protected, that the account's data terms fit the
// workspace, and that no unapproved extension has appeared.
package preflight

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/config"
)

// Severity of a finding.
type Severity int

const (
	Info Severity = iota
	Warn
	Block
)

func (s Severity) String() string {
	switch s {
	case Block:
		return "block"
	case Warn:
		return "warn"
	}
	return "info"
}

// MarshalJSON writes the severity as a word.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON reads the word form.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch v {
	case "block":
		*s = Block
	case "warn":
		*s = Warn
	default:
		*s = Info
	}
	return nil
}

// Finding is one problem (or one passed check, at Info).
type Finding struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Fix      string   `json:"fix,omitempty"`
	// Fingerprint identifies the exact value behind the finding (a proxy URL,
	// a certificate, an MCP server's command). Acknowledging a finding stores
	// the fingerprint; a different value later blocks again.
	Fingerprint string `json:"fingerprint,omitempty"`
	// NoAck marks findings that cannot be acknowledged away.
	NoAck bool `json:"no_ack,omitempty"`
	Acked bool `json:"acked,omitempty"`
}

// Report is the result of one preflight run.
type Report struct {
	At        time.Time `json:"at"`
	Cwd       string    `json:"cwd"`
	Workspace string    `json:"workspace,omitempty"`
	Findings  []Finding `json:"findings"`
}

// Blocked reports whether any finding blocks.
func (r Report) Blocked() bool {
	for _, f := range r.Findings {
		if f.Severity == Block {
			return true
		}
	}
	return false
}

// Count returns how many findings have the given severity.
func (r Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Problems returns Block and Warn findings, blocks first.
func (r Report) Problems() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity > Info {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity > out[j].Severity })
	return out
}

// ApplyAcks downgrades acknowledged Block findings to Warn.
func (r *Report) ApplyAcks(acks map[string]string) {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Severity != Block || f.NoAck || f.Fingerprint == "" {
			continue
		}
		if acks[f.ID] == f.Fingerprint {
			f.Severity = Warn
			f.Acked = true
		}
	}
}

// Fingerprint hashes the parts that define a finding's underlying value.
func Fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:8])
}

// sessionFile is where a session's last report is cached.
func sessionFile(p config.Paths, sessionID string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, sessionID)
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(p.SessionDir(), safe+".json")
}

// SaveSession caches a report for a session.
func SaveSession(p config.Paths, sessionID string, r Report) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(sessionFile(p, sessionID), b, 0o600)
}

// LoadSession returns the cached report; ok is false if there is none.
func LoadSession(p config.Paths, sessionID string) (Report, bool) {
	b, err := os.ReadFile(sessionFile(p, sessionID))
	if err != nil {
		return Report{}, false
	}
	var r Report
	if json.Unmarshal(b, &r) != nil {
		return Report{}, false
	}
	return r, true
}

// PruneSessions deletes cached reports older than maxAge.
func PruneSessions(p config.Paths, maxAge time.Duration, now time.Time) {
	entries, err := os.ReadDir(p.SessionDir())
	if errors.Is(err, fs.ErrNotExist) || err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > maxAge {
			os.Remove(filepath.Join(p.SessionDir(), e.Name()))
		}
	}
}
