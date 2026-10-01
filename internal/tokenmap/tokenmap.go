// Package tokenmap keeps the two-way table between real sensitive values and
// the placeholders Claude sees, such as ⟦EMAIL_003⟧.
//
// The same value always maps to the same placeholder within one table, so
// Claude can still tell that two documents mention the same customer. The
// table is the only place the real values live outside the user's own files,
// which is why claudeshield keeps it inside the encrypted vault when one is
// mounted.
//
// Hooks run as separate short-lived processes, often several at once (Claude
// Code runs matching hooks in parallel and may issue parallel tool calls), so
// every read-modify-write happens under an exclusive flock and the file is
// replaced atomically.
package tokenmap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/detect"
)

// Entry is one row of the table.
type Entry struct {
	Token   string    `json:"t"`
	Kind    string    `json:"k"`
	Value   string    `json:"v"`
	Created time.Time `json:"c"`
}

type fileFormat struct {
	Version int            `json:"version"`
	Next    map[string]int `json:"next"`
	Entries []Entry        `json:"entries"`
}

// Map is an in-memory copy of a table. Obtain one with Update or Load.
type Map struct {
	byValue map[string]string
	byToken map[string]string
	next    map[string]int
	entries []Entry
	dirty   bool
	now     func() time.Time
}

func newMap() *Map {
	return &Map{byValue: map[string]string{}, byToken: map[string]string{}, next: map[string]int{}, now: time.Now}
}

// New returns an empty in-memory table (used by tests and the scan command).
func New() *Map { return newMap() }

// Load reads a table under a shared lock. A missing file is an empty table.
func Load(path string) (*Map, error) {
	if _, err := os.Stat(filepath.Dir(path)); errors.Is(err, fs.ErrNotExist) {
		return newMap(), nil
	}
	unlock, err := lock(path, false)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return read(path)
}

// Update loads the table under an exclusive lock, runs fn, and writes the
// table back if fn added entries.
func Update(path string, fn func(*Map) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := lock(path, true)
	if err != nil {
		return err
	}
	defer unlock()
	m, err := read(path)
	if err != nil {
		return err
	}
	if err := fn(m); err != nil {
		return err
	}
	if !m.dirty {
		return nil
	}
	return write(path, m)
}

func read(path string) (*Map, error) {
	m := newMap()
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	var f fileFormat
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("token map %s is corrupt: %w", path, err)
	}
	for k, v := range f.Next {
		m.next[k] = v
	}
	for _, e := range f.Entries {
		m.entries = append(m.entries, e)
		m.byValue[e.Value] = e.Token
		m.byToken[e.Token] = e.Value
	}
	return m, nil
}

func write(path string, m *Map) error {
	f := fileFormat{Version: 1, Next: m.next, Entries: m.entries}
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tokenmap-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Len is the number of entries.
func (m *Map) Len() int { return len(m.entries) }

// Entries returns a copy of the rows, ordered by token.
func (m *Map) Entries() []Entry {
	out := append([]Entry(nil), m.entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Token < out[j].Token })
	return out
}

// TokenFor returns the placeholder for value, creating one of the given kind
// if the value has not been seen before.
func (m *Map) TokenFor(kind, value string) string {
	if t, ok := m.byValue[value]; ok {
		return t
	}
	kind = detect.SanitizeKind(kind)
	m.next[kind]++
	t := fmt.Sprintf("⟦%s_%03d⟧", kind, m.next[kind])
	for m.byToken[t] != "" { // only possible if the file was edited by hand
		m.next[kind]++
		t = fmt.Sprintf("⟦%s_%03d⟧", kind, m.next[kind])
	}
	m.byValue[value] = t
	m.byToken[t] = value
	m.entries = append(m.entries, Entry{Token: t, Kind: kind, Value: value, Created: m.now().UTC().Truncate(time.Second)})
	m.dirty = true
	return t
}

// Value returns the real value behind a placeholder.
func (m *Map) Value(token string) (string, bool) {
	v, ok := m.byToken[token]
	return v, ok
}

// Mask replaces every value d finds in s with its placeholder.
//
// Masking can expose a new match: in "NT$1,000sk-ant-…" the key has no word
// boundary in front of it until the amount before it becomes "⟦AMOUNT_001⟧".
// Mask therefore repeats until nothing more is found, which also makes it
// idempotent. Placeholders are never matched, so each pass only shrinks the
// unmasked text and the loop ends; the cap is a guard, not a limit reached in
// practice.
func (m *Map) Mask(d *detect.Detector, s string) (string, []detect.Match) {
	var all []detect.Match
	for pass := 0; pass < 8; pass++ {
		out, ms := m.maskOnce(d, s)
		if len(ms) == 0 {
			break
		}
		all = append(all, ms...)
		s = out
	}
	return s, all
}

func (m *Map) maskOnce(d *detect.Detector, s string) (string, []detect.Match) {
	ms := d.Find(s)
	if len(ms) == 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, x := range ms {
		b.WriteString(s[last:x.Start])
		b.WriteString(m.TokenFor(x.Kind, x.Value))
		last = x.End
	}
	b.WriteString(s[last:])
	return b.String(), ms
}

// Unmask replaces known placeholders in s with their real values. Unknown
// placeholders are left in place and returned, so callers can tell Claude it
// invented one.
func (m *Map) Unmask(s string) (out string, replaced int, unknown []string) {
	if !strings.Contains(s, "⟦") {
		return s, 0, nil
	}
	out = detect.TokenRE.ReplaceAllStringFunc(s, func(t string) string {
		if v, ok := m.byToken[t]; ok {
			replaced++
			return v
		}
		unknown = append(unknown, t)
		return t
	})
	return out, replaced, unknown
}

// HasTokens reports whether s contains anything shaped like a placeholder.
func HasTokens(s string) bool {
	return strings.Contains(s, "⟦") && detect.TokenRE.MatchString(s)
}

// MaskJSON walks a decoded JSON value (maps, slices, strings, numbers) and
// masks every string leaf. Object keys are left alone so the shape, which
// Claude Code validates, never changes. Values under a key in skipKeys (for
// example "base64" image data) are left untouched. It returns the new value,
// how many values were masked, and the kinds found.
func (m *Map) MaskJSON(d *detect.Detector, v any, skipKeys map[string]bool) (any, int, map[string]int) {
	kinds := map[string]int{}
	n := 0
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			out, ms := m.Mask(d, x)
			for _, mm := range ms {
				kinds[mm.Kind]++
			}
			n += len(ms)
			return out
		case map[string]any:
			cp := make(map[string]any, len(x))
			for k, e := range x {
				if skipKeys[k] {
					cp[k] = e
					continue
				}
				cp[k] = walk(e)
			}
			return cp
		case []any:
			cp := make([]any, len(x))
			for i, e := range x {
				cp[i] = walk(e)
			}
			return cp
		default:
			return v
		}
	}
	return walk(v), n, kinds
}

// UnmaskJSON is the inverse walk: every string leaf has its placeholders replaced.
func (m *Map) UnmaskJSON(v any) (any, int, []string) {
	n := 0
	var unknown []string
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			out, r, u := m.Unmask(x)
			n += r
			unknown = append(unknown, u...)
			return out
		case map[string]any:
			cp := make(map[string]any, len(x))
			for k, e := range x {
				cp[k] = walk(e)
			}
			return cp
		case []any:
			cp := make([]any, len(x))
			for i, e := range x {
				cp[i] = walk(e)
			}
			return cp
		default:
			return v
		}
	}
	return walk(v), n, unknown
}

// JSONHasTokens reports whether any string leaf contains a placeholder.
func JSONHasTokens(v any) bool {
	switch x := v.(type) {
	case string:
		return HasTokens(x)
	case map[string]any:
		for _, e := range x {
			if JSONHasTokens(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if JSONHasTokens(e) {
				return true
			}
		}
	}
	return false
}
