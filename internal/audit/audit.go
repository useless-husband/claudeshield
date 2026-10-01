// Package audit inventories everything that can run code or receive data
// inside Claude Code (hooks, MCP servers, plugins, skills, agents, commands,
// status lines, API key helpers) and compares it with a baseline the user
// approved. Anything new or changed blocks the session until it is reviewed.
//
// Each of these extensions sees conversation content or runs with the user's
// privileges, so an addition the user did not make (a plugin auto-update that
// adds a hook, a cloned repository's .mcp.json) is exactly the kind of quiet
// change that turns into a leak.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/i18n"
	"github.com/useless-husband/claudeshield/internal/preflight"
)

// Item is one extension.
type Item struct {
	Scope  string `json:"scope"`  // user, managed, project:<root>, local:<root>
	Kind   string `json:"kind"`   // hook, mcp, plugin, skill, agent, command, statusLine, apiKeyHelper
	Name   string `json:"name"`   // stable name within scope and kind
	Detail string `json:"detail"` // what a person needs to judge it (command line, URL, version)
	Hash   string `json:"hash"`   // content hash; changes when the extension changes
}

// Key identifies an item across runs.
func (it Item) Key() string { return it.Scope + "|" + it.Kind + "|" + it.Name }

// Baseline is the approved inventory.
type Baseline struct {
	Version int                  `json:"version"`
	Items   map[string]BaseEntry `json:"items"`
}

// BaseEntry is one approved item.
type BaseEntry struct {
	Hash       string    `json:"hash"`
	Detail     string    `json:"detail"`
	ApprovedAt time.Time `json:"approved_at"`
}

// Options for an inventory.
type Options struct {
	Paths config.Paths
	Cwd   string
	// Self is claudeshield's own executable; its hooks are not reported.
	Self string
}

// Collect builds the inventory for a working directory: user- and
// managed-scope items always, project-scope items for the project containing cwd.
func Collect(o Options) ([]Item, error) {
	var items []Item
	add := func(it Item) { items = append(items, it) }
	settings := []struct{ scope, path string }{
		{"user", filepath.Join(o.Paths.ClaudeDir, "settings.json")},
		{"user", filepath.Join(o.Paths.ClaudeDir, "settings.local.json")},
		{"managed", filepath.Join(o.Paths.ManagedDir, "managed-settings.json")},
	}
	root := ProjectRoot(o.Paths, o.Cwd)
	if root != "" {
		settings = append(settings,
			struct{ scope, path string }{"project:" + root, filepath.Join(root, ".claude", "settings.json")},
			struct{ scope, path string }{"local:" + root, filepath.Join(root, ".claude", "settings.local.json")})
	}
	enabledPlugins := map[string]bool{}
	for _, s := range settings {
		m, err := preflight.ReadSettings(s.path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		if m == nil {
			continue
		}
		for _, it := range hookItems(s.scope, m["hooks"], o.Self) {
			add(it)
		}
		if sl, ok := m["statusLine"].(map[string]any); ok {
			d := fmt.Sprint(sl["command"])
			add(Item{Scope: s.scope, Kind: "statusLine", Name: "statusLine", Detail: d, Hash: hashString(d)})
		}
		if h, ok := m["apiKeyHelper"].(string); ok && h != "" {
			add(Item{Scope: s.scope, Kind: "apiKeyHelper", Name: "apiKeyHelper", Detail: h, Hash: hashString(h)})
		}
		if ep, ok := m["enabledPlugins"].(map[string]any); ok {
			for id, v := range ep {
				if b, _ := v.(bool); b {
					enabledPlugins[id] = true
				}
			}
		}
	}

	// MCP servers: user scope and per-project local scope live in ~/.claude.json,
	// project scope in <root>/.mcp.json.
	if b, err := os.ReadFile(o.Paths.ClaudeJSON); err == nil {
		var cj struct {
			MCP      map[string]any `json:"mcpServers"`
			Projects map[string]struct {
				MCP map[string]any `json:"mcpServers"`
			} `json:"projects"`
		}
		if json.Unmarshal(b, &cj) == nil {
			for name, def := range cj.MCP {
				add(mcpItem("user", name, def))
			}
			if root != "" {
				for name, def := range cj.Projects[root].MCP {
					add(mcpItem("local:"+root, name, def))
				}
			}
		}
	}
	if root != "" {
		if b, err := os.ReadFile(filepath.Join(root, ".mcp.json")); err == nil {
			var mj struct {
				MCP map[string]any `json:"mcpServers"`
			}
			if json.Unmarshal(b, &mj) == nil {
				for name, def := range mj.MCP {
					add(mcpItem("project:"+root, name, def))
				}
			}
		}
	}

	// Plugins: hash the installed tree of every enabled plugin.
	if b, err := os.ReadFile(filepath.Join(o.Paths.ClaudeDir, "plugins", "installed_plugins.json")); err == nil {
		var ip struct {
			Plugins map[string][]struct {
				Scope       string `json:"scope"`
				InstallPath string `json:"installPath"`
				Version     string `json:"version"`
				Commit      string `json:"gitCommitSha"`
			} `json:"plugins"`
		}
		if json.Unmarshal(b, &ip) == nil {
			for id, insts := range ip.Plugins {
				if !enabledPlugins[id] {
					continue
				}
				for _, in := range insts {
					h, n, err := hashTree(in.InstallPath)
					if err != nil {
						h = "unreadable:" + err.Error()
					}
					detail := fmt.Sprintf("v%s, %d files", in.Version, n)
					if in.Commit != "" {
						detail += ", commit " + shortSHA(in.Commit)
					}
					add(Item{Scope: "user", Kind: "plugin", Name: id, Detail: detail, Hash: h})
				}
			}
		}
	}

	// Skills, agents and commands, user-level and project-level.
	dirs := []struct{ scope, base string }{{"user", o.Paths.ClaudeDir}}
	if root != "" {
		dirs = append(dirs, struct{ scope, base string }{"project:" + root, filepath.Join(root, ".claude")})
	}
	for _, d := range dirs {
		for _, kind := range []string{"skills", "agents", "commands"} {
			entries, err := os.ReadDir(filepath.Join(d.base, kind))
			if err != nil {
				continue
			}
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".") {
					continue
				}
				p := filepath.Join(d.base, kind, e.Name())
				h, n, err := hashTree(p)
				if err != nil {
					continue
				}
				add(Item{Scope: d.scope, Kind: strings.TrimSuffix(kind, "s"), Name: e.Name(), Detail: fmt.Sprintf("%d files", n), Hash: h})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key() < items[j].Key() })
	return items, nil
}

// ProjectRoot mirrors where Claude Code looks for project settings.
func ProjectRoot(p config.Paths, cwd string) string {
	if cwd == "" {
		return ""
	}
	dir, _ := filepath.Abs(cwd)
	for {
		if dir == p.Home {
			return ""
		}
		for _, m := range []string{".git", ".claude", ".mcp.json"} {
			if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func hookItems(scope string, v any, self string) []Item {
	events, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var out []Item
	for event, groups := range events {
		gl, _ := groups.([]any)
		for gi, g := range gl {
			gm, _ := g.(map[string]any)
			matcher := fmt.Sprint(gm["matcher"])
			if gm["matcher"] == nil {
				matcher = "*"
			}
			hl, _ := gm["hooks"].([]any)
			for hi, h := range hl {
				hm, _ := h.(map[string]any)
				detail := describeHook(hm)
				if self != "" && isSelf(hm, self) {
					continue
				}
				out = append(out, Item{Scope: scope, Kind: "hook", Name: fmt.Sprintf("%s[%s]#%d.%d", event, matcher, gi, hi), Detail: detail, Hash: hashString(canonical(hm))})
			}
		}
	}
	return out
}

func isSelf(h map[string]any, self string) bool {
	cmd, _ := h["command"].(string)
	return cmd == self || strings.HasPrefix(cmd, self+" ")
}

func describeHook(h map[string]any) string {
	t := fmt.Sprint(h["type"])
	switch t {
	case "command":
		s := fmt.Sprint(h["command"])
		if args, ok := h["args"].([]any); ok {
			for _, a := range args {
				s += " " + fmt.Sprint(a)
			}
		}
		return "command: " + s
	case "http":
		return "http: " + fmt.Sprint(h["url"])
	case "mcp_tool":
		return "mcp_tool: " + fmt.Sprint(h["server"]) + "/" + fmt.Sprint(h["tool"])
	case "prompt", "agent":
		p := fmt.Sprint(h["prompt"])
		if len(p) > 80 {
			p = p[:80] + "…"
		}
		return t + ": " + p
	}
	return t
}

func mcpItem(scope, name string, def any) Item {
	m, _ := def.(map[string]any)
	var parts []string
	if t, ok := m["type"].(string); ok {
		parts = append(parts, t)
	}
	if c, ok := m["command"].(string); ok {
		s := c
		if args, ok := m["args"].([]any); ok {
			for _, a := range args {
				s += " " + fmt.Sprint(a)
			}
		}
		parts = append(parts, s)
	}
	if u, ok := m["url"].(string); ok {
		parts = append(parts, u)
	}
	// Environment and header values are hashed, never shown: they often hold tokens.
	if env, ok := m["env"].(map[string]any); ok && len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts = append(parts, "env: "+strings.Join(keys, ","))
	}
	return Item{Scope: scope, Kind: "mcp", Name: name, Detail: strings.Join(parts, " "), Hash: hashString(canonical(m))}
}

// canonical serialises a decoded JSON value with sorted keys.
func canonical(v any) string {
	b, _ := json.Marshal(v) // encoding/json sorts map keys
	return string(b)
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:12])
}

// hashTree hashes every regular file under root (path, mode, content).
// Symlinks are hashed by target, not followed.
func hashTree(root string) (string, int, error) {
	st, err := os.Lstat(root)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n := 0
	if !st.IsDir() {
		if err := hashFile(h, root, filepath.Base(root), st); err != nil {
			return "", 0, err
		}
		return hex.EncodeToString(h.Sum(nil)[:12]), 1, nil
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		n++
		return hashFile(h, p, rel, info)
	})
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)[:12]), n, nil
}

func hashFile(h io.Writer, p, rel string, info fs.FileInfo) error {
	fmt.Fprintf(h, "%s\x00%o\x00", rel, info.Mode().Perm())
	if info.Mode()&os.ModeSymlink != 0 {
		t, _ := os.Readlink(p)
		fmt.Fprintf(h, "link:%s\x00", t)
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(h, f)
	h.Write([]byte{0})
	return err
}

func shortSHA(s string) string {
	if len(s) > 10 {
		return s[:10]
	}
	return s
}

// LoadBaseline reads the approved inventory; ok is false if none exists.
func LoadBaseline(p config.Paths) (Baseline, bool, error) {
	b, err := os.ReadFile(p.BaselineFile())
	if errors.Is(err, fs.ErrNotExist) {
		return Baseline{Version: 1, Items: map[string]BaseEntry{}}, false, nil
	}
	if err != nil {
		return Baseline{}, false, err
	}
	var bl Baseline
	if err := json.Unmarshal(b, &bl); err != nil {
		return Baseline{}, false, err
	}
	if bl.Items == nil {
		bl.Items = map[string]BaseEntry{}
	}
	return bl, true, nil
}

// SaveBaseline writes the approved inventory.
func SaveBaseline(p config.Paths, bl Baseline) error {
	b, err := json.MarshalIndent(bl, "", "  ")
	if err != nil {
		return err
	}
	return config.WriteFileAtomic(p.BaselineFile(), append(b, '\n'), 0o600)
}

// Change is one difference between inventory and baseline.
type Change struct {
	Item
	Was string // previous detail for changed items
	Op  string // "new", "changed", "removed"
}

// Diff compares current items with the baseline, restricted to the scopes
// present in this inventory (user, managed, and this project).
func Diff(items []Item, bl Baseline, root string) []Change {
	var out []Change
	seen := map[string]bool{}
	for _, it := range items {
		seen[it.Key()] = true
		be, ok := bl.Items[it.Key()]
		switch {
		case !ok:
			out = append(out, Change{Item: it, Op: "new"})
		case be.Hash != it.Hash:
			out = append(out, Change{Item: it, Op: "changed", Was: be.Detail})
		}
	}
	for k, be := range bl.Items {
		if seen[k] {
			continue
		}
		scope := strings.SplitN(k, "|", 2)[0]
		if scope == "user" || scope == "managed" || (root != "" && (scope == "project:"+root || scope == "local:"+root)) {
			parts := strings.SplitN(k, "|", 3)
			out = append(out, Change{Item: Item{Scope: parts[0], Kind: parts[1], Name: parts[2], Detail: be.Detail}, Op: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// Approve records the given items in the baseline, replacing the entries of
// the scopes they cover (so removed items disappear too).
func Approve(bl Baseline, items []Item, root string, now time.Time) Baseline {
	for k := range bl.Items {
		scope := strings.SplitN(k, "|", 2)[0]
		if scope == "user" || scope == "managed" || (root != "" && (scope == "project:"+root || scope == "local:"+root)) {
			delete(bl.Items, k)
		}
	}
	for _, it := range items {
		bl.Items[it.Key()] = BaseEntry{Hash: it.Hash, Detail: it.Detail, ApprovedAt: now.UTC().Truncate(time.Second)}
	}
	bl.Version = 1
	return bl
}

// Findings turns the diff into preflight findings.
func Findings(o Options) []preflight.Finding {
	items, err := Collect(o)
	if err != nil {
		return []preflight.Finding{{ID: "audit.error", Severity: preflight.Warn, Title: i18n.T("無法盤點 Claude Code 的擴充功能", "Could not inventory Claude Code extensions"), Detail: err.Error()}}
	}
	bl, ok, err := LoadBaseline(o.Paths)
	if err != nil {
		return []preflight.Finding{{ID: "audit.error", Severity: preflight.Block, NoAck: true, Title: i18n.T("核可清單檔案壞掉了", "The approved-extension baseline is corrupt"), Detail: err.Error(), Fix: "claudeshield audit approve"}}
	}
	if !ok {
		return []preflight.Finding{{ID: "audit.nobaseline", Severity: preflight.Warn,
			Title: i18n.T("還沒有記錄擴充功能的核可清單", "No approved-extension baseline yet"),
			Fix:   i18n.T("claudeshield audit 看目前裝了什麼，確認沒問題後 claudeshield audit approve", "Review with `claudeshield audit`, then `claudeshield audit approve`")}}
	}
	root := ProjectRoot(o.Paths, o.Cwd)
	var out []preflight.Finding
	var lines []string
	for _, c := range Diff(items, bl, root) {
		switch c.Op {
		case "new":
			lines = append(lines, i18n.Tf("＋ 新增 %s %s（%s）：%s", "+ new %s %s (%s): %s", c.Kind, c.Name, c.Scope, c.Detail))
		case "changed":
			lines = append(lines, i18n.Tf("～ 變更 %s %s（%s）：%s", "~ changed %s %s (%s): %s", c.Kind, c.Name, c.Scope, c.Detail))
		}
	}
	if len(lines) > 0 {
		out = append(out, preflight.Finding{ID: "audit.drift", Severity: preflight.Block, NoAck: true,
			Title:  i18n.Tf("有 %d 個擴充功能是新的或被改過，還沒核可", "%d extension(s) are new or changed and not yet approved", len(lines)),
			Detail: strings.Join(lines, "\n"),
			Fix:    i18n.T("確認每一項都是你自己裝的，再執行 claudeshield audit approve；不認得的先移除。", "Make sure each one is yours, then run `claudeshield audit approve`; remove anything you do not recognise."),
		})
	} else {
		out = append(out, preflight.Finding{ID: "audit", Severity: preflight.Info, Title: i18n.Tf("擴充功能和核可清單一致（%d 項）", "Extensions match the approved baseline (%d items)", len(items))})
	}
	return out
}
