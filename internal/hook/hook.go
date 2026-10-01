// Package hook implements claudeshield's Claude Code hooks:
//
//   - SessionStart: run the preflight checks, tell Claude about placeholders.
//   - UserPromptSubmit: refuse prompts while a check is failing, and refuse
//     prompts that contain sensitive values (offering a masked version).
//   - PreToolUse: put real values back into local tool inputs, judge where
//     shell commands and fetches would send data, and keep Claude away from
//     protected and unmaskable files.
//   - PostToolUse: replace sensitive values in tool results with placeholders
//     before Claude sees them.
//
// Each invocation is a separate process: Claude Code writes one JSON object
// to stdin and reads one JSON object from stdout.
package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/detect"
	"github.com/useless-husband/claudeshield/internal/egress"
	"github.com/useless-husband/claudeshield/internal/i18n"
	"github.com/useless-husband/claudeshield/internal/preflight"
	"github.com/useless-husband/claudeshield/internal/tokenmap"
	"github.com/useless-husband/claudeshield/internal/vault"
)

// Input is the subset of Claude Code's hook payload claudeshield reads.
type Input struct {
	SessionID      string         `json:"session_id"`
	TranscriptPath string         `json:"transcript_path"`
	Cwd            string         `json:"cwd"`
	PermissionMode string         `json:"permission_mode"`
	HookEventName  string         `json:"hook_event_name"`
	ToolName       string         `json:"tool_name"`
	ToolInput      map[string]any `json:"tool_input"`
	ToolResponse   any            `json:"tool_response"`
	ToolUseID      string         `json:"tool_use_id"`
	Prompt         string         `json:"prompt"`
	Source         string         `json:"source"`
	AgentID        string         `json:"agent_id"`
}

// Env carries everything a hook needs from outside, so tests can run offline.
type Env struct {
	Paths  config.Paths
	Global config.Global
	Now    func() time.Time
	Getenv func(string) string
	// Preflight runs the full check set for a working directory.
	Preflight func(cwd string) preflight.Report
	// PreflightTTL is how long a passing report is reused by UserPromptSubmit.
	PreflightTTL time.Duration
	// GitRemoteURL resolves remote names in git commands (tests override it).
	GitRemoteURL func(dir, remote string) (string, bool)
	// ConfigErr is set when ~/.claudeshield/config.json could not be read;
	// every hook then fails (closed inside a workspace).
	ConfigErr error
}

func (e *Env) defaults() {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	if e.PreflightTTL == 0 {
		e.PreflightTTL = 10 * time.Minute
	}
	if e.Preflight == nil {
		e.Preflight = func(cwd string) preflight.Report { return preflight.Report{At: e.Now(), Cwd: cwd} }
	}
}

// Marker is the first line of a wrapped shell command; it makes wrapping
// idempotent and tells a reader of the permission prompt what was added.
const Marker = "# claudeshield: mask output even if the command fails"

// wrapShell makes a failing command exit 0 and append its real status.
// Claude Code routes a failed command's output to PostToolUseFailure, which
// can neither rewrite what Claude sees nor stop the turn (verified on
// v2.1.287: "continue": false is ignored there); a successful one goes through
// PostToolUse, which can. The command runs in a { } group in the same shell,
// so cd and variables behave as before. (An EXIT trap would also catch
// "exit N", but Claude Code's Bash tool rejects commands containing trap.) A
// command that itself calls exit still ends the shell early; see Limitations.
func wrapShell(cmd string) string {
	if strings.HasPrefix(cmd, Marker) {
		return cmd
	}
	return Marker + "\n{ " + cmd + "\n}; __cs_rc=$?; if [ \"$__cs_rc\" -ne 0 ]; then printf '\\n[exit status %s]\\n' \"$__cs_rc\"; fi; true"
}

// Run handles one hook event. It returns the process exit code.
func Run(event string, stdin io.Reader, stdout io.Writer, env Env) int {
	env.defaults()
	raw, err := io.ReadAll(io.LimitReader(stdin, 64<<20))
	if err != nil {
		return failure(stdout, event, env, "", fmt.Errorf("read stdin: %w", err))
	}
	var in Input
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // keep numbers exact when echoing tool inputs and outputs back
	if err := dec.Decode(&in); err != nil {
		return failure(stdout, event, env, "", fmt.Errorf("parse hook input: %w", err))
	}
	if in.Cwd == "" {
		in.Cwd = env.Getenv("CLAUDE_PROJECT_DIR")
	}
	if env.ConfigErr != nil {
		return failure(stdout, event, env, in.Cwd, fmt.Errorf("config: %w", env.ConfigErr))
	}
	h := &handler{env: env, in: in, out: stdout}
	switch event {
	case "session-start", "SessionStart":
		err = h.sessionStart()
	case "prompt", "UserPromptSubmit":
		err = h.userPrompt()
	case "pre-tool", "PreToolUse":
		err = h.preTool()
	case "post-tool", "PostToolUse":
		err = h.postTool()
	default:
		err = fmt.Errorf("unknown hook event %q", event)
	}
	if err != nil {
		return failure(stdout, event, env, in.Cwd, err)
	}
	return 0
}

// failure decides what an internal error means. Inside a sensitive workspace
// claudeshield fails closed: a prompt or tool call it could not inspect does
// not go through. Elsewhere it fails open with a visible warning, so a bug
// cannot freeze every Claude Code session on the machine.
func failure(w io.Writer, event string, env Env, cwd string, err error) int {
	_, inWS, _ := config.FindWorkspace(cwd)
	msg := i18n.Tf("ClaudeShield 內部錯誤（%s）：%v", "ClaudeShield internal error (%s): %v", event, err)
	logEvent(env, map[string]any{"event": event, "error": err.Error()})
	if inWS || cwd == "" {
		switch event {
		case "pre-tool", "PreToolUse":
			writeJSON(w, map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": msg}})
			return 0
		case "prompt", "UserPromptSubmit":
			writeJSON(w, map[string]any{"decision": "block", "reason": msg,
				"hookSpecificOutput": map[string]any{"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true}})
			return 0
		}
	}
	writeJSON(w, map[string]any{"systemMessage": msg})
	return 0
}

type handler struct {
	env Env
	in  Input
	out io.Writer

	ctxDone bool
	ws      config.Workspace
	inWS    bool
	wsErr   error
}

func (h *handler) context() {
	if h.ctxDone {
		return
	}
	h.ctxDone = true
	h.ws, h.inWS, h.wsErr = config.FindWorkspace(h.in.Cwd)
	if h.wsErr != nil {
		var bad *config.BadWorkspaceError
		if errors.As(h.wsErr, &bad) {
			h.inWS = true
		}
	}
}

// mapPath picks the token table for this session.
func (h *handler) mapPath() (string, error) {
	h.context()
	ws := h.ws
	if h.wsErr != nil {
		ws = config.Workspace{} // unreadable marker: no stable ID, use the global table
	}
	p, err := vault.MapPath(h.env.Paths, h.env.Global, ws, h.inWS && h.wsErr == nil)
	if errors.Is(err, vault.ErrClosed) {
		return "", errVaultClosed
	}
	return p, err
}

var errVaultClosed = vault.ErrClosed

// detectorConfig returns the detection settings for content at path (or the
// session's working directory when path is empty); ok is false when nothing
// should be masked.
func (h *handler) detectorConfig(path string) (detect.Config, bool) {
	h.context()
	if path != "" {
		if ws, ok, err := config.FindWorkspace(filepath.Dir(path)); ok && err == nil {
			return ws.DetectorConfig(), true
		}
	}
	if h.inWS && h.wsErr == nil {
		return h.ws.DetectorConfig(), true
	}
	if h.inWS {
		// Unreadable marker: mask everything with default categories.
		return detect.Config{Profile: detect.Strict, Allow: detect.DefaultAllow}, true
	}
	if !h.env.Global.MaskingOn() {
		return detect.Config{}, false
	}
	return detect.Config{Profile: detect.Basic, Allow: append(append([]string(nil), detect.DefaultAllow...), h.env.Global.Allow...)}, true
}

// detectorFor builds a detector that also matches every value already in the
// token table, read-only. It returns nil when nothing should be masked.
func (h *handler) detectorFor(path string) *detect.Detector {
	cfg, ok := h.detectorConfig(path)
	if !ok {
		return nil
	}
	if mp, err := h.mapPath(); err == nil {
		if m, err := tokenmap.Load(mp); err == nil {
			cfg = withTerms(cfg, m.KnownTerms())
		}
	}
	return detect.New(cfg)
}

func withTerms(c detect.Config, extra map[string][]string) detect.Config {
	if len(extra) == 0 {
		return c
	}
	terms := map[string][]string{}
	for k, v := range c.Terms {
		terms[k] = append(terms[k], v...)
	}
	for k, v := range extra {
		terms[k] = append(terms[k], v...)
	}
	c.Terms = terms
	return c
}

func (h *handler) allowHosts() []string {
	h.context()
	out := append([]string(nil), egress.DefaultAllowHosts...)
	out = append(out, h.env.Global.AllowHosts...)
	if h.inWS {
		out = append(out, h.ws.AllowHosts...)
	}
	return out
}

// report returns the session's preflight report, running the checks when the
// cache is missing, stale, or last time found a problem (so fixing it is
// noticed on the next prompt).
func (h *handler) report(maxAge time.Duration) preflight.Report {
	if r, ok := preflight.LoadSession(h.env.Paths, h.in.SessionID); ok && !r.Blocked() && h.env.Now().Sub(r.At) < maxAge && r.Cwd == h.in.Cwd {
		return r
	}
	r := h.env.Preflight(h.in.Cwd)
	r.ApplyAcks(h.env.Global.Acknowledged)
	if h.in.SessionID != "" {
		if err := preflight.SaveSession(h.env.Paths, h.in.SessionID, r); err != nil {
			logEvent(h.env, map[string]any{"event": "save-session", "error": err.Error()})
		}
	}
	return r
}

// --- SessionStart ------------------------------------------------------------

func (h *handler) sessionStart() error {
	h.context()
	preflight.PruneSessions(h.env.Paths, 7*24*time.Hour, h.env.Now())
	r := h.env.Preflight(h.in.Cwd)
	r.ApplyAcks(h.env.Global.Acknowledged)
	if h.in.SessionID != "" {
		_ = preflight.SaveSession(h.env.Paths, h.in.SessionID, r)
	}
	var ctx []string
	if h.inWS {
		ctx = append(ctx, workspaceBriefing)
	}
	if r.Blocked() {
		ctx = append(ctx, "ClaudeShield found a problem that blocks this session (see the message shown to the user). "+
			"Prompts and tool calls are refused until it is fixed. Tell the user to run `claudeshield check` in a terminal.")
	}
	out := map[string]any{"systemMessage": statusLine(r, h.inWS)}
	if len(ctx) > 0 {
		out["hookSpecificOutput"] = map[string]any{"hookEventName": "SessionStart", "additionalContext": strings.Join(ctx, "\n\n")}
	}
	logEvent(h.env, map[string]any{"event": "SessionStart", "session": h.in.SessionID, "workspace": h.inWS, "blocked": r.Blocked(), "warn": r.Count(preflight.Warn)})
	return writeJSON(h.out, out)
}

const workspaceBriefing = `This folder is a ClaudeShield sensitive workspace. Before you see any tool result, sensitive values in it (people's names, ID numbers, phone numbers, e-mail and street addresses, money amounts, bank accounts, company names, credentials, internal hosts, and terms the user listed) are replaced with placeholders such as ⟦EMAIL_003⟧ or ⟦AMOUNT_012⟧. The same value always gets the same placeholder.
Rules:
1. Treat each placeholder as an opaque value. When you edit or write files, or run local commands, copy placeholders exactly, brackets included; ClaudeShield puts the real value back on this machine.
2. Do not guess, reconstruct, or ask the user for the real values, and do not invent new placeholders.
3. Placeholders are never expanded in web requests, web searches or MCP tools, and commands that would send expanded values off the machine are refused.
4. To calculate with ⟦AMOUNT_n⟧ values, write and run a script that reads the files; it runs on the real numbers locally.
5. If a tool call is refused, read the reason, and tell the user what to do instead.`

func statusLine(r preflight.Report, inWS bool) string {
	mode := i18n.T("一般模式（只遮罩金鑰類）", "standard mode (credentials masked)")
	if inWS {
		mode = i18n.T("敏感資料夾模式（全面遮罩）", "sensitive workspace (full masking)")
	}
	b, w := r.Count(preflight.Block), r.Count(preflight.Warn)
	switch {
	case b > 0:
		lines := []string{i18n.Tf("ClaudeShield：%s · %d 個問題擋下了這個工作階段：", "ClaudeShield: %s · %d problem(s) block this session:", mode, b)}
		for _, f := range r.Problems() {
			if f.Severity == preflight.Block {
				lines = append(lines, "  ✗ "+f.Title)
			}
		}
		lines = append(lines, i18n.T("  在終端機執行 claudeshield check 看詳細說明與解法。", "  Run `claudeshield check` in a terminal for details and fixes."))
		return strings.Join(lines, "\n")
	case w > 0:
		return i18n.Tf("ClaudeShield：%s · %d 個警告（claudeshield check 可查看）", "ClaudeShield: %s · %d warning(s) (see `claudeshield check`)", mode, w)
	}
	return i18n.Tf("ClaudeShield：%s · 檢查全部通過", "ClaudeShield: %s · all checks passed", mode)
}

// --- UserPromptSubmit --------------------------------------------------------

func (h *handler) userPrompt() error {
	h.context()
	r := h.report(h.env.PreflightTTL)
	if r.Blocked() {
		logEvent(h.env, map[string]any{"event": "UserPromptSubmit", "session": h.in.SessionID, "decision": "block", "why": "preflight"})
		return h.blockPrompt(blockedReport(r))
	}
	if h.inWS && h.wsErr != nil {
		return h.blockPrompt(i18n.Tf("ClaudeShield：這個資料夾的 %s 格式有誤，為了安全先擋下。錯誤：%v",
			"ClaudeShield: this folder's %s cannot be parsed, so prompts are blocked to be safe. Error: %v", config.WorkspaceFile, h.wsErr))
	}
	if h.inWS && h.env.Getenv("CLAUDE_CODE_BRIDGE_SESSION_ID") != "" {
		return h.blockPrompt(i18n.T(
			"ClaudeShield：這個工作階段開著 Remote Control。連線期間對話會同步存一份在 Anthropic 的伺服器上，敏感資料夾不允許。請先在 Claude Code 裡關掉 Remote Control（/remote-control）再傳訊息。",
			"ClaudeShield: Remote Control is active. While connected, the transcript is also stored on Anthropic's servers, which a sensitive workspace does not allow. Turn Remote Control off (/remote-control) and send again."))
	}
	if h.inWS {
		if refs := h.atReferences(h.in.Prompt); len(refs) > 0 {
			return h.blockPrompt(i18n.Tf(
				"ClaudeShield：訊息裡用 @ 引用了檔案（%s）。用 @ 引用時，Claude Code 會把檔案原文直接放進訊息，不會經過遮罩。請改成用文字說「請讀 %s」，讓 Claude 用讀檔工具讀，內容就會先遮罩。",
				"ClaudeShield: the prompt references files with @ (%s). Claude Code inlines @-referenced files verbatim, bypassing masking. Ask in words instead (\"read %s\") so the file goes through the Read tool and gets masked.",
				strings.Join(refs, ", "), strings.TrimPrefix(refs[0], "@")))
		}
	}
	d := h.detectorFor("")
	if d == nil {
		return nil
	}
	if ms := d.Find(stripPasteMarkers(h.in.Prompt)); len(ms) > 0 {
		path, err := h.mapPath()
		var masked string
		if err == nil {
			cfg, _ := h.detectorConfig("")
			err = tokenmap.Update(path, func(m *tokenmap.Map) error {
				masked, _ = m.Mask(detect.New(withTerms(cfg, m.KnownTerms())), h.in.Prompt)
				return nil
			})
		}
		kinds := kindSummary(ms)
		logEvent(h.env, map[string]any{"event": "UserPromptSubmit", "session": h.in.SessionID, "decision": "block", "why": "sensitive-prompt", "kinds": kinds})
		msg := i18n.Tf("ClaudeShield 擋下了這則訊息（沒有送出）：裡面有 %d 個機密（%s）。",
			"ClaudeShield blocked this prompt (nothing was sent): it contains %d sensitive value(s) (%s).", len(ms), kindList(kinds))
		if err == nil {
			msg += "\n\n" + i18n.T("可以改送下面這段，機密已換成代號；Claude 寫檔或在本機執行指令時，會自動換回真實內容：",
				"You can send this instead. Sensitive values are replaced with placeholders, which are swapped back to the real values when Claude writes files or runs local commands:") +
				"\n\n" + masked
		} else if errors.Is(err, errVaultClosed) {
			msg += "\n\n" + i18n.T("加密保險箱沒有打開，無法產生代號版本。請先執行 claudeshield vault open。", "The vault is closed, so no masked version could be made. Run `claudeshield vault open` first.")
		}
		return h.blockPrompt(msg)
	}
	return nil
}

func (h *handler) blockPrompt(reason string) error {
	return writeJSON(h.out, map[string]any{
		"decision": "block",
		"reason":   reason,
		"hookSpecificOutput": map[string]any{
			"hookEventName":          "UserPromptSubmit",
			"suppressOriginalPrompt": true,
		},
	})
}

func blockedReport(r preflight.Report) string {
	var b strings.Builder
	b.WriteString(i18n.T("ClaudeShield 擋下了這則訊息（沒有送出），因為安全檢查沒有通過：\n", "ClaudeShield blocked this prompt (nothing was sent) because a safety check failed:\n"))
	for _, f := range r.Problems() {
		if f.Severity != preflight.Block {
			continue
		}
		b.WriteString("\n✗ " + f.Title + "\n")
		if f.Detail != "" {
			b.WriteString("  " + strings.ReplaceAll(f.Detail, "\n", "\n  ") + "\n")
		}
		if f.Fix != "" {
			b.WriteString("  " + i18n.T("解法：", "Fix: ") + strings.ReplaceAll(f.Fix, "\n", "\n  ") + "\n")
		}
	}
	b.WriteString("\n" + i18n.T("修好之後再傳一次訊息就會重新檢查。", "Fix it and send the prompt again; the checks re-run automatically."))
	return b.String()
}

// atReferences finds @path references in a prompt that point at real files.
func (h *handler) atReferences(prompt string) []string {
	var refs []string
	for _, f := range strings.Fields(stripPasteMarkers(prompt)) {
		if !strings.HasPrefix(f, "@") || len(f) < 2 || strings.HasPrefix(f, "@agent-") {
			continue
		}
		p := strings.TrimRight(f[1:], ".,;:!?)」』，。")
		if i := strings.IndexByte(p, '#'); i > 0 { // @file.go#L10-20
			p = p[:i]
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(h.in.Cwd, p)
		}
		if _, err := os.Stat(p); err == nil {
			refs = append(refs, f)
		}
	}
	return refs
}

func stripPasteMarkers(s string) string {
	if !strings.Contains(s, "pasted_content") {
		return s
	}
	var keep []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "<pasted_content") || strings.HasPrefix(t, "</pasted_content") {
			continue
		}
		keep = append(keep, line)
	}
	return strings.Join(keep, "\n")
}

// --- PreToolUse --------------------------------------------------------------

var localTools = map[string]bool{"Read": true, "Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "Glob": true, "Grep": true, "LS": true}
var shellTools = map[string]bool{"Bash": true, "PowerShell": true, "Monitor": true}
var writeTools = map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true}

// ownFile reports whether abs is inside claudeshield's state directory or the
// vault's claudeshield folder. The token tables there hold the real values,
// and the config decides what is protected, so Claude never touches either.
func (h *handler) ownFile(abs string) bool {
	abs = config.Canonical(abs)
	for _, dir := range h.ownDirs() {
		if abs == dir || strings.HasPrefix(abs, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (h *handler) ownDirs() []string {
	dirs := []string{config.Canonical(h.env.Paths.State)}
	if vault.Configured(h.env.Global) {
		dirs = append(dirs, config.Canonical(vault.DataDir(h.env.Paths, h.env.Global)))
	}
	return dirs
}

func (h *handler) shellTouchesOwnFiles(cmd string) bool {
	if strings.Contains(cmd, ".claudeshield") {
		return true
	}
	dirs := h.ownDirs()
	dirs = append(dirs, filepath.Clean(h.env.Paths.State)) // as spelled, too
	for _, d := range dirs {
		if d != "" && d != "." && strings.Contains(cmd, d) {
			return true
		}
	}
	return false
}

func selfProtectReason() string {
	return i18n.T("ClaudeShield：這是 ClaudeShield 自己的設定或代號對照表（裡面有真實資料），Claude 不能讀取或修改。要改設定請使用者自己在終端機操作。",
		"ClaudeShield: this is ClaudeShield's own configuration or placeholder table (it holds the real values), which Claude may not read or change. The user can change settings in a terminal.")
}

var binaryExt = map[string]bool{
	".pdf": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".heic": true, ".tiff": true, ".bmp": true,
	".docx": true, ".doc": true, ".xlsx": true, ".xls": true, ".pptx": true, ".ppt": true, ".key": true, ".numbers": true, ".pages": true,
	".zip": true, ".gz": true, ".tgz": true, ".7z": true, ".rar": true, ".sqlite": true, ".db": true, ".ipynb": false,
}

type decision struct {
	verdict string // "", "allow", "deny", "ask"
	reason  string
	input   map[string]any
	context string
}

func (h *handler) preTool() error {
	h.context()
	d := h.decidePreTool()
	logEvent(h.env, map[string]any{"event": "PreToolUse", "session": h.in.SessionID, "tool": h.in.ToolName, "decision": d.verdict, "rewrote": d.input != nil, "workspace": h.inWS})
	if d.verdict == "" && d.input == nil && d.context == "" {
		return nil
	}
	hso := map[string]any{"hookEventName": "PreToolUse"}
	if d.verdict != "" {
		hso["permissionDecision"] = d.verdict
	}
	if d.reason != "" {
		hso["permissionDecisionReason"] = d.reason
	}
	if d.input != nil {
		hso["updatedInput"] = d.input
	}
	if d.context != "" {
		hso["additionalContext"] = d.context
	}
	return writeJSON(h.out, map[string]any{"hookSpecificOutput": hso})
}

func deny(reason string) decision { return decision{verdict: "deny", reason: reason} }
func ask(reason string) decision  { return decision{verdict: "ask", reason: reason} }

func (h *handler) decidePreTool() decision {
	tool := h.in.ToolName
	if r, ok := preflight.LoadSession(h.env.Paths, h.in.SessionID); ok && r.Blocked() {
		return deny(i18n.T("ClaudeShield：這個工作階段的安全檢查沒有通過，所有工具都先停用。請使用者在終端機執行 claudeshield check。",
			"ClaudeShield: this session failed its safety checks, so all tools are disabled. Ask the user to run `claudeshield check` in a terminal."))
	}
	if h.inWS && h.wsErr != nil {
		return deny(i18n.Tf("ClaudeShield：%s 格式有誤（%v），為了安全先停用工具。", "ClaudeShield: %s cannot be parsed (%v); tools are disabled to be safe.", config.WorkspaceFile, h.wsErr))
	}

	// Paths this call touches, for protection and binary checks.
	if localTools[tool] {
		for _, p := range toolPaths(h.in.ToolInput) {
			abs := p
			if !filepath.IsAbs(abs) {
				abs = filepath.Join(h.in.Cwd, abs)
			}
			if h.ownFile(abs) || (writeTools[tool] && filepath.Base(abs) == config.WorkspaceFile) {
				return deny(selfProtectReason())
			}
			if ws, ok, _ := config.FindWorkspace(filepath.Dir(abs)); ok {
				if ws.Protected(abs) {
					return deny(i18n.Tf("ClaudeShield：%s 在受保護的範圍（%s），Claude 不能讀取或修改。需要用到的話，請使用者用 claudeshield mask 產生遮罩版放到別的資料夾。",
						"ClaudeShield: %s is protected (%s); Claude may not read or change it. If it is needed, the user can create a masked copy elsewhere with `claudeshield mask`.",
						abs, strings.Join(ws.Protect, ", ")))
				}
				if tool == "Read" && binaryExt[strings.ToLower(filepath.Ext(abs))] && !ws.BinaryReads {
					return deny(i18n.Tf("ClaudeShield：%s 是二進位檔（PDF、圖片或 Office 檔），內容沒辦法遮罩，所以不能讀。請使用者先轉成文字檔，例如 Word 檔用 `textutil -convert txt 檔名.docx`，PDF 用 `pdftotext 檔名.pdf`，再讀轉出來的 .txt。",
						"ClaudeShield: %s is a binary file (PDF, image or Office document) whose content cannot be masked. Convert it to text first, e.g. `textutil -convert txt file.docx` or `pdftotext file.pdf`, and read the .txt instead.", abs))
				}
			}
		}
	}

	if shellTools[tool] {
		if cmd, _ := h.in.ToolInput["command"].(string); h.shellTouchesOwnFiles(cmd) {
			return deny(selfProtectReason())
		}
	}

	switch {
	case localTools[tool]:
		return h.unmaskLocal()
	case shellTools[tool]:
		return h.shell()
	case tool == "WebFetch":
		return h.webFetch()
	case tool == "WebSearch":
		q, _ := h.in.ToolInput["query"].(string)
		if tokenmap.HasTokens(q) {
			return deny(i18n.T("ClaudeShield：搜尋字串裡有代號（⟦…⟧），代號只代表本機資料，不能拿去網路搜尋。", "ClaudeShield: the search query contains placeholders (⟦…⟧); they stand for local data and must not be searched for on the web."))
		}
		if d := h.detectorFor(""); d != nil {
			if ms := d.Find(q); len(ms) > 0 {
				return deny(i18n.Tf("ClaudeShield：搜尋字串裡有機密（%s），不能送到網路搜尋。", "ClaudeShield: the search query contains sensitive values (%s) and cannot be sent to a web search.", kindList(kindSummary(ms))))
			}
		}
	case strings.HasPrefix(tool, "mcp__"):
		if h.inWS {
			if d := h.detectorFor(""); d != nil {
				b, _ := json.Marshal(h.in.ToolInput)
				if ms := d.Find(string(b)); len(ms) > 0 {
					return deny(i18n.Tf("ClaudeShield：要傳給 MCP 工具 %s 的內容裡有機密（%s）。MCP 伺服器在 ClaudeShield 的保護範圍外，敏感資料夾不允許。",
						"ClaudeShield: the input for MCP tool %s contains sensitive values (%s). MCP servers are outside ClaudeShield's protection, so this is not allowed in a sensitive workspace.", tool, kindList(kindSummary(ms))))
				}
			}
		}
	}
	return decision{}
}

func toolPaths(in map[string]any) []string {
	var out []string
	for _, k := range []string{"file_path", "notebook_path", "path"} {
		if s, ok := in[k].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// unmaskLocal puts real values back into a local file tool's input.
func (h *handler) unmaskLocal() decision {
	if !tokenmap.JSONHasTokens(h.in.ToolInput) {
		return decision{}
	}
	path, err := h.mapPath()
	if err != nil {
		return deny(vaultClosedReason())
	}
	m, err := tokenmap.Load(path)
	if err != nil {
		return deny(i18n.Tf("ClaudeShield：讀不到代號對照表：%v", "ClaudeShield: cannot read the placeholder table: %v", err))
	}
	out, _, unknown := m.UnmaskJSON(h.in.ToolInput)
	if len(unknown) > 0 && (h.in.ToolName == "Write" || h.in.ToolName == "Edit" || h.in.ToolName == "MultiEdit" || h.in.ToolName == "NotebookEdit") {
		return deny(i18n.Tf("ClaudeShield：%s 不是已知的代號。請照抄工具結果裡出現過的代號，不要自己編新的。", "ClaudeShield: %s is not a known placeholder. Copy placeholders exactly as they appeared in tool results; do not make new ones.", strings.Join(dedupe(unknown), ", ")))
	}
	return decision{verdict: h.rewriteVerdict(), input: out.(map[string]any)}
}

// rewriteVerdict is the permission decision sent with updatedInput. It is
// empty: Claude Code (verified on v2.1.287) applies updatedInput without a
// decision and then runs its normal permission flow against the rewritten
// input, so rewriting never adds or removes a prompt by itself.
func (h *handler) rewriteVerdict() string { return "" }

func (h *handler) shell() decision {
	cmd, _ := h.in.ToolInput["command"].(string)
	if cmd == "" {
		return decision{}
	}
	allow := h.allowHosts()
	hasTokens := tokenmap.HasTokens(cmd)
	real := cmd
	if hasTokens {
		path, err := h.mapPath()
		if err != nil {
			return deny(vaultClosedReason())
		}
		m, err := tokenmap.Load(path)
		if err != nil {
			return deny(i18n.Tf("ClaudeShield：讀不到代號對照表：%v", "ClaudeShield: cannot read the placeholder table: %v", err))
		}
		var unknown []string
		real, _, unknown = m.Unmask(cmd)
		if len(unknown) > 0 {
			return deny(i18n.Tf("ClaudeShield：%s 不是已知的代號。請照抄工具結果裡出現過的代號。", "ClaudeShield: %s is not a known placeholder. Copy placeholders exactly as they appeared in tool results.", strings.Join(dedupe(unknown), ", ")))
		}
	}
	r := egress.AnalyzeShell(real, egress.Options{Dir: h.in.Cwd, GitRemoteURL: h.env.GitRemoteURL})
	where := hostList(r)

	if h.inWS {
		for _, g := range h.ws.Protect {
			lit := globLiteral(g)
			if lit != "" && strings.Contains(real, lit) {
				return deny(i18n.Tf("ClaudeShield：指令碰到受保護的路徑（%s），不允許。", "ClaudeShield: the command touches a protected path (%s), which is not allowed.", g))
			}
		}
	}
	if hasTokens && r.Network && !r.AllHostsAllowed(allow) {
		return deny(i18n.Tf("ClaudeShield：這個指令裡有代號，而且會連到 %s。執行時代號會換回真實資料，等於把機密送出這台電腦，所以不允許。",
			"ClaudeShield: this command contains placeholders and connects to %s. Running it would expand them into real values and send those off this machine, so it is refused.", where))
	}
	if r.Obfuscated {
		msg := i18n.Tf("ClaudeShield：這個指令用了混淆手法（%s），看不出實際會做什麼。", "ClaudeShield: this command is obfuscated (%s), so what it really does cannot be checked.", strings.Join(r.Reasons, ", "))
		if h.inWS {
			return deny(msg)
		}
		return ask(msg)
	}
	if r.DataOut && !r.AllHostsAllowed(allow) {
		msg := i18n.Tf("ClaudeShield：這個指令會把資料送到不在白名單的地方：%s（%s）。確定要送嗎？", "ClaudeShield: this command sends data to a destination not on the allowlist: %s (%s). Allow it?", where, strings.Join(r.Reasons, ", "))
		if h.inWS {
			return deny(i18n.Tf("ClaudeShield：敏感資料夾不允許把資料送到白名單以外的地方：%s。如果這是可信任的目的地，請使用者把它加進 %s 的 allow_hosts。",
				"ClaudeShield: a sensitive workspace may not send data to destinations off the allowlist: %s. If it is trusted, the user can add it to allow_hosts in %s.", where, config.WorkspaceFile))
		}
		return ask(msg)
	}
	if h.inWS && r.Publish {
		return ask(i18n.Tf("ClaudeShield：這個指令會把東西公開或上傳（%s → %s）。敏感資料夾裡每次都要你確認。", "ClaudeShield: this command publishes or uploads (%s → %s). In a sensitive workspace you confirm each time.", strings.Join(r.Reasons, ", "), where))
	}
	if h.inWS && r.Network && !r.AllHostsAllowed(allow) {
		return ask(i18n.Tf("ClaudeShield：這個指令會連到白名單以外的地方：%s。", "ClaudeShield: this command connects to a destination not on the allowlist: %s.", where))
	}
	wrap := h.inWS && h.in.ToolName == "Bash" && h.ws.SandboxStrict()
	if !hasTokens && !wrap {
		return decision{}
	}
	in := cloneMap(h.in.ToolInput)
	in["command"] = real
	v := h.rewriteVerdict()
	if wrap {
		in["command"] = wrapShell(real)
		// The wrapped command uses $? and a { } group, which Claude Code's
		// permission parser cannot trace, so without a decision it would ask
		// every time. Inside a workspace whose sandbox is strict, sandboxed
		// commands are auto-allowed anyway (autoAllowBashIfSandboxed), so
		// "allow" grants nothing new: deny and ask rules still apply and the
		// OS sandbox still confines the command.
		v = "allow"
	}
	if hasTokens && h.inWS && r.Network {
		v = "ask" // real values about to reach an allowlisted host: show the user
	}
	return decision{verdict: v, input: in, reason: i18n.T("ClaudeShield：已把代號換回真實內容（只在本機執行）。", "ClaudeShield: placeholders were replaced with real values for local execution.")}
}

func (h *handler) webFetch() decision {
	u, _ := h.in.ToolInput["url"].(string)
	if tokenmap.HasTokens(u) {
		return deny(i18n.T("ClaudeShield：網址裡有代號（⟦…⟧），不能送出。", "ClaudeShield: the URL contains placeholders (⟦…⟧) and cannot be fetched."))
	}
	if d := h.detectorFor(""); d != nil {
		if ms := d.Find(u); len(ms) > 0 {
			return deny(i18n.Tf("ClaudeShield：網址裡有機密（%s），不能送出。", "ClaudeShield: the URL contains sensitive values (%s) and cannot be fetched.", kindList(kindSummary(ms))))
		}
	}
	r := egress.AnalyzeShell("curl "+shellQuote(u), egress.Options{})
	if r.DataOut {
		msg := i18n.Tf("ClaudeShield：這個網址的路徑或參數看起來夾帶了資料（%s）。", "ClaudeShield: this URL's path or query looks like it carries data (%s).", u)
		if h.inWS {
			return deny(msg)
		}
		return ask(msg)
	}
	if h.inWS && !r.AllHostsAllowed(h.allowHosts()) {
		return ask(i18n.Tf("ClaudeShield：要讀取白名單以外的網站：%s。", "ClaudeShield: fetching a site not on the allowlist: %s.", hostList(r)))
	}
	return decision{}
}

// --- PostToolUse -------------------------------------------------------------

func (h *handler) postTool() error {
	h.context()
	var path string
	if localTools[h.in.ToolName] {
		if ps := toolPaths(h.in.ToolInput); len(ps) > 0 {
			path = ps[0]
			if !filepath.IsAbs(path) {
				path = filepath.Join(h.in.Cwd, path)
			}
		}
	}
	cfg, ok := h.detectorConfig(path)
	if !ok || h.in.ToolResponse == nil {
		return nil
	}
	skip := map[string]bool{"base64": true}
	if m, ok := h.in.ToolResponse.(map[string]any); ok {
		if b, _ := m["isImage"].(bool); b {
			return nil
		}
		if t, _ := m["type"].(string); t == "image" {
			return nil
		}
	}
	var masked any
	var n int
	var kinds map[string]int
	mp, err := h.mapPath()
	if err == nil {
		err = tokenmap.Update(mp, func(m *tokenmap.Map) error {
			masked, n, kinds = m.MaskJSON(detect.New(withTerms(cfg, m.KnownTerms())), h.in.ToolResponse, skip)
			return nil
		})
	}
	note := ""
	if err != nil {
		// Without the table, mask with throwaway placeholders that can never
		// be expanded. Claude still never sees the values.
		masked, n, kinds = tokenmap.New().MaskJSON(detect.New(cfg), h.in.ToolResponse, skip)
		masked = redactAll(masked)
		note = i18n.T(" 保險箱沒有打開，這些值換成了無法還原的 ⟦REDACTED⟧。", " The vault is closed, so they were replaced with unrecoverable ⟦REDACTED⟧ markers.")
	}
	if n == 0 {
		return nil
	}
	logEvent(h.env, map[string]any{"event": "PostToolUse", "session": h.in.SessionID, "tool": h.in.ToolName, "masked": n, "kinds": kinds})
	return writeJSON(h.out, map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName":     "PostToolUse",
		"updatedToolOutput": masked,
		"additionalContext": fmt.Sprintf("ClaudeShield masked %d sensitive value(s) in this result (%s). Placeholders like ⟦KIND_001⟧ stand for real values; copy them exactly.%s", n, kindList(kinds), note),
	}})
}

func redactAll(v any) any {
	switch x := v.(type) {
	case string:
		return detect.TokenRE.ReplaceAllString(x, "⟦REDACTED⟧")
	case map[string]any:
		cp := make(map[string]any, len(x))
		for k, e := range x {
			cp[k] = redactAll(e)
		}
		return cp
	case []any:
		cp := make([]any, len(x))
		for i, e := range x {
			cp[i] = redactAll(e)
		}
		return cp
	}
	return v
}

// --- helpers -----------------------------------------------------------------

func vaultClosedReason() string {
	return i18n.T("ClaudeShield：加密保險箱沒有打開，代號沒辦法換回真實內容。請使用者在終端機執行 claudeshield vault open。",
		"ClaudeShield: the encrypted vault is closed, so placeholders cannot be expanded. Ask the user to run `claudeshield vault open` in a terminal.")
}

func hostList(r egress.Result) string {
	hs := append([]string(nil), r.Hosts...)
	if r.UnknownHost {
		hs = append(hs, i18n.T("無法判斷的目的地", "an undetermined destination"))
	}
	if len(hs) == 0 {
		return i18n.T("無法判斷的目的地", "an undetermined destination")
	}
	return strings.Join(hs, ", ")
}

func globLiteral(g string) string {
	g = strings.TrimPrefix(g, "./")
	if i := strings.IndexAny(g, "*?["); i >= 0 {
		g = g[:i]
	}
	if len(g) < 2 {
		return ""
	}
	return g
}

func kindSummary(ms []detect.Match) map[string]int {
	k := map[string]int{}
	for _, m := range ms {
		k[m.Kind]++
	}
	return k
}

var kindNamesZH = map[string]string{
	"TWID": "身分證字號", "EMAIL": "Email", "PHONE": "電話", "CARD": "信用卡號", "ADDRESS": "地址", "NAME": "姓名",
	"COMPANY": "公司名", "UBN": "統一編號", "AMOUNT": "金額", "BANKACCT": "銀行帳號", "APIKEY": "API 金鑰",
	"PRIVKEY": "私鑰", "JWT": "登入權杖", "SECRET": "密鑰", "PASSWORD": "密碼", "IP": "內部 IP", "HOST": "內部主機名",
}

func kindList(k map[string]int) string {
	names := make([]string, 0, len(k))
	for kind := range k {
		names = append(names, kind)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, kind := range names {
		label := kind
		if i18n.Lang() == "zh" {
			if z, ok := kindNamesZH[kind]; ok {
				label = z
			}
		}
		parts = append(parts, fmt.Sprintf("%s×%d", label, k[kind]))
	}
	return strings.Join(parts, ", ")
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	cp := make(map[string]any, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// logEvent appends one line to the decision log. It never records values,
// only what kind of thing happened.
func logEvent(env Env, fields map[string]any) {
	if env.Paths.State == "" {
		return
	}
	now := time.Now
	if env.Now != nil {
		now = env.Now
	}
	fields["at"] = now().UTC().Format(time.RFC3339)
	b, err := json.Marshal(fields)
	if err != nil {
		return
	}
	path := env.Paths.EventLog()
	if st, err := os.Stat(path); err == nil && st.Size() > 5<<20 {
		os.Rename(path, path+".1")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}
