// Command claudeshield keeps sensitive data from leaving your machine when
// you work with Claude Code: it checks the connection to Anthropic before a
// session starts, masks sensitive values in everything Claude reads, puts
// them back only for local actions, watches where shell commands send data,
// keeps transcripts in an encrypted vault, and blocks unapproved extensions.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/useless-husband/claudeshield/internal/app"
	"github.com/useless-husband/claudeshield/internal/audit"
	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/hook"
	"github.com/useless-husband/claudeshield/internal/i18n"
	"github.com/useless-husband/claudeshield/internal/preflight"
	"github.com/useless-husband/claudeshield/internal/settings"
	"github.com/useless-husband/claudeshield/internal/vault"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

type cli struct {
	p      config.Paths
	g      config.Global
	cfgErr error
	stdin  io.Reader
	out    io.Writer
	errw   io.Writer
	color  bool
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cli{p: config.Default(), stdin: stdin, out: stdout, errw: stderr}
	c.g, c.cfgErr = config.LoadGlobal(c.p)
	i18n.Set(c.g.Lang)
	if f, ok := stdout.(*os.File); ok && os.Getenv("NO_COLOR") == "" {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			c.color = true
		}
	}
	if len(args) == 0 {
		c.usage()
		return 2
	}
	if args[0] == "hook" {
		if len(args) < 2 {
			return 2
		}
		return hook.Run(args[1], stdin, stdout, app.HookEnv(c.p, c.g, c.cfgErr))
	}
	if c.cfgErr != nil {
		fmt.Fprintln(stderr, i18n.Tf("讀不到 %s：%v", "cannot read %s: %v", c.p.GlobalFile(), c.cfgErr))
		return 1
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := 0
	switch cmd {
	case "check":
		code, err = c.check(rest)
	case "run":
		code, err = c.runClaude(rest)
	case "shell-init":
		fmt.Fprint(c.out, shellInit)
	case "install":
		err = c.install(rest)
	case "uninstall":
		err = c.uninstall()
	case "init":
		err = c.initWorkspace(rest)
	case "scan":
		code, err = c.scan(rest)
	case "mask":
		err = c.mask(rest)
	case "unmask":
		err = c.unmask(rest)
	case "map":
		err = c.showMap(rest)
	case "audit":
		code, err = c.audit(rest)
	case "ack":
		err = c.ack(rest)
	case "account":
		err = c.account(rest)
	case "vault":
		err = c.vault(rest)
	case "tls":
		err = c.tls(rest)
	case "log":
		err = c.log(rest)
	case "lang":
		err = c.setLang(rest)
	case "version", "--version", "-v":
		fmt.Fprintln(c.out, "claudeshield", version)
	case "help", "--help", "-h":
		c.usage()
	default:
		fmt.Fprintln(stderr, i18n.Tf("不認得的指令：%s", "unknown command: %s", cmd))
		c.usage()
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, c.paint("31", i18n.T("錯誤：", "error: "))+err.Error())
		if code == 0 {
			code = 1
		}
	}
	return code
}

const shellInit = `# ClaudeShield: run the safety checks before every Claude Code launch.
claude() { command claudeshield run -- "$@"; }
`

func (c *cli) usage() {
	fmt.Fprint(c.out, i18n.T(`claudeshield — 讓機密可以放心交給 Claude Code 處理

開始使用
  claudeshield install            把 ClaudeShield 裝進 Claude Code（hooks）
  claudeshield init [資料夾]       把資料夾標記成「敏感資料夾」（全面遮罩）
  claudeshield check              執行安全檢查並說明每一項
  claudeshield run -- [參數]       檢查通過才啟動 claude（可搭配 shell-init）

遮罩
  claudeshield scan <檔案|->       列出會被遮罩的內容
  claudeshield mask <來源> -o <目的地>   產生遮罩版本
  claudeshield unmask <檔案> [-o 輸出]   把代號換回真實內容
  claudeshield map [--reveal]     看代號對照表

保險箱（加密對話紀錄）
  claudeshield vault create | open | close | status | migrate | restore

其他
  claudeshield audit [approve]    檢查／核可外掛、MCP、hooks
  claudeshield ack <檢查項目ID>     接受一個你確認沒問題的警示
  claudeshield account confirm    確認「幫助改善 Claude」已關閉
  claudeshield tls trust <主機>    Anthropic 換憑證商後重新記住
  claudeshield log [-n 數量]       看最近的攔截紀錄（不含機密內容）
  claudeshield lang zh|en         切換語言
  claudeshield uninstall          移除 hooks
`, `claudeshield — hand sensitive data to Claude Code without it leaving your machine

Getting started
  claudeshield install            wire ClaudeShield into Claude Code (hooks)
  claudeshield init [dir]         mark a folder as a sensitive workspace (full masking)
  claudeshield check              run the safety checks and explain each one
  claudeshield run -- [args]      start claude only if the checks pass (see shell-init)

Masking
  claudeshield scan <file|->      list what would be masked
  claudeshield mask <src> -o <dst>   write a masked copy
  claudeshield unmask <file> [-o out]   put real values back
  claudeshield map [--reveal]     show the placeholder table

Vault (encrypted transcripts)
  claudeshield vault create | open | close | status | migrate | restore

Other
  claudeshield audit [approve]    review/approve plugins, MCP servers and hooks
  claudeshield ack <finding-id>   accept a finding you have verified
  claudeshield account confirm    confirm "Help improve Claude" is off
  claudeshield tls trust <host>   re-pin after Anthropic changes certificate providers
  claudeshield log [-n N]         recent decisions (never contains sensitive values)
  claudeshield lang zh|en         switch language
  claudeshield uninstall          remove the hooks
`))
}

func (c *cli) paint(code, s string) string {
	if !c.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func cwd() string {
	d, _ := os.Getwd()
	return d
}

func (c *cli) tilde(path string) string {
	if c.p.Home != "" && strings.HasPrefix(path, c.p.Home) {
		return "~" + path[len(c.p.Home):]
	}
	return path
}

// --- check / run -------------------------------------------------------------

func (c *cli) check(args []string) (int, error) {
	jsonOut, network, all := false, true, false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "--offline":
			network = false
		case "--all":
			all = true
		}
	}
	r := app.Preflight(c.p, c.g, cwd(), network)
	if jsonOut {
		enc := json.NewEncoder(c.out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		enc.Encode(r)
	} else {
		c.printReport(r, all)
	}
	if r.Blocked() {
		return 1, nil
	}
	return 0, nil
}

func (c *cli) printReport(r preflight.Report, all bool) {
	fmt.Fprintln(c.out, c.paint("1", i18n.T("ClaudeShield 安全檢查", "ClaudeShield safety check"))+"  "+r.At.Format("2006-01-02 15:04"))
	where := c.tilde(r.Cwd)
	if r.Workspace != "" {
		where += i18n.Tf("（敏感資料夾：%s）", " (sensitive workspace: %s)", c.tilde(r.Workspace))
	}
	fmt.Fprintln(c.out, i18n.T("資料夾：", "Folder: ")+where)
	fmt.Fprintln(c.out)
	findings := append([]preflight.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Severity > findings[j].Severity })
	for _, f := range findings {
		if f.Severity == preflight.Info && !all {
			continue
		}
		var tag string
		switch f.Severity {
		case preflight.Block:
			tag = c.paint("31", i18n.T("✗ 擋下", "✗ BLOCK"))
		case preflight.Warn:
			tag = c.paint("33", i18n.T("! 警告", "! WARN "))
			if f.Acked {
				tag = c.paint("33", i18n.T("! 已接受", "! ACKED"))
			}
		default:
			tag = c.paint("32", i18n.T("✓ 通過", "✓ OK   "))
		}
		fmt.Fprintf(c.out, "%s  %s\n", tag, f.Title)
		if f.Severity > preflight.Info {
			for _, line := range strings.Split(f.Detail, "\n") {
				if line != "" {
					fmt.Fprintln(c.out, "        "+line)
				}
			}
			if f.Fix != "" {
				for i, line := range strings.Split(f.Fix, "\n") {
					prefix := "        " + i18n.T("解法：", "Fix: ")
					if i > 0 {
						prefix = "        " + strings.Repeat(" ", len([]rune(i18n.T("解法：", "Fix: ")))*2-2)
					}
					fmt.Fprintln(c.out, prefix+line)
				}
			}
			if f.Severity == preflight.Block && !f.NoAck && f.Fingerprint != "" {
				fmt.Fprintln(c.out, "        ID: "+f.ID)
			}
		}
	}
	b, w, ok := r.Count(preflight.Block), r.Count(preflight.Warn), r.Count(preflight.Info)
	fmt.Fprintln(c.out)
	switch {
	case b > 0:
		fmt.Fprintln(c.out, c.paint("31", i18n.Tf("結果：%d 個問題會擋下 Claude Code，%d 個警告，%d 項通過。", "Result: %d problem(s) block Claude Code, %d warning(s), %d passed.", b, w, ok)))
	case w > 0:
		fmt.Fprintln(c.out, c.paint("33", i18n.Tf("結果：可以使用，但有 %d 個警告；%d 項通過。", "Result: OK to use, with %d warning(s); %d passed.", w, ok)))
	default:
		fmt.Fprintln(c.out, c.paint("32", i18n.Tf("結果：%d 項全部通過。", "Result: all %d checks passed.", ok)))
	}
	if !all {
		fmt.Fprintln(c.out, i18n.T("（加 --all 可以看到每一項通過的檢查）", "(add --all to list every passed check)"))
	}
}

func (c *cli) runClaude(args []string) (int, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	r := app.Preflight(c.p, c.g, cwd(), true)
	if r.Blocked() {
		c.printReport(r, false)
		fmt.Fprintln(c.out, i18n.T("Claude Code 沒有啟動。修好上面的問題再試一次。", "Claude Code was not started. Fix the problems above and try again."))
		return 1, nil
	}
	bin, err := findClaude()
	if err != nil {
		return 1, err
	}
	return 1, syscall.Exec(bin, append([]string{"claude"}, args...), os.Environ())
}

func findClaude() (string, error) {
	if v := os.Getenv("CLAUDESHIELD_CLAUDE_BIN"); v != "" {
		return v, nil
	}
	return exec.LookPath("claude")
}

// --- install -------------------------------------------------------------------

func (c *cli) install(args []string) error {
	dry := len(args) > 0 && args[0] == "--dry-run"
	binDir := filepath.Join(c.p.State, "bin")
	target := filepath.Join(binDir, "claudeshield")
	if dry {
		fmt.Fprintln(c.out, i18n.Tf("會把執行檔複製到 %s，並在 %s 加入：", "Would copy the binary to %s and add to %s:", c.tilde(target), c.tilde(app.UserSettings(c.p))))
		b, _ := json.MarshalIndent(map[string]any{"hooks": settings.HookConfig(target), "env": settings.PrivacyEnv}, "", "  ")
		fmt.Fprintln(c.out, string(b))
		return nil
	}
	if c.p.Executable != target {
		if err := copyExecutable(c.p.Executable, target); err != nil {
			return err
		}
	}
	linked := ""
	localBin := filepath.Join(c.p.Home, ".local", "bin")
	if st, err := os.Stat(localBin); err == nil && st.IsDir() {
		l := filepath.Join(localBin, "claudeshield")
		if cur, err := os.Readlink(l); err == nil && cur != target {
			os.Remove(l)
		}
		if _, err := os.Lstat(l); err != nil {
			if os.Symlink(target, l) == nil {
				linked = l
			}
		}
	}
	now := time.Now()
	backup, added, err := settings.Install(app.UserSettings(c.p), target, filepath.Join(c.p.State, "backups"), now)
	if err != nil {
		return err
	}
	prevAdded := []string{}
	if c.g.Installed != nil {
		prevAdded = c.g.Installed.AddedEnv
	}
	c.g.Installed = &config.InstallRecord{At: now, Executable: target, Settings: app.UserSettings(c.p), Backup: backup, AddedEnv: append(prevAdded, added...)}
	if err := config.SaveGlobal(c.p, c.g); err != nil {
		return err
	}
	fmt.Fprintln(c.out, c.paint("32", i18n.T("已安裝。", "Installed.")))
	fmt.Fprintln(c.out, i18n.Tf("  執行檔：%s", "  binary:   %s", c.tilde(target)))
	if linked != "" {
		fmt.Fprintln(c.out, i18n.Tf("  指令：%s（在任何終端機都能打 claudeshield）", "  command:  %s", c.tilde(linked)))
	}
	fmt.Fprintln(c.out, i18n.Tf("  設定：%s（原檔備份在 %s）", "  settings: %s (backup: %s)", c.tilde(app.UserSettings(c.p)), c.tilde(backup)))
	if len(added) > 0 {
		fmt.Fprintln(c.out, i18n.Tf("  已關閉：%s", "  disabled: %s", strings.Join(added, ", ")))
	}
	fmt.Fprintln(c.out, i18n.T("  已經開著的 Claude Code 視窗會自動套用（Claude Code 會偵測設定檔變更）。", "  Running Claude Code sessions pick this up automatically (settings are watched)."))
	if _, ok, _ := audit.LoadBaseline(c.p); !ok {
		items, err := audit.Collect(audit.Options{Paths: c.p, Cwd: cwd(), Self: target})
		if err == nil {
			bl, _, _ := audit.LoadBaseline(c.p)
			if err := audit.SaveBaseline(c.p, audit.Approve(bl, items, audit.ProjectRoot(c.p, cwd()), now)); err == nil {
				fmt.Fprintln(c.out, i18n.Tf("\n記下了目前裝的 %d 個擴充功能當作核可清單，請看一下有沒有不認得的：", "\nRecorded the %d extensions installed now as the approved baseline. Check you recognise each:", len(items)))
				for _, it := range items {
					fmt.Fprintf(c.out, "  %-10s %-28s %s\n", it.Kind, it.Name, it.Detail)
				}
			}
		}
	}
	fmt.Fprintln(c.out, i18n.T(`
接下來：
  1. claudeshield check                  看目前的安全狀態
  2. claudeshield vault create           建立加密保險箱
  3. 關掉所有 Claude 視窗後：claudeshield vault migrate
  4. 到放機密的資料夾：claudeshield init
  5.（建議）把 eval "$(claudeshield shell-init)" 加進 ~/.zshrc，每次開 claude 前先檢查`, `
Next:
  1. claudeshield check                  see the current state
  2. claudeshield vault create           create the encrypted vault
  3. with every Claude window closed:    claudeshield vault migrate
  4. in a folder with sensitive data:    claudeshield init
  5. (recommended) add eval "$(claudeshield shell-init)" to ~/.zshrc`))
	return nil
}

func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func (c *cli) uninstall() error {
	var added []string
	if c.g.Installed != nil {
		added = c.g.Installed.AddedEnv
	}
	if err := settings.Uninstall(app.UserSettings(c.p), added); err != nil {
		return err
	}
	c.g.Installed = nil
	if err := config.SaveGlobal(c.p, c.g); err != nil {
		return err
	}
	l := filepath.Join(c.p.Home, ".local", "bin", "claudeshield")
	if t, err := os.Readlink(l); err == nil && strings.HasPrefix(t, c.p.State) {
		os.Remove(l)
	}
	fmt.Fprintln(c.out, i18n.T("已從 Claude Code 移除 ClaudeShield 的 hooks。保險箱、代號對照表和設定都還留著（在 ~/.claudeshield）。",
		"Removed ClaudeShield's hooks from Claude Code. The vault, placeholder tables and config are kept (~/.claudeshield)."))
	return nil
}

func (c *cli) setLang(args []string) error {
	if len(args) != 1 || (args[0] != "zh" && args[0] != "en") {
		return fmt.Errorf("usage: claudeshield lang zh|en")
	}
	c.g.Lang = args[0]
	if err := config.SaveGlobal(c.p, c.g); err != nil {
		return err
	}
	i18n.Set(args[0])
	fmt.Fprintln(c.out, i18n.T("已切換成中文。", "Switched to English."))
	return nil
}

// --- ack / account / log -------------------------------------------------------

func (c *cli) ack(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: claudeshield ack <finding-id>")
	}
	r := preflight.Run(app.PreflightOptions(c.p, c.g, cwd(), true))
	for _, f := range r.Findings {
		if f.ID != args[0] {
			continue
		}
		if f.NoAck || f.Fingerprint == "" {
			return fmt.Errorf("%s", i18n.Tf("「%s」不能用 ack 略過，必須照解法處理。", "%q cannot be acknowledged; it has to be fixed.", f.Title))
		}
		fmt.Fprintln(c.out, f.Title)
		fmt.Fprintln(c.out, f.Detail)
		if !confirm(i18n.T("你確認這是你自己的設定、而且沒問題嗎？之後只要內容改變就會再擋下。", "Do you confirm this is yours and safe? It will block again if the value changes.")) {
			return fmt.Errorf("%s", i18n.T("取消了", "cancelled"))
		}
		if c.g.Acknowledged == nil {
			c.g.Acknowledged = map[string]string{}
		}
		c.g.Acknowledged[f.ID] = f.Fingerprint
		return config.SaveGlobal(c.p, c.g)
	}
	return fmt.Errorf("%s", i18n.Tf("現在的檢查結果裡沒有 %s", "no current finding with ID %s", args[0]))
}

func (c *cli) account(args []string) error {
	if len(args) > 0 && args[0] == "confirm" {
		fmt.Fprintln(c.out, i18n.T("1. 打開 https://claude.ai/settings/data-privacy-controls\n2. 確認「幫助改善 Claude」是關閉的",
			"1. Open https://claude.ai/settings/data-privacy-controls\n2. Make sure \"Help improve Claude\" is off"))
		if !confirm(i18n.T("已經確認關閉了嗎？", "Is it off?")) {
			return fmt.Errorf("%s", i18n.T("沒有記錄", "not recorded"))
		}
		c.g.Account.TrainingOffConfirmedAt = time.Now().UTC()
		if err := config.SaveGlobal(c.p, c.g); err != nil {
			return err
		}
		fmt.Fprintln(c.out, i18n.T("已記錄，30 天後會再請你確認一次。", "Recorded. You will be asked again in 30 days."))
		return nil
	}
	kind, detail := preflight.DetectAccount(c.p, map[string]string{"ANTHROPIC_API_KEY": os.Getenv("ANTHROPIC_API_KEY"), "CLAUDE_CODE_USE_BEDROCK": os.Getenv("CLAUDE_CODE_USE_BEDROCK"), "CLAUDE_CODE_USE_VERTEX": os.Getenv("CLAUDE_CODE_USE_VERTEX")})
	fmt.Fprintf(c.out, "%s (%s)\n", kind, detail)
	if t := c.g.Account.TrainingOffConfirmedAt; !t.IsZero() {
		fmt.Fprintln(c.out, i18n.Tf("上次確認訓練開關關閉：%s", "Training switch last confirmed off: %s", t.Local().Format("2006-01-02")))
	}
	return nil
}

func (c *cli) log(args []string) error {
	n := 20
	if len(args) == 2 && args[0] == "-n" {
		fmt.Sscan(args[1], &n)
	}
	b, err := os.ReadFile(c.p.EventLog())
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, l := range lines {
		fmt.Fprintln(c.out, l)
	}
	return nil
}

// --- audit ----------------------------------------------------------------------

func (c *cli) audit(args []string) (int, error) {
	o := audit.Options{Paths: c.p, Cwd: cwd(), Self: app.Self(c.g)}
	items, err := audit.Collect(o)
	if err != nil {
		return 1, err
	}
	bl, ok, err := audit.LoadBaseline(c.p)
	if err != nil {
		return 1, err
	}
	root := audit.ProjectRoot(c.p, cwd())
	changes := audit.Diff(items, bl, root)
	if len(args) > 0 && args[0] == "approve" {
		if len(changes) > 0 {
			c.printChanges(changes)
			if !confirm(i18n.T("全部核可？", "Approve all of these?")) {
				return 1, fmt.Errorf("%s", i18n.T("取消了", "cancelled"))
			}
		}
		if err := audit.SaveBaseline(c.p, audit.Approve(bl, items, root, time.Now())); err != nil {
			return 1, err
		}
		fmt.Fprintln(c.out, i18n.Tf("核可清單已更新（%d 項）。", "Baseline updated (%d items).", len(items)))
		return 0, nil
	}
	for _, it := range items {
		fmt.Fprintf(c.out, "%-14s %-10s %-30s %s\n", shortScope(it.Scope), it.Kind, it.Name, it.Detail)
	}
	if !ok {
		fmt.Fprintln(c.out, i18n.T("\n還沒有核可清單。確認上面每一項都是你裝的，再執行 claudeshield audit approve。", "\nNo baseline yet. If every item above is yours, run `claudeshield audit approve`."))
		return 0, nil
	}
	if len(changes) == 0 {
		fmt.Fprintln(c.out, i18n.T("\n跟核可清單一致。", "\nMatches the approved baseline."))
		return 0, nil
	}
	fmt.Fprintln(c.out)
	c.printChanges(changes)
	return 1, nil
}

func shortScope(s string) string {
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i]
	}
	return s
}

func (c *cli) printChanges(changes []audit.Change) {
	for _, ch := range changes {
		switch ch.Op {
		case "new":
			fmt.Fprintln(c.out, c.paint("31", "+ ")+i18n.Tf("新增 %s %s（%s）：%s", "new %s %s (%s): %s", ch.Kind, ch.Name, ch.Scope, ch.Detail))
		case "changed":
			fmt.Fprintln(c.out, c.paint("33", "~ ")+i18n.Tf("變更 %s %s（%s）：%s → %s", "changed %s %s (%s): %s → %s", ch.Kind, ch.Name, ch.Scope, ch.Was, ch.Detail))
		case "removed":
			fmt.Fprintln(c.out, "- "+i18n.Tf("移除 %s %s（%s）", "removed %s %s (%s)", ch.Kind, ch.Name, ch.Scope))
		}
	}
}

// --- vault -----------------------------------------------------------------------

func (c *cli) vault(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "create":
		if vault.Configured(c.g) {
			return fmt.Errorf("%s", i18n.Tf("已經有保險箱了：%s", "a vault already exists: %s", c.g.Vault.Image))
		}
		image := vault.DefaultImage(c.p)
		size := "50g"
		for i := 1; i+1 < len(args); i++ {
			switch args[i] {
			case "--image":
				image = args[i+1]
			case "--size":
				size = args[i+1]
			}
		}
		fmt.Fprintln(c.out, i18n.T("建立 AES-256 加密的保險箱。密碼請記好：忘記就打不開，沒有任何救回的方法。", "Creating an AES-256 encrypted vault. Remember the password: if it is lost, the data cannot be recovered."))
		pw, err := readPassword(i18n.T("設定密碼：", "New password: "))
		if err != nil {
			return err
		}
		pw2, err := readPassword(i18n.T("再輸入一次：", "Repeat: "))
		if err != nil {
			return err
		}
		if string(pw) != string(pw2) {
			return fmt.Errorf("%s", i18n.T("兩次密碼不一樣", "passwords do not match"))
		}
		if len(pw) < 8 {
			return fmt.Errorf("%s", i18n.T("密碼至少 8 個字元", "use at least 8 characters"))
		}
		c.g.Vault = config.VaultConfig{Image: image, Volume: c.g.VaultVolume()}
		if err := vault.Create(image, c.g.VaultVolume(), size, pw); err != nil {
			return err
		}
		if err := vault.Open(c.p, c.g, pw); err != nil {
			return err
		}
		if err := config.SaveGlobal(c.p, c.g); err != nil {
			return err
		}
		fmt.Fprintln(c.out, i18n.Tf("保險箱建立好了，已經打開：%s\n下一步：關掉所有 Claude 視窗，然後 claudeshield vault migrate",
			"Vault created and open at %s\nNext: close every Claude window, then run `claudeshield vault migrate`", vault.MountPoint(c.p, c.g)))
		return nil
	case "open":
		if !vault.Configured(c.g) {
			return fmt.Errorf("%s", i18n.T("還沒有保險箱，先執行 claudeshield vault create", "no vault yet; run `claudeshield vault create`"))
		}
		if vault.Mounted(c.p, c.g) {
			fmt.Fprintln(c.out, i18n.T("保險箱已經是打開的。", "The vault is already open."))
			return nil
		}
		for attempt := 0; attempt < 3; attempt++ {
			pw, err := readPassword(i18n.T("保險箱密碼：", "Vault password: "))
			if err != nil {
				return err
			}
			err = vault.Open(c.p, c.g, pw)
			if err == vault.ErrWrongPassword {
				fmt.Fprintln(c.errw, i18n.T("密碼錯誤。", "Wrong password."))
				continue
			}
			if err != nil {
				return err
			}
			fmt.Fprintln(c.out, i18n.T("保險箱已打開。", "Vault open."))
			return nil
		}
		return fmt.Errorf("%s", i18n.T("密碼錯誤三次", "three wrong passwords"))
	case "close":
		force := len(args) > 1 && args[1] == "--force"
		if err := vault.Close(c.p, c.g, force); err != nil {
			return fmt.Errorf("%v\n%s", err, i18n.T("有程式還在用保險箱裡的檔案（通常是 Claude Code）。先關掉 Claude 視窗。", "Something still has files open in the vault (usually Claude Code). Close Claude first."))
		}
		fmt.Fprintln(c.out, i18n.T("保險箱已關上。", "Vault closed."))
		return nil
	case "migrate", "restore":
		if !vault.Mounted(c.p, c.g) {
			return fmt.Errorf("%s", i18n.T("保險箱沒有打開，先執行 claudeshield vault open", "the vault is not open; run `claudeshield vault open`"))
		}
		ps, _ := exec.Command("ps", "-axo", "pid=,comm=").Output()
		if running := vault.RunningClaude(string(ps)); len(running) > 0 {
			return fmt.Errorf("%s\n  %s", i18n.T("還有 Claude 在執行，請全部關掉再來（包括桌面版 App）：", "Claude is still running; close every instance first (including the desktop app):"), strings.Join(running, "\n  "))
		}
		plans := vault.MigratePlan(c.p, c.g, preflight.VaultDirs, preflight.VaultFiles)
		progress := func(n string) { fmt.Fprintln(c.out, "  → "+n) }
		if args[0] == "restore" {
			if err := vault.Restore(c.p, c.g, plans, progress); err != nil {
				return err
			}
			fmt.Fprintln(c.out, i18n.T("已把資料搬回 ~/.claude（未加密）。", "Data moved back to ~/.claude (unencrypted)."))
			return nil
		}
		var total int64
		for _, pl := range plans {
			if pl.Exists {
				fmt.Fprintf(c.out, "  %-18s %6d files  %8.1f MB\n", pl.Name, pl.Entries, float64(pl.Bytes)/1e6)
				total += pl.Bytes
			}
		}
		if !confirm(i18n.Tf("把以上 %.1f MB 搬進保險箱？", "Move the %.1f MB above into the vault?", float64(total)/1e6)) {
			return fmt.Errorf("%s", i18n.T("取消了", "cancelled"))
		}
		if err := vault.Migrate(c.p, c.g, plans, progress); err != nil {
			return err
		}
		fmt.Fprintln(c.out, i18n.T("完成。之後保險箱關著的時候，Claude Code 無法寫入對話紀錄，ClaudeShield 會擋下並提醒你先 vault open。\n注意：舊的明文檔案可能還留在 Time Machine 備份或 APFS 快照裡。",
			"Done. While the vault is closed Claude Code cannot write transcripts, and ClaudeShield blocks sessions until you `vault open`.\nNote: older plaintext copies may remain in Time Machine backups or APFS snapshots."))
		return nil
	case "status":
		if !vault.Configured(c.g) {
			fmt.Fprintln(c.out, i18n.T("還沒有保險箱。", "No vault yet."))
			return nil
		}
		state := i18n.T("關著", "closed")
		if vault.Mounted(c.p, c.g) {
			state = i18n.T("打開", "open")
		}
		fmt.Fprintf(c.out, "%s: %s (%s)\n", c.tilde(c.g.Vault.Image), state, vault.MountPoint(c.p, c.g))
		for _, pl := range vault.MigratePlan(c.p, c.g, preflight.VaultDirs, preflight.VaultFiles) {
			s := i18n.T("在保險箱裡", "in vault")
			if pl.Exists {
				s = c.paint("33", i18n.T("還在外面（明文）", "outside (plaintext)"))
			} else if !pl.Linked {
				s = i18n.T("尚未建立", "not created yet")
			}
			fmt.Fprintf(c.out, "  %-18s %s\n", pl.Name, s)
		}
		return nil
	}
	return fmt.Errorf("usage: claudeshield vault create|open|close|status|migrate|restore")
}
