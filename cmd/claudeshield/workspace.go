package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/detect"
	"github.com/useless-husband/claudeshield/internal/i18n"
	"github.com/useless-husband/claudeshield/internal/preflight"
	"github.com/useless-husband/claudeshield/internal/settings"
	"github.com/useless-husband/claudeshield/internal/tokenmap"
	"github.com/useless-husband/claudeshield/internal/vault"
)

// --- init ------------------------------------------------------------------------

func (c *cli) initWorkspace(args []string) error {
	dir := cwd()
	if len(args) > 0 {
		dir = args[0]
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	marker := filepath.Join(dir, config.WorkspaceFile)
	ws := config.DefaultWorkspace()
	if b, err := os.ReadFile(marker); err == nil {
		if err := json.Unmarshal(b, &ws); err != nil {
			return fmt.Errorf("%s: %w", marker, err)
		}
		fmt.Fprintln(c.out, i18n.T("這個資料夾已經是敏感資料夾，更新沙盒設定。", "Already a sensitive workspace; refreshing its sandbox rules."))
	} else {
		b, _ := json.MarshalIndent(ws, "", "  ")
		if err := os.WriteFile(marker, append(b, '\n'), 0o600); err != nil {
			return err
		}
	}
	ws.Root = dir
	for _, g := range ws.Protect {
		if lit := strings.TrimSuffix(strings.TrimSuffix(g, "/**"), "/*"); lit != "" && !strings.ContainsAny(lit, "*?[") {
			os.MkdirAll(filepath.Join(dir, lit), 0o700)
		}
	}
	local := filepath.Join(dir, ".claude", "settings.local.json")
	if err := settings.MergeWorkspaceSettings(local, ws); err != nil {
		return err
	}
	// Keep the marker (it lists client names) and the local settings out of git.
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		appendLines(filepath.Join(dir, ".gitignore"), []string{config.WorkspaceFile, ".claude/settings.local.json", "raw/"})
	}
	fmt.Fprintln(c.out, c.paint("32", i18n.Tf("%s 已標記為敏感資料夾。", "%s is now a sensitive workspace.", c.tilde(dir))))
	fmt.Fprintln(c.out, i18n.Tf(`
在這個資料夾（和子資料夾）裡：
  • Claude 讀到的身分證、電話、Email、地址、金額、公司名、金鑰…都會先換成代號
  • Claude 寫檔或在本機跑指令時，代號自動換回真實內容
  • 指令都在沙盒裡跑；要把資料送到白名單以外的地方會被擋下
  • raw/ 是保護區：放原始檔，Claude 完全不能碰

建議接著做：
  1. 打開 %s，在 "terms" 裡填上客戶名、公司名、專案代號（這些沒辦法靠規則猜到）
  2. 個人帳號的話：claudeshield account confirm
  3. claudeshield check`, `
Inside this folder (and below):
  • IDs, phone numbers, e-mail and street addresses, amounts, company names, keys… are replaced with placeholders before Claude reads them
  • placeholders turn back into real values when Claude writes files or runs local commands
  • shell commands run in the sandbox; sending data to hosts off the allowlist is refused
  • raw/ is protected: keep originals there, Claude cannot touch it

Next:
  1. Edit %s and list client names, company names and code words under "terms" (no pattern can guess those)
  2. On a personal account: claudeshield account confirm
  3. claudeshield check`, c.tilde(marker)))
	return nil
}

func appendLines(path string, lines []string) {
	b, _ := os.ReadFile(path)
	have := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		have[strings.TrimSpace(l)] = true
	}
	var add []string
	for _, l := range lines {
		if !have[l] {
			add = append(add, l)
		}
	}
	if len(add) == 0 {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	if len(b) > 0 && !bytes.HasSuffix(b, []byte("\n")) {
		f.WriteString("\n")
	}
	f.WriteString("# claudeshield\n" + strings.Join(add, "\n") + "\n")
}

// --- detection helpers -------------------------------------------------------------

// detectorFor picks the detector for a path: the workspace's when the path is
// inside one, Strict with defaults otherwise (the CLI is used deliberately on
// data the user considers sensitive).
func (c *cli) detectorFor(path string) (detect.Config, config.Workspace, bool) {
	dir := path
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		dir = filepath.Dir(path)
	}
	ws, ok, err := config.FindWorkspace(dir)
	if ok && err == nil {
		return ws.DetectorConfig(), ws, true
	}
	return detect.Config{Profile: detect.Strict, Allow: detect.DefaultAllow}, config.Workspace{}, false
}

func isText(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	return !bytes.Contains(b[:n], []byte{0}) && utf8.Valid(trimPartialRune(b[:n]))
}

func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0 && !utf8.Valid(b); i++ {
		b = b[:len(b)-1]
	}
	return b
}

// --- scan --------------------------------------------------------------------------

func (c *cli) scan(args []string) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("usage: claudeshield scan <file|dir|->")
	}
	type hit struct {
		file string
		line int
		m    detect.Match
	}
	var hits []hit
	scanText := func(name string, text string, cfg detect.Config) {
		d := detect.New(cfg)
		for _, m := range d.Find(text) {
			hits = append(hits, hit{name, 1 + strings.Count(text[:m.Start], "\n"), m})
		}
	}
	if args[0] == "-" {
		b, err := io.ReadAll(c.stdin)
		if err != nil {
			return 1, err
		}
		cfg, _, _ := c.detectorFor(cwd())
		scanText("stdin", string(b), cfg)
	} else {
		root := args[0]
		cfg, _, _ := c.detectorFor(root)
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || !isText(b) {
				return nil
			}
			scanText(p, string(b), cfg)
			return nil
		})
		if err != nil {
			return 1, err
		}
	}
	for _, h := range hits {
		fmt.Fprintf(c.out, "%s:%d  %-9s %s\n", h.file, h.line, h.m.Kind, preview(h.m.Value))
	}
	fmt.Fprintln(c.out, i18n.Tf("共 %d 個會被遮罩。", "%d value(s) would be masked.", len(hits)))
	if len(hits) > 0 {
		return 1, nil
	}
	return 0, nil
}

// preview shows enough of a value to recognise it without printing it whole.
func preview(v string) string {
	v = strings.ReplaceAll(v, "\n", "⏎")
	r := []rune(v)
	switch {
	case len(r) <= 4:
		return strings.Repeat("•", len(r))
	case len(r) <= 10:
		return string(r[:1]) + strings.Repeat("•", len(r)-2) + string(r[len(r)-1:])
	}
	return string(r[:3]) + strings.Repeat("•", 6) + string(r[len(r)-3:])
}

// --- mask / unmask -------------------------------------------------------------------

func (c *cli) mapFor(ws config.Workspace, inWS bool) (string, error) {
	p, err := vault.MapPath(c.p, c.g, ws, inWS)
	if err == vault.ErrClosed {
		return "", fmt.Errorf("%s", i18n.T("保險箱沒有打開，先執行 claudeshield vault open", "the vault is closed; run `claudeshield vault open`"))
	}
	return p, err
}

func (c *cli) mask(args []string) error {
	var src, dst string
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" && i+1 < len(args) {
			dst = args[i+1]
			i++
		} else {
			src = args[i]
		}
	}
	if src == "" || dst == "" {
		return fmt.Errorf("usage: claudeshield mask <src> -o <dst>")
	}
	cfg, _, _ := c.detectorFor(src)
	// Placeholders go into the table of the workspace Claude will work in: the
	// destination's, if it is inside one.
	absDst, _ := filepath.Abs(dst)
	ws, inWS, err := config.FindWorkspace(filepath.Dir(absDst))
	if err != nil {
		return err
	}
	if !inWS {
		ws, inWS, _ = config.FindWorkspace(filepath.Dir(src))
	}
	if inWS && ws.Protected(absDst) {
		return fmt.Errorf("%s", i18n.T("目的地在受保護範圍裡，Claude 會讀不到；請放到別的地方。", "the destination is inside a protected path, where Claude cannot read it"))
	}
	mp, err := c.mapFor(ws, inWS)
	if err != nil {
		return err
	}
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	files, masked, skipped := 0, 0, 0
	err = tokenmap.Update(mp, func(m *tokenmap.Map) error {
		d := detect.New(cfg)
		one := func(from, to string) error {
			b, err := os.ReadFile(from)
			if err != nil {
				return err
			}
			if !isText(b) {
				skipped++
				fmt.Fprintln(c.errw, i18n.Tf("略過（不是文字檔）：%s", "skipped (not text): %s", from))
				return nil
			}
			out, ms := m.Mask(d, string(b))
			files++
			masked += len(ms)
			if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
				return err
			}
			return os.WriteFile(to, []byte(out), 0o600)
		}
		if !st.IsDir() {
			return one(src, dst)
		}
		return filepath.WalkDir(src, func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() {
				if de.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			rel, _ := filepath.Rel(src, p)
			return one(p, filepath.Join(dst, rel))
		})
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.out, i18n.Tf("完成：%d 個檔案，遮罩 %d 個值，略過 %d 個非文字檔。", "Done: %d file(s), %d value(s) masked, %d non-text file(s) skipped.", files, masked, skipped))
	return nil
}

func (c *cli) unmask(args []string) error {
	var src, dst string
	inPlace := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-o" && i+1 < len(args):
			dst = args[i+1]
			i++
		case args[i] == "--in-place":
			inPlace = true
		default:
			src = args[i]
		}
	}
	if src == "" {
		return fmt.Errorf("usage: claudeshield unmask <file|-> [-o out | --in-place]")
	}
	var b []byte
	var err error
	where := cwd()
	if src == "-" {
		b, err = io.ReadAll(c.stdin)
	} else {
		b, err = os.ReadFile(src)
		where = filepath.Dir(src)
	}
	if err != nil {
		return err
	}
	ws, inWS, err := config.FindWorkspace(where)
	if err != nil {
		return err
	}
	mp, err := c.mapFor(ws, inWS)
	if err != nil {
		return err
	}
	m, err := tokenmap.Load(mp)
	if err != nil {
		return err
	}
	out, n, unknown := m.Unmask(string(b))
	switch {
	case inPlace && src != "-":
		dst = src
	case dst == "":
		fmt.Fprint(c.out, out)
	}
	if dst != "" {
		if err := os.WriteFile(dst, []byte(out), 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintln(c.errw, i18n.Tf("還原了 %d 個代號。", "Restored %d placeholder(s).", n))
	if len(unknown) > 0 {
		fmt.Fprintln(c.errw, i18n.Tf("不認得的代號：%s", "Unknown placeholders: %s", strings.Join(unknown, ", ")))
	}
	return nil
}

func (c *cli) showMap(args []string) error {
	reveal := len(args) > 0 && args[0] == "--reveal"
	ws, inWS, err := config.FindWorkspace(cwd())
	if err != nil {
		return err
	}
	mp, err := c.mapFor(ws, inWS)
	if err != nil {
		return err
	}
	m, err := tokenmap.Load(mp)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.out, i18n.Tf("對照表：%s（%d 筆）", "Table: %s (%d entries)", c.tilde(mp), m.Len()))
	for _, e := range m.Entries() {
		v := preview(e.Value)
		if reveal {
			v = e.Value
		}
		fmt.Fprintf(c.out, "  %-16s %s\n", e.Token, v)
	}
	return nil
}

// --- tls -----------------------------------------------------------------------------

func (c *cli) tls(args []string) error {
	if len(args) != 2 || args[0] != "trust" {
		return fmt.Errorf("usage: claudeshield tls trust <host>")
	}
	host := args[1]
	chain, ip, err := preflight.FetchChain(host)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.out, i18n.Tf("%s（%s）送來的憑證鏈：", "Chain served by %s (%s):", host, ip))
	for _, cert := range chain {
		fmt.Fprintf(c.out, "  %s  ←  %s\n", cert.Subject.CommonName, cert.Issuer.CommonName)
	}
	// Refuse anything the system itself does not trust, so this command can
	// widen the pins only to a publicly trusted CA.
	inter := x509.NewCertPool()
	for _, cert := range chain[1:] {
		inter.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err != nil {
		return fmt.Errorf("%s: %v", i18n.T("連系統都不信任這串憑證，拒絕記住", "the system does not trust this chain either; refusing to pin it"), err)
	}
	top := chain[len(chain)-1]
	if !preflight.InAnthropicRange(ip) {
		fmt.Fprintln(c.out, c.paint("31", i18n.T("警告：這個連線的 IP 不在 Anthropic 網段。", "Warning: this connection's IP is outside Anthropic's ranges.")))
	}
	fmt.Fprintln(c.out, i18n.Tf("會記住：%s（SPKI %s）", "Will pin: %s (SPKI %s)", top.Subject.CommonName, preflight.SPKIHash(top)[:16]+"…"))
	if !confirm(i18n.T("你已經用別的網路確認過、而且知道 Anthropic 換了憑證商嗎？", "Have you checked from another network and confirmed Anthropic changed CA?")) {
		return fmt.Errorf("%s", i18n.T("取消了", "cancelled"))
	}
	c.g.TLS.ExtraRoots = append(c.g.TLS.ExtraRoots, preflight.SPKIHash(top))
	sort.Strings(c.g.TLS.ExtraRoots)
	return config.SaveGlobal(c.p, c.g)
}
