package preflight

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/i18n"
	"github.com/useless-husband/claudeshield/internal/vault"
)

//go:embed roots/*.pem
var rootFS embed.FS

// Options configures a run. Every function field has a real default; tests
// replace them to stay offline and deterministic.
type Options struct {
	Paths   config.Paths
	Global  config.Global
	Cwd     string
	Environ []string // KEY=VALUE, defaults to os.Environ()
	Network bool     // run the DNS and TLS checks
	Now     func() time.Time

	RunCmd   func(name string, args ...string) (string, error)
	Resolve  func(host string) ([]net.IP, error)
	TLSChain func(host string) (chain []*x509.Certificate, remote net.IP, err error)
	// Audit compares installed extensions with the approved baseline. It is
	// injected to keep this package free of the audit package's filesystem walk.
	Audit func(cwd string) []Finding
	// HooksInstalled reports whether claudeshield's hooks are wired into
	// Claude Code's user settings.
	HooksInstalled func() (bool, string)
}

// Anthropic's published inbound ranges for the API
// (https://platform.claude.com/docs/en/api/ip-addresses).
var anthropicRanges = mustCIDRs("160.79.104.0/23", "2607:6bc0::/48")

func mustCIDRs(s ...string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range s {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		out = append(out, n)
	}
	return out
}

// InAnthropicRange reports whether ip is in Anthropic's published API ranges.
func InAnthropicRange(ip net.IP) bool {
	for _, n := range anthropicRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (o *Options) defaults() {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Environ == nil {
		o.Environ = os.Environ()
	}
	if o.RunCmd == nil {
		o.RunCmd = runCmd
	}
	if o.Resolve == nil {
		o.Resolve = func(host string) ([]net.IP, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			var ips []net.IP
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, err
		}
	}
	if o.TLSChain == nil {
		o.TLSChain = FetchChain
	}
}

func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// FetchChain completes a TLS handshake and returns the server's chain
// unverified; verification against claudeshield's own root set happens in
// checkTLS, deliberately without the system trust store.
func FetchChain(host string) ([]*x509.Certificate, net.IP, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, "443"), &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // verified manually against pinned roots below
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	var ip net.IP
	if a, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = a.IP
	}
	return conn.ConnectionState().PeerCertificates, ip, nil
}

// Run performs every check and returns the report.
func Run(o Options) Report {
	o.defaults()
	r := Report{At: o.Now(), Cwd: o.Cwd}
	ws, inWS, wsErr := config.FindWorkspace(o.Cwd)
	if inWS {
		r.Workspace = ws.Root
		if wsErr != nil {
			r.Findings = append(r.Findings, Finding{ID: "workspace.parse", Severity: Block, NoAck: true,
				Title:  i18n.Tf("%s 格式錯誤", "%s cannot be parsed", config.WorkspaceFile),
				Detail: wsErr.Error(),
				Fix:    i18n.T("修正那個 JSON 檔（可以刪掉後重新執行 claudeshield init）。", "Fix the JSON file (or delete it and run `claudeshield init` again)."),
			})
		}
	}
	if inWS && wsErr == nil && !ws.SandboxStrict(filepath.Join(o.Paths.ClaudeDir, "settings.json")) {
		r.Findings = append(r.Findings, Finding{ID: "workspace.sandbox", Severity: Block, Fingerprint: Fingerprint(ws.Root),
			Title:  i18n.T("敏感資料夾的沙盒沒有開好", "The sensitive workspace's sandbox is not set up"),
			Detail: i18n.T("沒有沙盒時，指令執行失敗的輸出不會經過遮罩，網路也只靠 hook 判斷。", "Without the sandbox, the output of failing commands is not masked and network access rests on the hook alone."),
			Fix:    i18n.T("在這個資料夾執行 claudeshield init（會寫入 .claude/settings.local.json）", "Run `claudeshield init` in this folder (it writes .claude/settings.local.json)"),
		})
	}
	r.Findings = append(r.Findings, checkEnv(o)...)
	r.Findings = append(r.Findings, checkSettings(o)...)
	r.Findings = append(r.Findings, checkSystemProxy(o)...)
	r.Findings = append(r.Findings, checkTrustSettings(o)...)
	r.Findings = append(r.Findings, checkSniffers(o)...)
	r.Findings = append(r.Findings, checkScreen(o)...)
	if o.Network {
		r.Findings = append(r.Findings, checkNetwork(o)...)
	}
	r.Findings = append(r.Findings, checkAccount(o, inWS)...)
	r.Findings = append(r.Findings, checkVault(o, inWS)...)
	if o.Audit != nil {
		r.Findings = append(r.Findings, o.Audit(o.Cwd)...)
	}
	if o.HooksInstalled != nil {
		if ok, detail := o.HooksInstalled(); !ok {
			// Without the hooks nothing checks or masks inside the session,
			// so `claudeshield run` must not start Claude Code.
			r.Findings = append(r.Findings, Finding{ID: "hooks.missing", Severity: Block, NoAck: true,
				Title:  i18n.T("ClaudeShield 的 hooks 沒有完整裝進 Claude Code", "ClaudeShield's hooks are not fully installed in Claude Code"),
				Detail: detail,
				Fix:    "claudeshield install",
			})
		}
	}
	r.Findings = append(r.Findings, checkFileVault(o)...)
	return r
}

func checkFileVault(o Options) []Finding {
	out, err := o.RunCmd("fdesetup", "status")
	if err != nil {
		return nil
	}
	if strings.Contains(out, "FileVault is On") {
		return []Finding{{ID: "disk.filevault", Severity: Info, Title: i18n.T("FileVault 全碟加密已開啟", "FileVault full-disk encryption is on")}}
	}
	return []Finding{{ID: "disk.filevault", Severity: Warn, Fingerprint: "off",
		Title:  i18n.T("FileVault 全碟加密沒有開", "FileVault full-disk encryption is off"),
		Detail: i18n.T("保險箱外的檔案（工作資料夾、暫存檔、swap）都是明文；電腦遺失時任何人都讀得到。", "Everything outside the vault (working folders, temp files, swap) is plaintext; anyone with the disk can read it."),
		Fix:    i18n.T("系統設定 → 隱私權與安全性 → FileVault → 開啟", "System Settings → Privacy & Security → FileVault → Turn On"),
	}}
}

func envMap(environ []string) map[string]string {
	m := map[string]string{}
	for _, kv := range environ {
		if i := strings.IndexByte(kv, '='); i > 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

// envFindings checks one set of variables; origin says where they came from
// ("the shell", "~/.claude/settings.json", ...).
// EnvFindings is envFindings for other packages (the ConfigChange hook).
func EnvFindings(vars map[string]string, origin string) []Finding { return envFindings(vars, origin) }

func envFindings(vars map[string]string, origin string) []Finding {
	var out []Finding
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := vars[k]
		if v == "" {
			continue
		}
		id := "env." + k + "@" + origin
		switch {
		case strings.HasPrefix(k, "ANTHROPIC_") && strings.HasSuffix(k, "BASE_URL"):
			if isOfficialURL(v) {
				continue
			}
			out = append(out, Finding{ID: id, Severity: Block, Fingerprint: Fingerprint(k, v),
				Title:  i18n.Tf("%s 把 Claude 的連線改送到別的伺服器", "%s redirects Claude's traffic to another server", k),
				Detail: i18n.Tf("來源：%s\n目前的值：%s\n所有對話都會先經過這台伺服器，它看得到全部內容。", "Set in: %s\nValue: %s\nEvery conversation would pass through that server, which can read all of it.", origin, v),
				Fix:    i18n.Tf("如果不是你自己設定的，從 %s 刪掉這個變數。確定是你信任的閘道器，才用 claudeshield ack %s 接受。", "If you did not set this, remove it from %s. Only if it is a gateway you trust: `claudeshield ack %s`.", origin, id),
			})
		case k == "HTTPS_PROXY" || k == "https_proxy" || k == "HTTP_PROXY" || k == "http_proxy" || k == "ALL_PROXY" || k == "all_proxy":
			out = append(out, Finding{ID: id, Severity: Block, Fingerprint: Fingerprint(k, v),
				Title:  i18n.Tf("設定了代理伺服器 %s", "A proxy is configured (%s)", k),
				Detail: i18n.Tf("來源：%s\n值：%s\nClaude Code 的連線會經過這個代理。", "Set in: %s\nValue: %s\nClaude Code's connections go through this proxy.", origin, v),
				Fix:    i18n.Tf("不是你設定的就刪掉。公司網路規定一定要用代理的話：claudeshield ack %s", "Remove it unless you set it. If your network requires it: `claudeshield ack %s`", id),
			})
		case k == "NODE_TLS_REJECT_UNAUTHORIZED" && v == "0":
			out = append(out, Finding{ID: id, Severity: Block, NoAck: true,
				Title:  i18n.T("憑證驗證被關掉了（NODE_TLS_REJECT_UNAUTHORIZED=0）", "Certificate verification is disabled (NODE_TLS_REJECT_UNAUTHORIZED=0)"),
				Detail: i18n.Tf("來源：%s\n任何人都能假冒 Anthropic 的伺服器。", "Set in: %s\nAnyone could impersonate Anthropic's servers.", origin),
				Fix:    i18n.Tf("從 %s 刪掉這個變數。", "Remove it from %s.", origin),
			})
		case k == "NODE_EXTRA_CA_CERTS" || k == "SSL_CERT_FILE" || k == "SSL_CERT_DIR":
			out = append(out, Finding{ID: id, Severity: Block, Fingerprint: Fingerprint(k, v),
				Title:  i18n.Tf("額外信任了一組憑證（%s）", "Extra certificates are trusted (%s)", k),
				Detail: i18n.Tf("來源：%s\n檔案：%s\n這是中間人攔截加密連線的標準做法。", "Set in: %s\nFile: %s\nThis is how a man-in-the-middle decrypts TLS.", origin, v),
				Fix:    i18n.Tf("不是你設定的就刪掉。確定是公司要求的才 claudeshield ack %s", "Remove it unless you set it. If your employer requires it: `claudeshield ack %s`", id),
			})
		case k == "SSLKEYLOGFILE":
			out = append(out, Finding{ID: id, Severity: Block, NoAck: true,
				Title:  i18n.T("加密金鑰被寫到檔案（SSLKEYLOGFILE）", "TLS session keys are being logged (SSLKEYLOGFILE)"),
				Detail: i18n.Tf("來源：%s\n檔案：%s\n有了這個檔，錄下來的網路封包就能被解密。", "Set in: %s\nFile: %s\nWith this file, captured traffic can be decrypted.", origin, v),
				Fix:    i18n.Tf("從 %s 刪掉這個變數，並刪除那個檔案。", "Remove it from %s and delete the file.", origin),
			})
		case k == "NODE_OPTIONS" && nodeOptionsRisky(v):
			out = append(out, Finding{ID: id, Severity: Block, Fingerprint: Fingerprint(k, v),
				Title:  i18n.T("NODE_OPTIONS 會把別的程式碼載入 Claude Code", "NODE_OPTIONS loads extra code into Claude Code"),
				Detail: i18n.Tf("來源：%s\n值：%s", "Set in: %s\nValue: %s", origin, v),
				Fix:    i18n.Tf("不是你設定的就刪掉；確定沒問題才 claudeshield ack %s", "Remove it unless you set it; otherwise `claudeshield ack %s`", id),
			})
		case strings.HasPrefix(k, "DYLD_INSERT_LIBRARIES") || k == "DYLD_LIBRARY_PATH" || k == "DYLD_FRAMEWORK_PATH":
			out = append(out, Finding{ID: id, Severity: Block, Fingerprint: Fingerprint(k, v),
				Title:  i18n.Tf("%s 會把動態函式庫注入程式", "%s injects libraries into programs", k),
				Detail: i18n.Tf("來源：%s\n值：%s", "Set in: %s\nValue: %s", origin, v),
				Fix:    i18n.Tf("不是你設定的就刪掉；確定沒問題才 claudeshield ack %s", "Remove it unless you set it; otherwise `claudeshield ack %s`", id),
			})
		}
	}
	return out
}

func isOfficialURL(v string) bool {
	v = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), "/")
	return v == "https://api.anthropic.com" || v == "https://api.anthropic.com/v1"
}

func nodeOptionsRisky(v string) bool {
	for _, f := range strings.Fields(v) {
		for _, bad := range []string{"--require", "-r", "--import", "--loader", "--experimental-loader", "--inspect", "--inspect-brk", "--tls-keylog", "--use-openssl-ca", "--use-system-ca"} {
			if f == bad || strings.HasPrefix(f, bad+"=") {
				return true
			}
		}
	}
	return false
}

func checkEnv(o Options) []Finding {
	return envFindings(envMap(o.Environ), i18n.T("目前的終端機環境", "the shell environment"))
}

// settingsFiles lists every settings file Claude Code reads for a directory.
func settingsFiles(p config.Paths, cwd string) []string {
	files := []string{
		filepath.Join(p.ClaudeDir, "settings.json"),
		filepath.Join(p.ClaudeDir, "settings.local.json"),
		filepath.Join(p.ManagedDir, "managed-settings.json"),
	}
	if root := projectRoot(cwd); root != "" {
		files = append(files, filepath.Join(root, ".claude", "settings.json"), filepath.Join(root, ".claude", "settings.local.json"))
	}
	return files
}

// projectRoot is the nearest directory (from cwd up) containing .claude or
// .git, which is where Claude Code looks for project settings.
func projectRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	dir := cwd
	for {
		if dir == home {
			// ~/.claude is user settings, not a project
			return ""
		}
		for _, m := range []string{".git", ".claude"} {
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

// ReadSettings parses a settings file; a missing file returns nil, nil.
func ReadSettings(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func checkSettings(o Options) []Finding {
	var out []Finding
	home := o.Paths.Home
	for _, f := range settingsFiles(o.Paths, o.Cwd) {
		s, err := ReadSettings(f)
		if err != nil {
			out = append(out, Finding{ID: "settings.parse@" + f, Severity: Warn, Title: i18n.Tf("讀不懂設定檔 %s", "Cannot parse settings file %s", tilde(f, home)), Detail: err.Error()})
			continue
		}
		if s == nil {
			continue
		}
		origin := tilde(f, home)
		if env, ok := s["env"].(map[string]any); ok {
			vars := map[string]string{}
			for k, v := range env {
				vars[k] = fmt.Sprint(v)
			}
			out = append(out, envFindings(vars, origin)...)
		}
		project := !strings.HasPrefix(f, o.Paths.ClaudeDir) && !strings.HasPrefix(f, o.Paths.ManagedDir)
		if b, _ := s["disableAllHooks"].(bool); b {
			out = append(out, Finding{ID: "settings.disableAllHooks@" + origin, Severity: Block, NoAck: true,
				Title:  i18n.Tf("%s 關掉了所有 hooks，ClaudeShield 會失效", "%s disables all hooks, which turns ClaudeShield off", origin),
				Detail: `"disableAllHooks": true`,
				Fix:    i18n.Tf("從 %s 刪掉 disableAllHooks。", "Remove disableAllHooks from %s.", origin),
			})
		}
		if h, ok := s["apiKeyHelper"].(string); ok && h != "" && project {
			out = append(out, Finding{ID: "settings.apiKeyHelper@" + origin, Severity: Block, Fingerprint: Fingerprint(h),
				Title:  i18n.Tf("專案設定 %s 指定了 apiKeyHelper", "Project settings %s define an apiKeyHelper", origin),
				Detail: i18n.Tf("每次連線前都會執行：%s", "Runs before every connection: %s", h),
				Fix:    i18n.Tf("確認那是你自己的腳本後：claudeshield ack settings.apiKeyHelper@%s", "If it is your own script: `claudeshield ack settings.apiKeyHelper@%s`", origin),
			})
		}
	}
	return out
}

func tilde(path, home string) string {
	if home != "" && strings.HasPrefix(path, home+"/") {
		return "~" + path[len(home):]
	}
	return path
}

var scutilKV = regexp.MustCompile(`(?m)^\s*(\w+)\s*:\s*(.+?)\s*$`)

func checkSystemProxy(o Options) []Finding {
	out, err := o.RunCmd("scutil", "--proxy")
	if err != nil {
		return nil
	}
	kv := map[string]string{}
	for _, m := range scutilKV.FindAllStringSubmatch(out, -1) {
		kv[m[1]] = m[2]
	}
	var on []string
	for _, p := range []struct{ enable, host string }{
		{"HTTPEnable", "HTTPProxy"}, {"HTTPSEnable", "HTTPSProxy"}, {"SOCKSEnable", "SOCKSProxy"},
		{"ProxyAutoConfigEnable", "ProxyAutoConfigURLString"}, {"ProxyAutoDiscoveryEnable", ""},
	} {
		if kv[p.enable] == "1" {
			on = append(on, strings.TrimSuffix(p.enable, "Enable")+" "+kv[p.host])
		}
	}
	if len(on) == 0 {
		return []Finding{{ID: "sysproxy", Severity: Info, Title: i18n.T("系統沒有設定代理伺服器", "No system proxy")}}
	}
	return []Finding{{ID: "sysproxy", Severity: Warn, Fingerprint: Fingerprint(on...),
		Title:  i18n.T("macOS 系統設定裡開了代理伺服器", "A system proxy is enabled in macOS settings"),
		Detail: strings.Join(on, "\n") + "\n" + i18n.T("Claude Code 預設不走系統代理，但這通常代表網路流量正在被轉送或檢查。", "Claude Code does not use the system proxy by default, but this usually means traffic is being routed or inspected."),
		Fix:    i18n.T("系統設定 → 網路 → 你的連線 → 詳細資訊 → 代理伺服器，確認每一項是不是你自己開的。", "System Settings → Network → your connection → Details → Proxies: check each one is yours."),
	}}
}

var certLine = regexp.MustCompile(`(?m)^Cert \d+: (.+)$`)

func checkTrustSettings(o Options) []Finding {
	var names []string
	for _, args := range [][]string{{"dump-trust-settings"}, {"dump-trust-settings", "-d"}} {
		out, _ := o.RunCmd("security", args...)
		for _, m := range certLine.FindAllStringSubmatch(out, -1) {
			names = append(names, strings.TrimSpace(m[1]))
		}
	}
	if len(names) == 0 {
		return []Finding{{ID: "trust.custom-roots", Severity: Info, Title: i18n.T("沒有自行加入信任的根憑證", "No user-added trusted root certificates")}}
	}
	sort.Strings(names)
	return []Finding{{ID: "trust.custom-roots", Severity: Block, Fingerprint: Fingerprint(names...),
		Title:  i18n.T("鑰匙圈裡有自行加入信任的根憑證", "User-added trusted root certificates are present"),
		Detail: strings.Join(names, "\n") + "\n" + i18n.T("這種憑證能讓別人解開這台電腦的所有加密連線（學校／公司管理的電腦、防毒軟體常會裝）。", "Such a certificate lets its owner decrypt this Mac's TLS connections (managed school/work Macs and antivirus products install them)."),
		Fix:    i18n.T("打開「鑰匙圈存取」→ 搜尋上面的名稱 → 不認得的就刪掉。確認是自己需要的才執行 claudeshield ack trust.custom-roots", "Open Keychain Access, search for the names above, delete the ones you do not recognise. If they are yours: `claudeshield ack trust.custom-roots`"),
	}}
}

func checkSniffers(o Options) []Finding {
	out, _ := o.RunCmd("sh", "-c", "lsof -Fc /dev/bpf* 2>/dev/null")
	var procs []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "c") && len(line) > 1 {
			procs = append(procs, line[1:])
		}
	}
	procs = uniqueSorted(procs)
	if len(procs) == 0 {
		return []Finding{{ID: "sniffer", Severity: Info, Title: i18n.T("沒有程式在擷取網路封包", "No packet capture in progress")}}
	}
	return []Finding{{ID: "sniffer", Severity: Warn, Fingerprint: Fingerprint(procs...),
		Title:  i18n.T("有程式正在擷取網路封包", "A program is capturing network packets"),
		Detail: strings.Join(procs, ", ") + "\n" + i18n.T("對話內容有 TLS 加密，光錄封包看不到內容；但如果同時有 SSLKEYLOGFILE 就能解開。", "Conversations are TLS-encrypted, so a capture alone cannot read them; together with SSLKEYLOGFILE it could."),
		Fix:    i18n.T("確認是不是你自己開的 Wireshark / tcpdump。", "Check whether this is your own Wireshark/tcpdump."),
	}}
}

// Remote-desktop and screen-sharing processes that can show your screen to
// someone else. Matching is on the executable name.
var screenProcs = []string{"AnyDesk", "TeamViewer", "TeamViewer_Desktop", "rustdesk", "RustDesk", "Parsec", "parsecd", "Splashtop Streamer", "SRStreamer", "ScreensharingAgent", "screensharingd", "MiniRemote", "MiniRemoteServer", "Chrome Remote Desktop Host", "remoting_me2me_host", "VNC Server", "vncserver", "x11vnc", "Jump Desktop Connect"}

func checkScreen(o Options) []Finding {
	out, err := o.RunCmd("ps", "-axo", "comm=")
	if err != nil {
		return nil
	}
	var hit []string
	for _, line := range strings.Split(out, "\n") {
		base := filepath.Base(strings.TrimSpace(line))
		for _, p := range screenProcs {
			if base == p {
				hit = append(hit, base)
			}
		}
	}
	hit = uniqueSorted(hit)
	if len(hit) == 0 {
		return nil
	}
	return []Finding{{ID: "screen.remote", Severity: Warn, Fingerprint: Fingerprint(hit...),
		Title:  i18n.T("有遠端桌面／螢幕分享程式在執行", "Remote-desktop or screen-sharing software is running"),
		Detail: strings.Join(hit, ", ") + "\n" + i18n.T("連進來的人看得到你畫面上的對話，遮罩也擋不住你自己螢幕上顯示的內容。", "Anyone connected sees the conversation on your screen; masking cannot hide what your own screen shows."),
		Fix:    i18n.T("處理機密時先關掉這些程式。", "Quit them while working with sensitive data."),
	}}
}

func checkNetwork(o Options) []Finding {
	var out []Finding
	for _, host := range o.Global.TLSHosts() {
		ips, err := o.Resolve(host)
		if err != nil || len(ips) == 0 {
			out = append(out, Finding{ID: "dns." + host, Severity: Warn,
				Title:  i18n.Tf("查不到 %s 的 IP（離線？）", "Could not resolve %s (offline?)", host),
				Detail: fmt.Sprint(err)})
			continue
		}
		var bad []string
		for _, ip := range ips {
			if !InAnthropicRange(ip) {
				bad = append(bad, ip.String())
			}
		}
		sort.Strings(bad)
		if len(bad) > 0 {
			out = append(out, Finding{ID: "dns." + host, Severity: Block, Fingerprint: Fingerprint(bad...),
				Title:  i18n.Tf("%s 被解析到非 Anthropic 的 IP", "%s resolves to addresses outside Anthropic's ranges", host),
				Detail: i18n.Tf("%s\nAnthropic 公布的範圍是 160.79.104.0/23 和 2607:6bc0::/48。可能是 /etc/hosts 被改、DNS 被劫持，或網路在做攔截。", "%s\nAnthropic publishes 160.79.104.0/23 and 2607:6bc0::/48. Possible causes: an edited /etc/hosts, hijacked DNS, or an intercepting network.", strings.Join(bad, ", ")),
				Fix:    i18n.Tf("檢查 /etc/hosts 和 DNS 設定；在別的網路試試看。確定沒問題才 claudeshield ack dns.%s", "Check /etc/hosts and your DNS settings; try another network. Only if you are sure: `claudeshield ack dns.%s`", host),
			})
		} else {
			out = append(out, Finding{ID: "dns." + host, Severity: Info, Title: i18n.Tf("%s 解析到 Anthropic 官方網段", "%s resolves inside Anthropic's ranges", host)})
		}
		out = append(out, checkTLS(o, host)...)
	}
	return out
}

// Roots returns claudeshield's pinned root pool plus any roots the user has
// learned with `claudeshield tls trust`.
func Roots(extraSPKI []string) (*x509.CertPool, map[string]bool, error) {
	pool := x509.NewCertPool()
	spki := map[string]bool{}
	entries, err := rootFS.ReadDir("roots")
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		b, err := rootFS.ReadFile("roots/" + e.Name())
		if err != nil {
			return nil, nil, err
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, nil, fmt.Errorf("bad PEM %s", e.Name())
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		pool.AddCert(c)
		spki[SPKIHash(c)] = true
	}
	for _, s := range extraSPKI {
		spki[strings.ToLower(s)] = true
	}
	return pool, spki, nil
}

// SPKIHash is the hex SHA-256 of a certificate's SubjectPublicKeyInfo.
func SPKIHash(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

// VerifyChain checks a served chain against the pinned roots. It ignores the
// system trust store on purpose: a root added to the keychain by an
// intercepting proxy must not make a forged chain look valid.
func VerifyChain(host string, chain []*x509.Certificate, extraSPKI []string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("server sent no certificates")
	}
	pool, spki, err := Roots(extraSPKI)
	if err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
		// A learned pin may name an intermediate or root the server sends.
		if spki[SPKIHash(c)] && len(extraSPKI) > 0 {
			pool.AddCert(c)
		}
	}
	_, err = chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: pool, Intermediates: inter, CurrentTime: now})
	return err
}

func checkTLS(o Options, host string) []Finding {
	chain, ip, err := o.TLSChain(host)
	if err != nil {
		return []Finding{{ID: "tls." + host, Severity: Warn, Title: i18n.Tf("無法和 %s 建立加密連線", "Could not open a TLS connection to %s", host), Detail: err.Error()}}
	}
	var out []Finding
	if ip != nil && !InAnthropicRange(ip) {
		out = append(out, Finding{ID: "tls.peer." + host, Severity: Block, Fingerprint: Fingerprint(ip.String()),
			Title:  i18n.Tf("連到 %s 的實際 IP 不在 Anthropic 網段", "The connection to %s landed outside Anthropic's ranges", host),
			Detail: ip.String(),
			Fix:    i18n.Tf("可能有透明代理在攔截。換個網路試試；確定沒問題才 claudeshield ack tls.peer.%s", "A transparent proxy may be intercepting. Try another network; only if sure: `claudeshield ack tls.peer.%s`", host),
		})
	}
	if err := VerifyChain(host, chain, o.Global.TLS.ExtraRoots, o.Now()); err != nil {
		var issuers []string
		for _, c := range chain {
			issuers = append(issuers, c.Subject.CommonName+" ← "+c.Issuer.CommonName)
		}
		out = append(out, Finding{ID: "tls." + host, Severity: Block, NoAck: true,
			Title:  i18n.Tf("%s 的憑證不是預期的那一串", "%s presented an unexpected certificate chain", host),
			Detail: strings.Join(issuers, "\n") + "\n" + err.Error() + "\n" + i18n.T("可能是有人在中間攔截加密連線；也可能是 Anthropic 換了憑證商。", "Either someone is intercepting TLS, or Anthropic changed certificate providers."),
			Fix:    i18n.Tf("先換一個網路（例如手機熱點）再跑 claudeshield check。換網路也一樣、而且確認是 Anthropic 換了憑證商，才執行 claudeshield tls trust %s", "Switch networks (e.g. a phone hotspot) and run `claudeshield check` again. Only if it persists and you have confirmed Anthropic changed CA: `claudeshield tls trust %s`", host),
		})
		return out
	}
	return append(out, Finding{ID: "tls." + host, Severity: Info, Title: i18n.Tf("%s 的憑證鏈通過釘選驗證（%s）", "%s certificate chain matches the pinned roots (%s)", host, chain[len(chain)-1].Issuer.CommonName)})
}

// AccountKind classifies how Claude Code authenticates.
type AccountKind string

const (
	AccountConsumer   AccountKind = "consumer"   // Free, Pro, Max
	AccountCommercial AccountKind = "commercial" // Team, Enterprise, API key, cloud providers
	AccountUnknown    AccountKind = "unknown"
)

// DetectAccount reads ~/.claude.json and the environment.
func DetectAccount(p config.Paths, env map[string]string) (AccountKind, string) {
	for _, k := range []string{"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "CLAUDE_CODE_USE_ANTHROPIC_AWS"} {
		if env[k] == "1" || env[k] == "true" {
			return AccountCommercial, k
		}
	}
	if env["ANTHROPIC_API_KEY"] != "" {
		return AccountCommercial, "ANTHROPIC_API_KEY"
	}
	b, err := os.ReadFile(p.ClaudeJSON)
	if err != nil {
		return AccountUnknown, ""
	}
	var cj struct {
		OAuth struct {
			OrganizationType string `json:"organizationType"`
			BillingType      string `json:"billingType"`
		} `json:"oauthAccount"`
		PrimaryAPIKey string `json:"primaryApiKey"`
	}
	if json.Unmarshal(b, &cj) != nil {
		return AccountUnknown, ""
	}
	if cj.PrimaryAPIKey != "" {
		return AccountCommercial, "console API key"
	}
	t := strings.ToLower(cj.OAuth.OrganizationType)
	switch {
	case strings.Contains(t, "max") || strings.Contains(t, "pro") || strings.Contains(t, "free") || t == "claude_individual":
		return AccountConsumer, cj.OAuth.OrganizationType
	case strings.Contains(t, "team") || strings.Contains(t, "enterprise") || strings.Contains(t, "api"):
		return AccountCommercial, cj.OAuth.OrganizationType
	}
	return AccountUnknown, cj.OAuth.OrganizationType
}

func checkAccount(o Options, inWS bool) []Finding {
	env := envMap(o.Environ)
	kind, detail := DetectAccount(o.Paths, env)
	switch kind {
	case AccountCommercial:
		return []Finding{{ID: "account", Severity: Info, Title: i18n.Tf("使用商業條款帳號（%s）：Anthropic 不會拿資料訓練", "Commercial terms (%s): Anthropic does not train on this data", detail)}}
	case AccountConsumer:
		confirmed := o.Global.Account.TrainingOffConfirmedAt
		fresh := !confirmed.IsZero() && o.Now().Sub(confirmed) < 30*24*time.Hour
		if !inWS {
			if fresh {
				return []Finding{{ID: "account", Severity: Info, Title: i18n.Tf("個人帳號（%s），你在 %s 確認過訓練開關已關閉", "Consumer account (%s); you confirmed training is off on %s", detail, confirmed.Format("2006-01-02"))}}
			}
			return []Finding{{ID: "account", Severity: Info, Title: i18n.Tf("個人帳號（%s），適用消費者條款", "Consumer account (%s) under consumer terms", detail)}}
		}
		if fresh {
			return []Finding{{ID: "account", Severity: Info, Title: i18n.Tf("個人帳號（%s），%s 已確認訓練開關關閉", "Consumer account (%s); training switch confirmed off on %s", detail, confirmed.Format("2006-01-02"))}}
		}
		return []Finding{{ID: "account.training", Severity: Block, NoAck: true,
			Title: i18n.T("敏感資料夾要先確認「幫助改善 Claude」已關閉", "Confirm \"Help improve Claude\" is off before using a sensitive workspace"),
			Detail: i18n.Tf("你用的是個人帳號（%s）。這個開關開著時，對話可能被拿去訓練並保存 5 年；關掉是保存 30 天。開關存在網站上，ClaudeShield 在本機讀不到，所以要你自己確認（每 30 天確認一次）。",
				"This is a consumer account (%s). With that switch on, conversations may be used for training and kept 5 years; off, 30 days. The switch lives on the website and cannot be read locally, so you confirm it yourself (every 30 days).", detail),
			Fix: i18n.T("1. 打開 https://claude.ai/settings/data-privacy-controls\n2. 把「幫助改善 Claude」關掉\n3. 回終端機執行 claudeshield account confirm",
				"1. Open https://claude.ai/settings/data-privacy-controls\n2. Turn \"Help improve Claude\" off\n3. Run `claudeshield account confirm`"),
		}}
	}
	return []Finding{{ID: "account", Severity: Info, Title: i18n.T("無法判斷帳號類型", "Account type could not be determined")}}
}

// VaultDirs are the parts of ~/.claude that hold conversation data.
var VaultDirs = []string{"projects", "file-history", "plans", "paste-cache", "image-cache", "uploads", "session-env", "tasks", "shell-snapshots", "debug", "feedback-bundles", "usage-data"}

// VaultFiles are single files under ~/.claude that hold conversation data.
var VaultFiles = []string{"history.jsonl"}

func checkVault(o Options, inWS bool) []Finding {
	if !vault.Configured(o.Global) {
		f := Finding{ID: "vault.none", Severity: Warn, Fingerprint: "none",
			Title:  i18n.T("對話紀錄沒有加密（還沒建立保險箱）", "Transcripts are not encrypted (no vault yet)"),
			Detail: i18n.Tf("%s 裡的對話紀錄、檔案修改前的備份都是明文。", "Transcripts and pre-edit file snapshots under %s are plaintext.", tilde(o.Paths.ClaudeDir, o.Paths.Home)),
			Fix:    i18n.T("claudeshield vault create，然後關掉所有 Claude 視窗執行 claudeshield vault migrate", "`claudeshield vault create`, then close every Claude window and run `claudeshield vault migrate`"),
		}
		if inWS {
			f.Severity = Block
			f.Detail += "\n" + i18n.T("敏感資料夾裡，Claude 改過的檔案原文會留在 file-history 備份，所以要先有保險箱。", "In a sensitive workspace, file-history keeps the real contents of files Claude edits, so a vault is required.")
			f.Fix += "\n" + i18n.T("暫時不想建立的話：claudeshield ack vault.none", "To proceed without one for now: `claudeshield ack vault.none`")
		}
		return []Finding{f}
	}
	if !vault.Mounted(o.Paths, o.Global) {
		return []Finding{{ID: "vault.closed", Severity: Block, NoAck: true,
			Title:  i18n.T("加密保險箱沒有打開", "The encrypted vault is closed"),
			Detail: i18n.Tf("保險箱：%s", "Vault: %s", o.Global.Vault.Image),
			Fix:    "claudeshield vault open",
		}}
	}
	mp := vault.MountPoint(o.Paths, o.Global)
	if ok, img, err := vault.BackedBy(o.Paths, o.Global); err == nil && !ok {
		return []Finding{{ID: "vault.spoofed", Severity: Block, NoAck: true,
			Title:  i18n.Tf("%s 掛載的不是你的保險箱", "The volume at %s is not your vault", mp),
			Detail: i18n.Tf("實際來源：%s\n預期：%s\n有別的磁碟映像佔用了保險箱的位置，寫進去的對話紀錄不會受到保護。", "Backed by: %s\nExpected: %s\nAnother disk image occupies the vault's mount point; transcripts written there are not protected.", img, o.Global.Vault.Image),
			Fix:    i18n.Tf("hdiutil detach %q，然後 claudeshield vault open", "hdiutil detach %q, then `claudeshield vault open`", mp),
		}}
	}
	var plain []string
	for _, d := range append(append([]string(nil), VaultDirs...), VaultFiles...) {
		p := filepath.Join(o.Paths.ClaudeDir, d)
		fi, err := os.Lstat(p)
		if err != nil {
			continue // not created yet; migrate makes the link when it exists
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if t, err := os.Readlink(p); err == nil && strings.HasPrefix(t, mp+"/") {
				continue
			}
		}
		plain = append(plain, d)
	}
	if len(plain) > 0 {
		f := Finding{ID: "vault.unmigrated", Severity: Warn, Fingerprint: Fingerprint(plain...),
			Title:  i18n.T("保險箱打開了，但還有對話資料在保險箱外面", "The vault is open but some conversation data is still outside it"),
			Detail: strings.Join(plain, ", "),
			Fix:    i18n.T("關掉所有 Claude 視窗後執行 claudeshield vault migrate", "Close every Claude window and run `claudeshield vault migrate`"),
		}
		if inWS {
			f.Severity = Block
			f.Fix += "\n" + i18n.T("或暫時接受：claudeshield ack vault.unmigrated", "Or accept for now: `claudeshield ack vault.unmigrated`")
		}
		return []Finding{f}
	}
	return []Finding{{ID: "vault", Severity: Info, Title: i18n.T("對話資料都在加密保險箱裡", "Conversation data is inside the encrypted vault")}}
}

func uniqueSorted(s []string) []string {
	sort.Strings(s)
	var out []string
	for i, x := range s {
		if i == 0 || x != s[i-1] {
			out = append(out, x)
		}
	}
	return out
}
