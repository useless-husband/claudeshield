// Package egress decides whether a shell command or URL can send data off
// the machine, and where to.
//
// The distinction that matters is direction. Downloading a page is inbound;
// a POST body, an upload, an SSH session, a DNS lookup of a made-up hostname
// or a URL built from command output is outbound. Claude Code's sandbox (when
// enabled) enforces a host allowlist at the OS level; this package exists to
// explain to a person, before anything runs, what a command would send where,
// and to catch the case the sandbox cannot see: a placeholder about to be
// expanded back into a real value inside a network command.
package egress

import (
	"math"
	"net"
	"net/url"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Result describes one command.
type Result struct {
	Network     bool     // something in the command talks to the network
	DataOut     bool     // and it sends data out, not just fetches
	Publish     bool     // it publishes (git push, gh create, npm publish, ...)
	UnknownHost bool     // at least one destination could not be determined
	Obfuscated  bool     // eval / decode-and-run / ANSI-C escapes around it
	Hosts       []string // destinations, lower-cased, sorted
	Reasons     []string // short machine-readable reasons, for logs and messages
}

func (r *Result) host(h string) {
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if h == "" {
		return
	}
	if strings.Contains(h, subst) {
		r.UnknownHost = true
		r.DataOut = true
		r.reason("dynamic-host")
		return
	}
	for _, x := range r.Hosts {
		if x == h {
			return
		}
	}
	r.Hosts = append(r.Hosts, h)
}

func (r *Result) reason(s string) {
	for _, x := range r.Reasons {
		if x == s {
			return
		}
	}
	r.Reasons = append(r.Reasons, s)
}

func (r *Result) merge(o Result) {
	r.Network = r.Network || o.Network
	r.DataOut = r.DataOut || o.DataOut
	r.Publish = r.Publish || o.Publish
	r.UnknownHost = r.UnknownHost || o.UnknownHost
	r.Obfuscated = r.Obfuscated || o.Obfuscated
	for _, h := range o.Hosts {
		r.host(h)
	}
	for _, s := range o.Reasons {
		r.reason(s)
	}
}

// Options tune the analysis.
type Options struct {
	// Dir is the working directory, used to resolve a git remote's URL.
	Dir string
	// GitRemoteURL overrides how remote names are resolved (tests).
	GitRemoteURL func(dir, remote string) (string, bool)
}

// AnalyzeShell inspects a shell command line.
func AnalyzeShell(cmd string, o Options) Result {
	return analyze(cmd, o, 0)
}

func analyze(cmd string, o Options, depth int) Result {
	var r Result
	if depth > 6 {
		r.Network, r.UnknownHost, r.Obfuscated = true, true, true
		r.reason("nesting-too-deep")
		return r
	}
	lx := lex(cmd)
	if lx.ansiC {
		r.Obfuscated = true
		r.reason("ansi-c-escapes")
	}
	if m := devTCP.FindAllStringSubmatch(cmd, -1); m != nil {
		r.Network, r.DataOut = true, true
		r.reason("dev-tcp")
		for _, x := range m {
			r.host(x[2])
		}
	}
	for _, n := range lx.nested {
		r.merge(analyze(n, o, depth+1))
	}
	decoderUpstream := false
	fetchUpstream := false
	for _, c := range lx.cmds {
		words := unwrap(c.words)
		if len(words) == 0 {
			if c.heredoc != "" {
				r.merge(analyze(c.heredoc, o, depth+1))
			}
			continue
		}
		prog := path.Base(words[0])
		args := words[1:]
		if c.piped && isShellOrInterp(prog) && len(nonFlags(args)) == 0 {
			if decoderUpstream {
				r.Obfuscated = true
				r.reason("decode-and-run")
			}
			if fetchUpstream {
				r.Obfuscated = true
				r.reason("download-and-run")
			}
		}
		decoderUpstream = c.pipeTo && isDecoder(prog, args)
		fetchUpstream = c.pipeTo && (prog == "curl" || prog == "wget")
		r.merge(analyzeOne(prog, args, c, o, depth))
	}
	sort.Strings(r.Hosts)
	return r
}

var devTCP = regexp.MustCompile(`/dev/(tcp|udp)/([^/\s"']+)/`)

// unwrap strips assignments and wrapper commands (sudo, env, nohup, xargs…)
// so the real program is first.
func unwrap(w []string) []string {
	for len(w) > 0 {
		first := w[0]
		if isAssignment(first) {
			w = w[1:]
			continue
		}
		switch path.Base(first) {
		case "!", "then", "do", "else", "elif", "if", "while", "until", "time", "command", "exec", "nohup", "builtin", "noglob", "caffeinate", "{", "}":
			w = w[1:]
		case "sudo", "doas":
			w = skipFlags(w[1:], map[string]bool{"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-U": true})
		case "env":
			w = w[1:]
			for len(w) > 0 && (isAssignment(w[0]) || strings.HasPrefix(w[0], "-")) {
				if w[0] == "-u" || w[0] == "-C" || w[0] == "-S" {
					w = w[1:]
				}
				if len(w) > 0 {
					w = w[1:]
				}
			}
		case "nice":
			w = skipFlags(w[1:], map[string]bool{"-n": true})
		case "timeout", "gtimeout":
			w = skipFlags(w[1:], map[string]bool{"-s": true, "-k": true, "--signal": true, "--kill-after": true})
			if len(w) > 0 {
				w = w[1:] // duration
			}
		case "stdbuf":
			w = skipFlags(w[1:], nil)
		case "xargs":
			w = skipFlags(w[1:], map[string]bool{"-I": true, "-n": true, "-P": true, "-L": true, "-s": true, "-d": true, "-E": true, "-J": true, "-R": true, "-S": true})
		case "watch":
			w = skipFlags(w[1:], map[string]bool{"-n": true, "-d": false})
		default:
			return w
		}
	}
	return w
}

func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := s[i]
		if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// skipFlags drops leading options; names in takesValue consume the next word.
func skipFlags(w []string, takesValue map[string]bool) []string {
	for len(w) > 0 && strings.HasPrefix(w[0], "-") {
		if w[0] == "--" {
			return w[1:]
		}
		if takesValue[w[0]] && len(w) > 1 {
			w = w[2:]
			continue
		}
		w = w[1:]
	}
	return w
}

func nonFlags(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

func isShellOrInterp(p string) bool {
	switch p {
	case "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "node", "perl", "ruby", "php", "osascript":
		return true
	}
	return false
}

func isDecoder(prog string, args []string) bool {
	switch prog {
	case "base64", "gbase64":
		for _, a := range args {
			if a == "-d" || a == "-D" || a == "--decode" {
				return true
			}
		}
	case "xxd":
		for _, a := range args {
			if a == "-r" || a == "-p" {
				return true
			}
		}
	case "openssl":
		return len(args) > 0 && (args[0] == "enc" || args[0] == "base64")
	case "printf", "echo":
		for _, a := range args {
			if strings.Contains(a, `\x`) {
				return true
			}
		}
	case "rev", "tr", "gunzip", "zcat", "uudecode":
		return true
	}
	return false
}

// curl options that take a value; the value is not a URL unless noted.
var curlValueOpts = map[string]bool{
	"-H": true, "--header": true, "-o": true, "--output": true, "-X": true, "--request": true,
	"-u": true, "--user": true, "-A": true, "--user-agent": true, "-e": true, "--referer": true,
	"-w": true, "--write-out": true, "-m": true, "--max-time": true, "--connect-timeout": true,
	"-b": true, "--cookie": true, "-c": true, "--cookie-jar": true, "-K": true, "--config": true,
	"--cacert": true, "--cert": true, "--key": true, "-r": true, "--range": true, "--retry": true,
	"-z": true, "--time-cond": true, "--resolve": true, "--connect-to": true, "-D": true, "--dump-header": true,
	"--limit-rate": true, "-Y": true, "-y": true, "--interface": true, "--dns-servers": true,
}
var curlDataOpts = map[string]bool{
	"-d": true, "--data": true, "--data-raw": true, "--data-binary": true, "--data-ascii": true,
	"--data-urlencode": true, "-F": true, "--form": true, "--form-string": true, "-T": true,
	"--upload-file": true, "--json": true,
}

func analyzeOne(prog string, args []string, c simpleCmd, o Options, depth int) Result {
	var r Result
	switch prog {
	case "sh", "bash", "zsh", "dash", "ksh", "fish":
		for i, a := range args {
			if a == "-c" && i+1 < len(args) {
				r.merge(analyze(args[i+1], o, depth+1))
				if strings.Contains(args[i+1], subst) {
					r.Obfuscated = true
					r.reason("shell-c-dynamic")
				}
				break
			}
		}
		if c.heredoc != "" {
			r.merge(analyze(c.heredoc, o, depth+1))
		}
	case "eval":
		joined := strings.Join(args, " ")
		r.merge(analyze(joined, o, depth+1))
		if strings.Contains(joined, subst) {
			r.Obfuscated = true
			r.reason("eval-dynamic")
		}
	case "curl":
		r.Network = true
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case curlDataOpts[a]:
				r.DataOut = true
				r.reason("curl-data")
				i++
			case strings.HasPrefix(a, "--data") || strings.HasPrefix(a, "--form") || strings.HasPrefix(a, "--upload-file") || strings.HasPrefix(a, "--json"):
				r.DataOut = true
				r.reason("curl-data")
			case len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.IndexByte("dFT", a[1]) >= 0:
				r.DataOut = true // -d@file, -Ffoo=bar
				r.reason("curl-data")
			case a == "-X" || a == "--request":
				if i+1 < len(args) && strings.ToUpper(args[i+1]) != "GET" && strings.ToUpper(args[i+1]) != "HEAD" {
					r.DataOut = true
					r.reason("curl-method")
				}
				i++
			case a == "-x" || a == "--proxy" || a == "--url" || a == "--preproxy":
				if i+1 < len(args) {
					r.urlArg(args[i+1], true)
				}
				i++
			case curlValueOpts[a]:
				i++
			case strings.HasPrefix(a, "-"):
			default:
				r.urlArg(a, true)
			}
		}
		if len(r.Hosts) == 0 && !r.UnknownHost {
			r.UnknownHost = true
			r.reason("curl-no-url")
		}
	case "wget":
		r.Network = true
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case strings.HasPrefix(a, "--post-data") || strings.HasPrefix(a, "--post-file") || strings.HasPrefix(a, "--body-data") || strings.HasPrefix(a, "--body-file"):
				r.DataOut = true
				r.reason("wget-data")
				if !strings.Contains(a, "=") {
					i++
				}
			case strings.HasPrefix(a, "--method"):
				m := strings.TrimPrefix(strings.TrimPrefix(a, "--method"), "=")
				if m == "" && i+1 < len(args) {
					m = args[i+1]
					i++
				}
				if up := strings.ToUpper(m); up != "GET" && up != "HEAD" {
					r.DataOut = true
					r.reason("wget-method")
				}
			case a == "-O" || a == "-o" || a == "-P" || a == "-U" || a == "--header" || a == "-e" || a == "-t" || a == "-T":
				i++
			case strings.HasPrefix(a, "-"):
			default:
				r.urlArg(a, true)
			}
		}
		if len(r.Hosts) == 0 && !r.UnknownHost {
			r.UnknownHost = true
		}
	case "http", "https", "xh", "xhs", "httpie":
		r.Network = true
		urlSeen := false
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			up := strings.ToUpper(a)
			if !urlSeen && (up == "POST" || up == "PUT" || up == "PATCH" || up == "DELETE") {
				r.DataOut = true
				r.reason("http-method")
				continue
			}
			if !urlSeen {
				r.urlArg(a, true)
				urlSeen = true
				continue
			}
			if strings.ContainsAny(a, "=:@") {
				r.DataOut = true
				r.reason("http-fields")
			}
		}
	case "nc", "ncat", "netcat", "telnet", "socat", "ftp", "tftp", "lftp", "sftp", "ssh", "mosh", "scp", "rsync":
		r.Network, r.DataOut = true, true
		r.reason(prog)
		found := false
		for _, a := range sshLikeHosts(prog, args) {
			r.host(a)
			found = true
		}
		if !found {
			if prog == "rsync" {
				// rsync between two local paths is not network at all.
				return Result{}
			}
			r.UnknownHost = true
		}
	case "mail", "mailx", "sendmail", "mutt", "msmtp", "swaks":
		r.Network, r.DataOut, r.UnknownHost = true, true, true
		r.reason("mail")
	case "dig", "nslookup", "host", "drill", "ping", "ping6", "traceroute", "traceroute6", "whois", "mtr":
		r.Network = true
		for _, a := range nonFlags(args) {
			if strings.HasPrefix(a, "@") || a == "any" || a == "A" || a == "AAAA" || a == "TXT" || a == "MX" || a == "NS" || isDigits(a) {
				continue
			}
			r.host(a)
			for _, label := range strings.Split(a, ".") {
				if len(label) >= 25 || strings.Contains(label, subst) {
					r.DataOut = true
					r.reason("dns-long-label")
				}
			}
		}
	case "git":
		r.merge(gitResult(args, o))
	case "gh":
		r.Network = true
		r.host("github.com")
		if !ghReadOnly(args) {
			r.DataOut, r.Publish = true, true
			r.reason("gh-write")
		}
	case "npm", "pnpm", "yarn", "bun", "npx", "bunx":
		r.merge(pkgResult(args, []string{"registry.npmjs.org"}, "publish"))
	case "pip", "pip3", "uv", "poetry", "pipx":
		r.merge(pkgResult(args, []string{"pypi.org", "files.pythonhosted.org"}, "publish"))
	case "twine":
		r.Network, r.DataOut, r.Publish = true, true, true
		r.host("upload.pypi.org")
	case "cargo":
		r.merge(pkgResult(args, []string{"crates.io", "index.crates.io", "static.crates.io"}, "publish"))
	case "go":
		if len(args) > 0 && (args[0] == "get" || args[0] == "install" || (args[0] == "mod" && len(args) > 1 && args[1] == "download")) {
			r.Network = true
			r.host("proxy.golang.org")
			r.host("sum.golang.org")
		}
	case "brew":
		if len(args) > 0 && (args[0] == "install" || args[0] == "upgrade" || args[0] == "update" || args[0] == "fetch" || args[0] == "reinstall") {
			r.Network = true
			r.host("formulae.brew.sh")
			r.host("ghcr.io")
		}
	case "docker", "podman":
		if len(args) > 0 && (args[0] == "push" || args[0] == "login") {
			r.Network, r.DataOut, r.Publish, r.UnknownHost = true, true, true, true
			r.reason("docker-push")
		} else if len(args) > 0 && args[0] == "pull" {
			r.Network, r.UnknownHost = true, true
		}
	case "aws", "gcloud", "gsutil", "az", "rclone", "s3cmd", "azcopy":
		r.Network, r.UnknownHost = true, true
		for _, a := range args {
			switch a {
			case "cp", "sync", "mv", "put", "upload", "copy", "copyto", "moveto", "rsync":
				r.DataOut = true
				r.reason("cloud-copy")
			}
		}
	case "open":
		for _, a := range nonFlags(args) {
			if strings.Contains(a, "://") {
				r.Network = true
				r.urlArg(a, false)
			}
		}
	case "osascript":
		script := strings.Join(args, " ") + c.heredoc
		if strings.Contains(script, "do shell script") || netCode.MatchString(script) {
			r.Network, r.UnknownHost, r.Obfuscated = true, true, true
			r.reason("osascript-shell")
		}
	case "python", "python3", "python2", "node", "deno", "ruby", "perl", "php", "pwsh", "lua", "Rscript", "julia", "swift":
		code := inlineCode(prog, args) + c.heredoc
		if code != "" && netCode.MatchString(code) {
			r.Network, r.DataOut = true, true
			r.reason("interpreter-network")
			urls := urlLiteral.FindAllString(code, -1)
			for _, u := range urls {
				r.urlArg(u, false)
			}
			if len(urls) == 0 {
				r.UnknownHost = true
			}
		}
	}
	return r
}

// urlArg records the host of a URL-ish argument and flags dynamic or
// data-shaped URLs as outbound.
func (r *Result) urlArg(a string, bareHostOK bool) {
	if a == "" {
		return
	}
	raw := a
	if !strings.Contains(a, "://") {
		if !bareHostOK || !looksLikeHost(strings.SplitN(strings.SplitN(a, "/", 2)[0], ":", 2)[0]) {
			return
		}
		raw = "http://" + a
	}
	if strings.Contains(raw, subst) {
		r.DataOut = true
		r.reason("dynamic-url")
		// The host part may still be static; try to keep it.
		hostPart := strings.SplitN(strings.SplitN(raw, "://", 2)[1], "/", 2)[0]
		if !strings.Contains(hostPart, subst) {
			r.host(stripPort(stripUserinfo(hostPart)))
		} else {
			r.UnknownHost = true
		}
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return
	}
	r.host(u.Hostname())
	if DataShapedURL(u) {
		r.DataOut = true
		r.reason("data-shaped-url")
	}
}

// DataShapedURL flags URLs whose path or query carries something that looks
// like encoded data rather than an address: a long, high-entropy segment.
func DataShapedURL(u *url.URL) bool {
	segs := strings.Split(u.EscapedPath(), "/")
	for _, kv := range strings.Split(u.RawQuery, "&") {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			segs = append(segs, kv[i+1:])
		} else {
			segs = append(segs, kv)
		}
	}
	for _, s := range segs {
		if len(s) >= 40 && entropy(s) >= 4.0 {
			return true
		}
	}
	// Subdomain labels can carry data too (DNS exfiltration).
	for _, label := range strings.Split(u.Hostname(), ".") {
		if len(label) >= 30 && entropy(label) >= 3.5 {
			return true
		}
	}
	return false
}

func entropy(s string) float64 {
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

var hostRE = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

func looksLikeHost(s string) bool {
	if s == "localhost" || net.ParseIP(strings.Trim(s, "[]")) != nil {
		return true
	}
	if !hostRE.MatchString(s) {
		return false
	}
	// "file.txt", "main.go": a dotted word whose last label is a common file
	// extension is a filename, not a host.
	switch strings.ToLower(s[strings.LastIndexByte(s, '.')+1:]) {
	case "txt", "md", "json", "go", "py", "js", "ts", "sh", "csv", "html", "htm", "xml", "yaml", "yml", "toml", "log", "out", "tar", "gz", "zip", "png", "jpg", "pdf", "rs", "c", "h", "rb", "java", "swift", "lock", "mod", "sum", "env", "cfg", "conf", "ini", "bak", "tmp", "pem", "key", "crt":
		return false
	}
	return true
}

func stripPort(h string) string {
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i > 0 && strings.Count(h, ":") == 1 {
		return h[:i]
	}
	return h
}

func stripUserinfo(h string) string {
	if i := strings.LastIndexByte(h, '@'); i >= 0 {
		return h[i+1:]
	}
	return h
}

// sshLikeHosts finds destinations in ssh/scp/rsync/nc-style arguments.
func sshLikeHosts(prog string, args []string) []string {
	var hosts []string
	valueOpts := map[string]bool{"-p": true, "-P": true, "-i": true, "-l": true, "-o": true, "-F": true, "-J": true, "-L": true, "-R": true, "-D": true, "-e": true, "-b": true, "-c": true, "-m": true, "-w": true, "-s": true, "-q": true, "-W": true, "-B": true, "-E": true, "-O": true, "-S": true}
	positional := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if valueOpts[a] && i+1 < len(args) {
				if a == "-J" { // ProxyJump host
					hosts = append(hosts, stripPort(stripUserinfo(args[i+1])))
				}
				i++
			}
			continue
		}
		switch prog {
		case "scp", "rsync", "sftp":
			if strings.Contains(a, "://") {
				if u, err := url.Parse(a); err == nil && u.Hostname() != "" {
					hosts = append(hosts, u.Hostname())
				}
				continue
			}
			if j := strings.IndexByte(a, ':'); j > 0 && !strings.Contains(a[:j], "/") {
				hosts = append(hosts, stripUserinfo(a[:j]))
			} else if prog == "sftp" && positional == 0 {
				hosts = append(hosts, stripUserinfo(a))
			}
		case "socat":
			// socat ADDRESS ADDRESS, e.g. TCP:host:port or OPENSSL:host:port
			parts := strings.Split(a, ":")
			if len(parts) >= 3 {
				switch strings.ToUpper(parts[0]) {
				case "TCP", "TCP4", "TCP6", "UDP", "UDP4", "UDP6", "OPENSSL", "SSL", "SOCKS4", "SOCKS4A", "PROXY":
					hosts = append(hosts, parts[1])
				}
			}
		default: // ssh, mosh, nc, telnet, ftp: first positional is the host
			if positional == 0 {
				h := a
				if strings.Contains(h, "://") {
					if u, err := url.Parse(h); err == nil {
						h = u.Hostname()
					}
				}
				hosts = append(hosts, stripPort(stripUserinfo(h)))
			}
		}
		positional++
	}
	return hosts
}

func gitResult(args []string, o Options) Result {
	var r Result
	args = skipFlags(args, map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true})
	if len(args) == 0 {
		return r
	}
	sub := args[0]
	rest := args[1:]
	switch sub {
	case "push", "send-email", "request-pull":
		r.Network, r.DataOut, r.Publish = true, true, true
		r.reason("git-push")
	case "clone", "fetch", "pull", "ls-remote", "archive":
		r.Network = true
	case "submodule":
		if len(rest) > 0 && (rest[0] == "update" || rest[0] == "add" || rest[0] == "sync") {
			r.Network = true
		}
		return r
	case "remote":
		if len(rest) > 0 && (rest[0] == "update" || rest[0] == "show" || rest[0] == "prune") {
			r.Network, r.UnknownHost = true, true
		}
		return r
	default:
		return r
	}
	pos := nonFlags(rest)
	gotURL := false
	for _, a := range pos {
		if h := gitURLHost(a); h != "" {
			r.host(h)
			gotURL = true
		}
	}
	if !gotURL {
		remote := "origin"
		if sub != "clone" && len(pos) > 0 {
			remote = pos[0]
		}
		resolve := o.GitRemoteURL
		if resolve == nil {
			resolve = gitRemoteURL
		}
		if u, ok := resolve(o.Dir, remote); ok && gitURLHost(u) != "" {
			r.host(gitURLHost(u))
		} else {
			r.UnknownHost = true
			r.reason("git-remote-unknown")
		}
	}
	return r
}

func gitRemoteURL(dir, remote string) (string, bool) {
	if strings.ContainsAny(remote, "\x00") || strings.HasPrefix(remote, "-") {
		return "", false
	}
	cmd := exec.Command("git", "remote", "get-url", "--push", "--", remote)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// gitURLHost extracts the host from https://, ssh:// and scp-like git URLs.
func gitURLHost(s string) string {
	if strings.Contains(s, "://") {
		if strings.HasPrefix(s, "file://") {
			return ""
		}
		if u, err := url.Parse(s); err == nil {
			return u.Hostname()
		}
		return ""
	}
	// user@host:path (scp-like); a colon before any slash.
	if i := strings.IndexByte(s, ':'); i > 0 && !strings.Contains(s[:i], "/") {
		h := stripUserinfo(s[:i])
		if looksLikeHost(h) || strings.Contains(s[:i], "@") {
			return h
		}
	}
	return ""
}

func ghReadOnly(args []string) bool {
	if len(args) == 0 {
		return true
	}
	if args[0] == "api" {
		for i, a := range args {
			if a == "-f" || a == "-F" || a == "--field" || a == "--raw-field" || a == "--input" || strings.HasPrefix(a, "--input=") {
				return false
			}
			if (a == "-X" || a == "--method") && i+1 < len(args) && strings.ToUpper(args[i+1]) != "GET" {
				return false
			}
			if strings.HasPrefix(a, "--method=") && strings.ToUpper(strings.TrimPrefix(a, "--method=")) != "GET" {
				return false
			}
		}
		return true
	}
	if args[0] == "auth" || args[0] == "status" || args[0] == "browse" || args[0] == "search" || args[0] == "help" || args[0] == "--version" || args[0] == "version" {
		return true
	}
	if len(args) >= 2 {
		switch args[1] {
		case "list", "view", "status", "diff", "checks", "watch", "download", "clone", "checkout", "ls":
			return true
		}
	}
	return false
}

func pkgResult(args []string, hosts []string, publishWord string) Result {
	var r Result
	if len(args) == 0 {
		return r
	}
	switch args[0] {
	case publishWord, "upload", "unpublish", "deprecate", "owner", "yank":
		r.Network, r.DataOut, r.Publish = true, true, true
		r.reason("package-publish")
	case "install", "i", "add", "ci", "update", "upgrade", "download", "fetch", "sync", "lock", "x", "exec", "dlx", "create", "init", "outdated", "audit", "info", "view", "search", "run", "tool":
		r.Network = true
	default:
		return r
	}
	for _, h := range hosts {
		r.host(h)
	}
	return r
}

func inlineCode(prog string, args []string) string {
	for i, a := range args {
		switch {
		case (a == "-c" && (strings.HasPrefix(prog, "python") || prog == "pwsh")) ||
			((a == "-e" || a == "--eval" || a == "-p" || a == "--print") && (prog == "node" || prog == "ruby" || prog == "perl" || prog == "deno" || prog == "lua")) ||
			(a == "-r" && prog == "php") || (a == "eval" && prog == "deno"):
			if i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return "" // script files and stdin ("python3 - <<EOF") are covered by the heredoc body
}

var netCode = regexp.MustCompile(`(?i)\b(?:urllib|requests\.|http\.client|httpx|aiohttp|socket\.|smtplib|ftplib|paramiko|fetch\s*\(|XMLHttpRequest|axios|https?\.request|https?\.get|net\.connect|net\.Socket|dgram|LWP::|HTTP::Tiny|Net::HTTP|open-uri|Faraday|curl_init|file_get_contents\s*\(\s*['"]https?|Invoke-WebRequest|Invoke-RestMethod|URLSession|do shell script)`)

var urlLiteral = regexp.MustCompile(`https?://[^\s'"<>()\\]+`)

// HostAllowed reports whether host matches an allowlist entry. Entries are
// exact hostnames, or "*.example.com" for any subdomain of example.com.
// Loopback is always allowed.
func HostAllowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "localhost" || host == "::1" || strings.HasPrefix(host, "127.") {
		return true
	}
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		switch {
		case a == "":
		case a == "*":
			return true
		case strings.HasPrefix(a, "*."):
			if strings.HasSuffix(host, a[1:]) {
				return true
			}
		case a == host:
			return true
		}
	}
	return false
}

// AllHostsAllowed reports whether every destination is known and allowed.
func (r Result) AllHostsAllowed(allow []string) bool {
	if r.UnknownHost {
		return false
	}
	for _, h := range r.Hosts {
		if !HostAllowed(h, allow) {
			return false
		}
	}
	return true
}

// DisallowedHosts lists the destinations not on the allowlist.
func (r Result) DisallowedHosts(allow []string) []string {
	var out []string
	for _, h := range r.Hosts {
		if !HostAllowed(h, allow) {
			out = append(out, h)
		}
	}
	return out
}

// DefaultAllowHosts are package registries and code hosts that ordinary
// development needs. They are destinations for downloads; publishing to them
// is still reported separately (Result.Publish).
var DefaultAllowHosts = []string{
	"github.com", "api.github.com", "codeload.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
	"registry.npmjs.org", "pypi.org", "files.pythonhosted.org", "proxy.golang.org", "sum.golang.org",
	"crates.io", "index.crates.io", "static.crates.io", "formulae.brew.sh", "ghcr.io", "rubygems.org",
	"docs.claude.com", "code.claude.com", "platform.claude.com", "docs.anthropic.com", "api.anthropic.com",
}
