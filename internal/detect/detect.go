// Package detect finds sensitive values in text: credentials, personal data,
// money amounts and organisation names, with Taiwan-specific formats
// (national ID with checksum, UBN, mobile numbers, street addresses) next to
// the usual international ones.
//
// Detection is a mix of regular expressions, checksum validators and a
// literal term list supplied by the user. The literal list is the precise
// tool: names and code words cannot be recognised by pattern alone, so the
// regexes are a safety net, not a guarantee.
package detect

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Category groups kinds so a workspace can switch whole families on or off.
type Category string

const (
	Secret  Category = "secret"  // credentials, keys, internal hosts
	PII     Category = "pii"     // people: IDs, phones, e-mail, addresses, names
	Finance Category = "finance" // amounts, bank accounts
	Doc     Category = "doc"     // organisations, UBN, user terms
)

// AllCategories lists every category in display order.
var AllCategories = []Category{Secret, PII, Finance, Doc}

// Profile selects how aggressive detection is.
type Profile int

const (
	// Basic finds only high-confidence credentials. It is meant to run in every
	// session, where false positives would get in the way of ordinary work.
	Basic Profile = iota
	// Strict runs every rule of every enabled category. It is meant for
	// workspaces the user has marked as sensitive.
	Strict
)

// Match is one sensitive value found in a text. Start and End are byte offsets.
type Match struct {
	Start, End int
	Kind       string
	Category   Category
	Value      string
}

// Config controls a Detector.
type Config struct {
	Profile Profile
	// Categories enabled under Strict. Nil means all.
	Categories map[Category]bool
	// Terms are literal values to always mask, grouped by token kind
	// (for example "CLIENT": {"王小明", "Acme"}). Kinds are upper-cased and
	// stripped to [A-Z0-9]; terms are always active, under any profile.
	Terms map[string][]string
	// InternalDomains are extra domain suffixes treated as internal hosts.
	InternalDomains []string
	// Allow lists values that are never reported: exact strings, "*@domain"
	// for e-mail domains, or ".domain" suffixes for hosts and e-mail.
	Allow []string
}

type rule struct {
	kind  string
	cat   Category
	re    *regexp.Regexp
	group int               // submatch holding the value; 0 = whole match
	valid func(string) bool // optional extra check on the value
	basic bool              // part of the Basic profile
	prio  int               // tie-breaker when two rules claim the same span
	// need lists lower-cased literals of which at least one must occur in a
	// line before the regex runs on it; digits is a minimum run of ASCII
	// digits. Both are cheap prefilters: regexp matching dominates the cost,
	// and most lines cannot match most rules.
	need   []string
	digits int
	// multiline rules run once over the whole text instead of per line.
	multiline bool
}

func (r *rule) worth(lower string) bool {
	if r.digits > 0 && !hasDigitRun(lower, r.digits) {
		return false
	}
	if len(r.need) == 0 {
		return true
	}
	for _, n := range r.need {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func hasDigitRun(s string, n int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			run++
			if run >= n {
				return true
			}
		} else if s[i] != '-' && s[i] != ' ' && s[i] != ',' && s[i] != '.' {
			run = 0
		}
	}
	return false
}

// TokenRE matches a placeholder produced by the tokenmap package. Detection
// never reports anything that overlaps a placeholder, so masking is idempotent.
var TokenRE = regexp.MustCompile(`⟦[A-Z][A-Z0-9]*_[0-9]+⟧`)

var twCounties = `(?:臺北市|台北市|新北市|桃園市|臺中市|台中市|臺南市|台南市|高雄市|基隆市|新竹市|嘉義市|新竹縣|苗栗縣|彰化縣|南投縣|雲林縣|嘉義縣|屏東縣|宜蘭縣|花蓮縣|臺東縣|台東縣|澎湖縣|金門縣|連江縣)`

var rules = []rule{
	// --- credentials -------------------------------------------------------
	{kind: "PRIVKEY", multiline: true, need: []string{"private key"}, cat: Secret, basic: true, prio: 100,
		re: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----`)},
	{kind: "APIKEY", need: []string{"sk-ant-"}, cat: Secret, basic: true, prio: 90,
		re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}`)},
	{kind: "APIKEY", need: []string{"sk-"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}`)},
	{kind: "APIKEY", need: []string{"akia", "asia"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{kind: "SECRET", need: []string{"secret"}, cat: Secret, basic: true, prio: 80,
		re:    regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})`),
		group: 1},
	{kind: "APIKEY", need: []string{"gh", "github_pat_"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`)},
	{kind: "APIKEY", need: []string{"xox"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}`)},
	{kind: "APIKEY", need: []string{"_live_", "_test_"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
	{kind: "APIKEY", need: []string{"aiza"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{kind: "APIKEY", need: []string{"glpat-"}, cat: Secret, basic: true, prio: 80,
		re: regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`)},
	{kind: "JWT", need: []string{"eyj"}, cat: Secret, basic: true, prio: 70,
		re: regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{kind: "SECRET", need: []string{"bearer"}, cat: Secret, basic: true, prio: 60, group: 1, valid: plausibleSecret,
		re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})`)},
	{kind: "PASSWORD", need: []string{"://"}, cat: Secret, basic: true, prio: 60, group: 1, valid: plausibleSecret,
		re: regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@'"]+:([^\s@/'"]+)@[^\s/'"]+`)},
	{kind: "PASSWORD", need: []string{"pass", "pwd", "secret", "token", "key", "credential"}, cat: Secret, basic: true, prio: 50, group: 1, valid: plausibleSecret,
		re: regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|credentials?)["']?\s*[:=]\s*["']([^"'\s]{6,})["']`)},
	{kind: "PASSWORD", need: []string{"pass", "secret", "token", "key"}, cat: Secret, basic: true, prio: 50, group: 1, valid: plausibleSecret,
		// .env style: an upper-case variable name directly followed by "=".
		// Spaces around "=" mean source code ("password = request.form[...]"),
		// which the quoted-value rule above already covers.
		re: regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]*=["']?([^\s"'#]{6,})`)},
	{kind: "IP", need: []string{"10.", "192.168.", "172."}, cat: Secret, prio: 30, valid: validIPv4,
		re: regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)},
	{kind: "HOST", need: []string{".internal", ".corp", ".intranet", ".lan", ".local", ".private"}, cat: Secret, prio: 30,
		re: regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.(?:internal|corp|intranet|lan|local|private|localdomain)\b`)},

	// --- people ------------------------------------------------------------
	{kind: "TWID", digits: 8, cat: PII, prio: 70, valid: ValidTaiwanID,
		re: regexp.MustCompile(`\b[A-Z][1289A-D][0-9]{8}\b`)},
	{kind: "EMAIL", need: []string{"@"}, cat: PII, prio: 60,
		re: regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}\b`)},
	{kind: "PHONE", need: []string{"09", "886"}, digits: 4, cat: PII, prio: 55,
		re: regexp.MustCompile(`(?:\+886[\s-]?|\b0)9\d{2}[\s-]?\d{3}[\s-]?\d{3}\b`)},
	{kind: "PHONE", need: []string{"0"}, digits: 4, cat: PII, prio: 50,
		re: regexp.MustCompile(`\(0[2-8]\d?\)\s?\d{3,4}[\s-]?\d{4}\b|\b0[2-8]\d?[\s-]\d{3,4}[\s-]?\d{4}\b|\+886[\s-]?[2-8]\d?[\s-]?\d{3,4}[\s-]?\d{4}\b`)},
	{kind: "PHONE", need: []string{"+"}, digits: 3, cat: PII, prio: 40,
		re: regexp.MustCompile(`\+[1-9]\d{0,2}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,4}){2,4}\b`)},
	{kind: "CARD", digits: 13, cat: PII, prio: 65, valid: validCard,
		re: regexp.MustCompile(`\b[3-6]\d{3}(?:[ -]?\d){9,15}\b`)},
	{kind: "ADDRESS", need: []string{"號"}, cat: PII, prio: 45,
		re: regexp.MustCompile(twCounties + `?(?:[\p{Han}]{1,3}[區鄉鎮市])?[\p{Han}0-9]{1,5}(?:路|街|大道)(?:[一二三四五六七八九十0-9]+段)?(?:[0-9]+巷)?(?:[0-9]+弄)?[0-9]+(?:之[0-9]+)?號(?:[0-9]+樓)?(?:之[0-9]+)?`)},
	{kind: "NAME", need: []string{"姓名", "客戶", "客户", "聯絡人", "联系人", "負責人", "收件人", "申請人", "承辦人", "員工", "病患", "學生", "學員"}, cat: PII, prio: 40, group: 1,
		re: regexp.MustCompile(`(?:姓名|客戶|客户|聯絡人|联系人|負責人|收件人|申請人|承辦人|員工|病患|學生|學員)\s*[：:]\s*([\p{Han}]{2,4})`)},
	{kind: "NAME", need: []string{"出席", "列席", "與會", "參加者", "參與者", "成員", "收件者", "寄件者", "致", "敬啟者"}, cat: PII, prio: 40, group: 1,
		re: regexp.MustCompile(`(?:出席|列席|與會|參加者|參與者|成員|收件者|寄件者|致|敬啟者)\s*[：:]\s*([\p{Han}]{2,4})`)},
	{kind: "NAME", need: []string{"name", "customer", "client", "contact"}, cat: PII, prio: 40, group: 1,
		re: regexp.MustCompile(`\b(?:[Nn]ame|NAME|[Cc]ustomer|[Cc]lient|[Cc]ontact)\s*[:=]\s*["']?([A-Z][a-z]+(?:[ \t][A-Z][a-z]+){1,2})`)},

	// --- money -------------------------------------------------------------
	{kind: "AMOUNT", need: []string{"nt", "usd", "twd", "us$", "hk$", "rmb", "cny", "jpy", "eur", "€", "£", "¥", "＄"}, cat: Finance, prio: 35,
		re: regexp.MustCompile(`(?:NT\$|NTD|TWD|US\$|USD|HK\$|RMB|CNY|JPY|EUR|€|£|¥|＄)\s?\d+(?:,\d{3})*(?:\.\d+)?(?:\s?(?:萬|億|千|百萬|[kKmM]\b|million\b|billion\b))?`)},
	{kind: "AMOUNT", need: []string{"$"}, cat: Finance, prio: 35,
		re: regexp.MustCompile(`\$\s?(?:\d{1,3}(?:,\d{3})+|\d{3,})(?:\.\d+)?(?:\s?(?:[kKmM]\b|million\b|billion\b))?`)},
	{kind: "AMOUNT", need: []string{"元", "圓", "萬", "億", "美金", "台幣"}, cat: Finance, prio: 35,
		re: regexp.MustCompile(`\d+(?:,\d{3})*(?:\.\d+)?\s?(?:萬元|億元|千元|百萬元|元|圓|萬|億|美元|美金|台幣|新台幣|日圓|人民幣|歐元)`)},
	{kind: "AMOUNT", need: []string{"報價", "營收", "營業額", "金額", "薪", "預算", "成本", "價", "總額", "獲利", "淨利", "毛利", "price", "salary", "revenue", "amount", "budget", "cost"}, cat: Finance, prio: 35, group: 1,
		re: regexp.MustCompile(`(?i)(?:報價|營收|營業額|金額|薪資|薪水|月薪|年薪|時薪|預算|成本|售價|單價|總價|總額|獲利|淨利|毛利|price|salary|revenue|amount|budget|cost)\s*[：:=]\s*([\d,]*\d(?:\.\d+)?)`)},
	{kind: "BANKACCT", need: []string{"帳", "account"}, cat: Finance, prio: 45, group: 1,
		re: regexp.MustCompile(`(?i)(?:銀行帳號|帳號|帳戶|account\s*(?:no\.?|number|#))\s*[：:]?\s*(\d[\d-]{8,18}\d)`)},

	// --- organisations -----------------------------------------------------
	{kind: "COMPANY", need: []string{"公司"}, cat: Doc, prio: 40,
		re: regexp.MustCompile(`[\p{Han}A-Za-z0-9]{2,10}(?:股份有限公司|有限公司)`)},
	{kind: "COMPANY", need: []string{"inc", "corp", "ltd", "llc", "gmbh", "co."}, cat: Doc, prio: 40,
		re: regexp.MustCompile(`\b(?:[A-Z][A-Za-z0-9&-]+[ \t]){0,3}[A-Z][A-Za-z0-9&-]+,?[ \t](?:Inc|Corp|Corporation|Ltd|LLC|GmbH|Co\.,?[ \t]Ltd)\b\.?`)},
	{kind: "UBN", need: []string{"統一編號", "統編", "ubn", "vat"}, cat: Doc, prio: 45, group: 1, valid: ValidUBN,
		re: regexp.MustCompile(`(?:統一編號|統編|UBN|VAT\s*No\.?)\s*[：:]?\s*(\d{8})\b`)},
}

// Detector finds sensitive values according to a Config.
type Detector struct {
	cfg      Config
	rules    []rule
	terms    []term
	termAC   *ahoCorasick
	termLens []int
	allowSet map[string]bool
	allowSfx []string
	extHost  *regexp.Regexp
}

type term struct {
	kind  string
	value string
	ascii bool
	lower string
}

// New builds a Detector.
func New(cfg Config) *Detector {
	d := &Detector{cfg: cfg, allowSet: map[string]bool{}}
	for _, r := range rules {
		if cfg.Profile == Basic && !r.basic {
			continue
		}
		if cfg.Profile == Strict && cfg.Categories != nil && !cfg.Categories[r.cat] {
			continue
		}
		d.rules = append(d.rules, r)
	}
	if cfg.Profile == Strict && len(cfg.InternalDomains) > 0 && (cfg.Categories == nil || cfg.Categories[Secret]) {
		var alts []string
		for _, dom := range cfg.InternalDomains {
			dom = strings.Trim(strings.ToLower(dom), ". ")
			if dom != "" {
				alts = append(alts, regexp.QuoteMeta(dom))
			}
		}
		if len(alts) > 0 {
			d.extHost = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*(?:` + strings.Join(alts, "|") + `)\b`)
		}
	}
	for kind, vals := range cfg.Terms {
		k := SanitizeKind(kind)
		for _, v := range vals {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			t := term{kind: k, value: v, ascii: isASCII(v)}
			if t.ascii {
				t.lower = asciiLower(v)
			}
			d.terms = append(d.terms, t)
		}
	}
	// Longest first, so "Acme Holdings" wins over "Acme".
	sort.SliceStable(d.terms, func(i, j int) bool { return len(d.terms[i].value) > len(d.terms[j].value) })
	if len(d.terms) > 0 {
		pats := make([]string, len(d.terms))
		d.termLens = make([]int, len(d.terms))
		for i, t := range d.terms {
			// All patterns are matched against the ASCII-lower-cased text;
			// lower-casing leaves non-ASCII bytes alone, so CJK terms match
			// exactly and ASCII ones case-insensitively.
			pats[i] = asciiLower(t.value)
			d.termLens[i] = len(pats[i])
		}
		d.termAC = newAhoCorasick(pats)
	}
	for _, a := range cfg.Allow {
		a = strings.TrimSpace(a)
		switch {
		case a == "":
		case strings.HasPrefix(a, "*@"):
			d.allowSfx = append(d.allowSfx, strings.ToLower(a[1:]))
		case strings.HasPrefix(a, "."):
			d.allowSfx = append(d.allowSfx, strings.ToLower(a))
		default:
			d.allowSet[a] = true
		}
	}
	return d
}

// DefaultAllow holds values that look sensitive but are public by design.
var DefaultAllow = []string{"*@example.com", "*@example.org", "*@example.net", ".example.com", ".example.org", ".example.net", "noreply@anthropic.com", "*@users.noreply.github.com", "git@github.com", "git@gitlab.com", "git@bitbucket.org"}

// Find returns non-overlapping matches ordered by position. Leftmost wins; for
// two matches starting at the same byte the longer wins, then the higher
// priority rule.
func (d *Detector) Find(s string) []Match {
	if s == "" {
		return nil
	}
	protected := TokenRE.FindAllStringIndex(s, -1)
	var cands []cand
	add := func(start, end int, kind string, cat Category, prio int) {
		if start >= end || overlapsAny(start, end, protected) {
			return
		}
		v := s[start:end]
		if d.allowed(v) {
			return
		}
		cands = append(cands, cand{Match{start, end, kind, cat, v}, prio})
	}
	lower := asciiLower(s)
	run := func(r *rule, text string, off int) {
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			st, en := loc[2*r.group], loc[2*r.group+1]
			if st < 0 {
				continue
			}
			if r.valid != nil && !r.valid(text[st:en]) {
				continue
			}
			add(off+st, off+en, r.kind, r.cat, r.prio)
		}
	}
	for i := range d.rules {
		if r := &d.rules[i]; r.multiline && r.worth(lower) {
			run(r, s, 0)
		}
	}
	for ls := 0; ls < len(s); {
		le := strings.IndexByte(s[ls:], '\n')
		if le < 0 {
			le = len(s)
		} else {
			le += ls
		}
		line, ll := s[ls:le], lower[ls:le]
		for i := range d.rules {
			if r := &d.rules[i]; !r.multiline && r.worth(ll) {
				run(r, line, ls)
			}
		}
		ls = le + 1
	}
	if d.cfg.Profile == Strict {
		d.tableMatches(s, add)
		if d.cfg.Categories == nil || d.cfg.Categories[PII] {
			nameRuns(s, add)
			honorificNames(s, add)
		}
	}
	if d.extHost != nil {
		for _, loc := range d.extHost.FindAllStringIndex(s, -1) {
			add(loc[0], loc[1], "HOST", Secret, 35)
		}
	}
	if d.termAC != nil {
		d.termAC.find(lower, d.termLens, func(st, en, p int) {
			if d.terms[p].ascii && !asciiBoundary(s, st, en) {
				return
			}
			add(st, en, d.terms[p].kind, Doc, 200)
		})
	}
	return resolve(cands)
}

type cand struct {
	Match
	prio int
}

func resolve(c []cand) []Match {
	sort.Slice(c, func(i, j int) bool {
		if c[i].Start != c[j].Start {
			return c[i].Start < c[j].Start
		}
		li, lj := c[i].End-c[i].Start, c[j].End-c[j].Start
		if li != lj {
			return li > lj
		}
		return c[i].prio > c[j].prio
	})
	var out []Match
	last := -1
	for _, m := range c {
		if m.Start < last {
			// Overlaps a match we already kept. A strictly higher-priority
			// match fully inside the kept one does not displace it: the
			// enclosing span is masked either way.
			continue
		}
		out = append(out, m.Match)
		last = m.End
	}
	return out
}

func overlapsAny(s, e int, spans [][]int) bool {
	for _, sp := range spans {
		if s < sp[1] && sp[0] < e {
			return true
		}
	}
	return false
}

func (d *Detector) allowed(v string) bool {
	if d.allowSet[v] {
		return true
	}
	if len(d.allowSfx) == 0 {
		return false
	}
	lv := strings.ToLower(v)
	for _, sfx := range d.allowSfx {
		if strings.HasSuffix(lv, sfx) {
			return true
		}
	}
	return false
}

// SanitizeKind turns a user-supplied kind into the [A-Z][A-Z0-9]* form tokens use.
func SanitizeKind(k string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(k) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9' && b.Len() > 0) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "TERM"
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII letters only, so byte offsets stay aligned with
// the original string (strings.ToLower can change UTF-8 lengths).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func asciiBoundary(s string, st, en int) bool {
	if st > 0 && isWordByte(s[st-1]) && isWordByte(s[st]) {
		return false
	}
	if en < len(s) && isWordByte(s[en]) && isWordByte(s[en-1]) {
		return false
	}
	return true
}

// --- validators --------------------------------------------------------------

var twLetter = map[byte]int{
	'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15, 'G': 16, 'H': 17, 'I': 34,
	'J': 18, 'K': 19, 'L': 20, 'M': 21, 'N': 22, 'O': 35, 'P': 23, 'Q': 24, 'R': 25,
	'S': 26, 'T': 27, 'U': 28, 'V': 29, 'W': 32, 'X': 30, 'Y': 31, 'Z': 33,
}

// ValidTaiwanID checks a Taiwan national ID or resident certificate number
// (old and new format) against its check digit.
func ValidTaiwanID(s string) bool {
	if len(s) != 10 {
		return false
	}
	code, ok := twLetter[s[0]]
	if !ok {
		return false
	}
	var second int
	switch c := s[1]; {
	case c == '1' || c == '2' || c == '8' || c == '9':
		second = int(c - '0')
	case c >= 'A' && c <= 'D':
		// Old-format resident certificate: the second letter's code, ones digit.
		second = twLetter[c] % 10
	default:
		return false
	}
	sum := code/10 + (code%10)*9 + second*8
	for i := 2; i < 9; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * (9 - i)
	}
	if s[9] < '0' || s[9] > '9' {
		return false
	}
	sum += int(s[9] - '0')
	return sum%10 == 0
}

// ValidUBN checks a Taiwan Unified Business Number (統一編號). Since 2023 the
// rule is "sum divisible by 5"; numbers valid under the older "by 10" rule
// also pass.
func ValidUBN(s string) bool {
	if len(s) != 8 {
		return false
	}
	w := [8]int{1, 2, 1, 2, 1, 2, 4, 1}
	sum := 0
	for i := 0; i < 8; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		p := int(s[i]-'0') * w[i]
		sum += p/10 + p%10
	}
	if sum%5 == 0 {
		return true
	}
	// Seventh digit 7: the product 28 may count as 10 (1+0) or 1 (sum again).
	return s[6] == '7' && (sum+1)%5 == 0
}

// Luhn reports whether a digit string passes the Luhn checksum.
func Luhn(digits string) bool {
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func validCard(s string) bool {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	d := b.String()
	return len(d) >= 13 && len(d) <= 19 && Luhn(d)
}

func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

var placeholderWords = []string{
	"password", "passwd", "secret", "token", "changeme", "change_me", "example",
	"your", "xxxx", "****", "....", "dummy", "placeholder", "redacted", "<", ">",
	"${", "{{", "%(", "$(", "process.env", "os.environ", "getenv", "env(", "none", "null", "undefined",
}

func startsWithSurname(v string) bool {
	r, _ := utf8.DecodeRuneInString(v)
	if surnames1[r] {
		return true
	}
	for _, c := range surnames2 {
		if strings.HasPrefix(v, c) {
			return true
		}
	}
	return false
}

// plausibleSecret filters out values that are obviously not real secrets:
// placeholders, references to environment variables, and runs of one character.
func plausibleSecret(v string) bool {
	if strings.HasPrefix(v, "⟦") {
		return false
	}
	lv := strings.ToLower(v)
	for _, w := range placeholderWords {
		if strings.Contains(lv, w) {
			return false
		}
	}
	if strings.HasPrefix(v, "$") {
		return false
	}
	return Entropy(v) >= 2.0
}

// Entropy is the Shannon entropy of s in bits per byte.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
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
