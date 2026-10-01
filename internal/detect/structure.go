package detect

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Structure-aware detection for things no single-value pattern can see:
// names in a CSV column headed "姓名", or a list of attendees separated by "、".

// columnKinds maps header keywords to the kind of value the column holds.
// Matching is on the lower-cased header: CJK keywords as substrings, ASCII
// keywords as whole words of a snake/kebab/space-separated header.
var columnKinds = []struct {
	kind string
	cat  Category
	zh   []string
	en   []string
}{
	{"NAME", PII, []string{"姓名", "名字", "客戶", "聯絡人", "联系人", "負責人", "收件人", "申請人", "承辦人", "員工", "學生", "學員", "病患", "會員", "持卡人"},
		[]string{"name", "fullname", "firstname", "lastname", "customer", "client", "contact", "employee", "patient", "member", "cardholder", "owner"}},
	{"TWID", PII, []string{"身分證", "身份證", "證號", "統號"}, []string{"national_id", "nationalid", "id_number", "idnumber", "ssn", "passport"}},
	{"PHONE", PII, []string{"電話", "手機", "行動", "聯絡方式"}, []string{"phone", "tel", "telephone", "mobile", "cell"}},
	{"EMAIL", PII, []string{"信箱", "電子郵件", "郵件"}, []string{"email", "e-mail", "mail"}},
	{"ADDRESS", PII, []string{"地址", "住址", "通訊處", "戶籍"}, []string{"address", "addr", "street"}},
	{"DOB", PII, []string{"生日", "出生"}, []string{"dob", "birthday", "birthdate", "birth_date", "date_of_birth"}},
	{"AMOUNT", Finance, []string{"金額", "薪", "價格", "售價", "單價", "總價", "總額", "報價", "營收", "成本", "預算", "獎金", "費用"},
		[]string{"amount", "price", "salary", "total", "revenue", "cost", "budget", "bonus", "fee", "payment", "balance", "order_total"}},
	{"BANKACCT", Finance, []string{"帳號", "帳戶", "銀行"}, []string{"iban", "account_number", "bank_account", "account_no"}},
	{"COMPANY", Doc, []string{"公司", "廠商", "供應商", "客戶名稱", "單位"}, []string{"company", "organization", "organisation", "org", "vendor", "supplier", "employer"}},
}

func headerKind(h string) (string, Category, bool) {
	h = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(h), `"'`)))
	h = strings.TrimPrefix(h, "\xef\xbb\xbf")
	if h == "" {
		return "", "", false
	}
	words := strings.FieldsFunc(h, func(r rune) bool { return r == '_' || r == '-' || r == ' ' || r == '.' })
	joined := strings.Join(words, "_")
	for _, ck := range columnKinds {
		for _, k := range ck.zh {
			if strings.Contains(h, k) {
				return ck.kind, ck.cat, true
			}
		}
		for _, k := range ck.en {
			if joined == k || h == k {
				return ck.kind, ck.cat, true
			}
			for _, w := range words {
				if w == k {
					return ck.kind, ck.cat, true
				}
			}
		}
	}
	return "", "", false
}

type span struct{ start, end int }

// splitCells splits one line on delim, honouring double quotes, and returns
// the byte span of each cell's content (quotes and surrounding blanks excluded).
func splitCells(line string, off int, delim byte) []span {
	var out []span
	start := 0
	inQ := false
	emit := func(end int) {
		s, e := start, end
		for s < e && (line[s] == ' ' || line[s] == '\t' && delim != '\t') {
			s++
		}
		for e > s && (line[e-1] == ' ' || line[e-1] == '\r' || line[e-1] == '\t' && delim != '\t') {
			e--
		}
		if e-s >= 2 && line[s] == '"' && line[e-1] == '"' {
			s++
			e--
		}
		out = append(out, span{off + s, off + e})
	}
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '"':
			inQ = !inQ
		case c == delim && !inQ:
			emit(i)
			start = i + 1
		}
	}
	emit(len(line))
	return out
}

// tableMatches finds CSV/TSV/pipe tables and reports every non-empty cell of
// a column whose header names a sensitive field. A table is a run of at least
// two lines with the same number of delimiters as its header line.
func (d *Detector) tableMatches(s string, add func(start, end int, kind string, cat Category, prio int)) {
	lines := strings.SplitAfter(s, "\n")
	offs := make([]int, len(lines))
	o := 0
	for i, l := range lines {
		offs[i] = o
		o += len(l)
	}
	for i := 0; i < len(lines); i++ {
		head := strings.TrimRight(lines[i], "\r\n")
		delim, n := tableDelim(head)
		if n == 0 {
			continue
		}
		heads := splitCells(head, offs[i], delim)
		kinds := make([]struct {
			kind string
			cat  Category
			ok   bool
		}, len(heads))
		any := false
		for j, h := range heads {
			k, c, ok := headerKind(s[h.start:h.end])
			if ok && (d.cfg.Categories == nil || d.cfg.Categories[c]) {
				kinds[j].kind, kinds[j].cat, kinds[j].ok = k, c, true
				any = true
			}
		}
		if !any {
			continue
		}
		j := i + 1
		for ; j < len(lines); j++ {
			row := strings.TrimRight(lines[j], "\r\n")
			cells := splitCells(row, offs[j], delim)
			if len(cells) != len(heads) {
				break
			}
			if delim == '|' && isMarkdownRule(row) {
				continue
			}
			for c, sp := range cells {
				if c < len(kinds) && kinds[c].ok && sp.end > sp.start {
					add(sp.start, sp.end, kinds[c].kind, kinds[c].cat, 25)
				}
			}
		}
		if j > i+1 {
			i = j - 1
		}
	}
}

// tableDelim picks the delimiter of a header line: the one of tab, comma,
// pipe or semicolon that appears most (at least once), with the count.
func tableDelim(line string) (byte, int) {
	best, bestN := byte(0), 0
	for _, c := range []byte{'\t', ',', '|', ';'} {
		if n := len(splitCells(line, 0, c)) - 1; n > bestN {
			best, bestN = c, n
		}
	}
	return best, bestN
}

func isMarkdownRule(row string) bool {
	for i := 0; i < len(row); i++ {
		if strings.IndexByte("|-: \t", row[i]) < 0 {
			return false
		}
	}
	return true
}

// Common Taiwanese and Chinese surnames, single and compound.
var surnames1 = map[rune]bool{}
var surnames2 = []string{"歐陽", "司馬", "上官", "諸葛", "東方", "皇甫", "尉遲", "公孫", "慕容", "夏侯", "長孫", "宇文", "司徒", "張簡", "范姜", "周黃", "張廖", "陳黃"}

func init() {
	for _, r := range "陳林黃張李王吳劉蔡楊許鄭謝郭洪曾邱廖賴周徐蘇葉莊呂江何蕭羅高潘簡朱鍾彭游詹胡施沈余趙盧梁顏柯孫魏翁戴范宋方鄧杜傅侯曹溫薛丁馬蔣唐卓藍馮姚石董紀歐程連古汪湯姜田康鄒白涂尤巫韓龔嚴袁黎金阮陸倪夏童邵柳錢凌溫粘閻" {
		surnames1[r] = true
	}
}

// Characters that end place names, organisations and common nouns but almost
// never a personal name; a run ending in one is not reported as a name.
var nonNameTail = map[rune]bool{}

func init() {
	for _, r := range "市縣區鄉鎮里村路街巷弄號樓段局部處署院會業碼書式價額量率費稅表單類型性化度期日月年週季店館站廠場港灣島山河湖海線網機器車品物料錢元萬億司廳科系組隊班校所室家國省州郡城門橋塔堂寺廟宮府衙營庫倉場區域界版本號題案件項目檔頁章節慶典節展賽杯獎獄院團社協盟黨庄厝" {
		nonNameTail[r] = true
	}
}

// nameRuns reports standalone runs of Han characters shaped like a personal
// name: a common surname followed by one or two given-name characters, with
// no Han character directly before or after. In Chinese prose words are not
// separated, so a standalone 2-3 character run appears mostly in lists,
// tables and headers, which is where names sit ("出席：王小明、陳美玲").
func nameRuns(s string, add func(start, end int, kind string, cat Category, prio int)) {
	i := 0
	for i < len(s) {
		r, w := utf8.DecodeRuneInString(s[i:])
		if !unicode.Is(unicode.Han, r) {
			i += w
			continue
		}
		start := i
		var runes []rune
		for i < len(s) {
			r, w = utf8.DecodeRuneInString(s[i:])
			if !unicode.Is(unicode.Han, r) {
				break
			}
			runes = append(runes, r)
			i += w
		}
		if looksLikeName(runes) {
			add(start, i, "NAME", PII, 20)
		}
	}
}

func looksLikeName(r []rune) bool {
	n := len(r)
	if n < 2 || n > 4 || nonNameTail[r[n-1]] {
		return false
	}
	s := string(r)
	for _, c := range surnames2 {
		if strings.HasPrefix(s, c) {
			return n == 3 || n == 4
		}
	}
	// Two-character runs ("林業", "高雄") are too often ordinary words; only
	// three characters are taken on shape alone.
	return n == 3 && surnames1[r[0]]
}

var honorifics = []string{"先生", "小姐", "女士", "同學", "老師", "經理", "主任", "董事長", "總經理", "副總", "律師", "醫師", "醫生", "教授", "博士", "議員", "委員"}

// honorificNames finds names directly before a title ("陳美玲小姐",
// "林志豪先生"): the longest 2-4 character Han run ending at the title that
// starts with a surname.
func honorificNames(s string, add func(start, end int, kind string, cat Category, prio int)) {
	for _, h := range honorifics {
		for off := 0; ; {
			i := strings.Index(s[off:], h)
			if i < 0 {
				break
			}
			at := off + i
			off = at + len(h)
			// Collect up to four Han runes immediately before the title.
			var starts []int
			p := at
			for len(starts) < 4 && p > 0 {
				r, w := utf8.DecodeLastRuneInString(s[:p])
				if !unicode.Is(unicode.Han, r) {
					break
				}
				p -= w
				starts = append(starts, p)
			}
			for k := len(starts) - 1; k >= 1; k-- { // longest first, at least 2 runes
				cand := s[starts[k]:at]
				if startsWithSurname(cand) && !nonNameTail[lastRune(cand)] && (k+1 <= 3 || hasCompoundSurname(cand)) {
					add(starts[k], at, "NAME", PII, 40)
					break
				}
			}
		}
	}
}

func lastRune(s string) rune {
	r, _ := utf8.DecodeLastRuneInString(s)
	return r
}

func hasCompoundSurname(s string) bool {
	for _, c := range surnames2 {
		if strings.HasPrefix(s, c) {
			return true
		}
	}
	return false
}
