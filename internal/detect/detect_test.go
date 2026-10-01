package detect

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Fake credentials, assembled at run time so that no credential-shaped
// literal appears in the source (secret scanners would flag it).
var (
	fakeAWSKey       = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeAnthropicKey = "sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
	fakeGitHubToken  = "ghp" + "_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
)

func kinds(ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Kind+"="+m.Value)
	}
	return out
}

func strict() *Detector { return New(Config{Profile: Strict, Allow: DefaultAllow}) }

func TestTaiwanIDChecksum(t *testing.T) {
	valid := []string{"A123456789", "F131104093", "A800000014", "AC01234567"}
	for _, id := range valid {
		if !ValidTaiwanID(id) {
			t.Errorf("%s should be valid", id)
		}
	}
	invalid := []string{"A123456788", "A323456789", "a123456789", "A12345678", "1123456789", "AE01234567"}
	for _, id := range invalid {
		if ValidTaiwanID(id) {
			t.Errorf("%s should be invalid", id)
		}
	}
}

// Every ID produced by the published construction must validate. Changing one
// digit by d at a position of weight w is caught exactly when w*d is not a
// multiple of 10: the scheme has even weights, so a ±5 change at those
// positions is invisible to the check digit, and the test pins that down.
func TestTaiwanIDGeneratedProperty(t *testing.T) {
	seed := int64(20261002)
	r := rand.New(rand.NewSource(seed))
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for n := 0; n < 2000; n++ {
		b := []byte{letters[r.Intn(26)], "1289"[r.Intn(4)]}
		for i := 0; i < 7; i++ {
			b = append(b, byte('0'+r.Intn(10)))
		}
		code := twLetter[b[0]]
		sum := code/10 + (code%10)*9 + int(b[1]-'0')*8
		for i := 2; i < 9; i++ {
			sum += int(b[i]-'0') * (9 - i)
		}
		b = append(b, byte('0'+(10-sum%10)%10))
		id := string(b)
		if !ValidTaiwanID(id) {
			t.Fatalf("seed %d: generated %s does not validate", seed, id)
		}
		pos := 2 + r.Intn(8)
		w := 9 - pos
		if pos == 9 {
			w = 1
		}
		d := 1 + r.Intn(9)
		mut := []byte(id)
		mut[pos] = byte('0' + (int(mut[pos]-'0')+d)%10)
		caught := (w*d)%10 != 0
		if ValidTaiwanID(string(mut)) == caught {
			t.Fatalf("seed %d: change %s -> %s (weight %d, delta %d): caught=%v", seed, id, mut, w, d, !ValidTaiwanID(string(mut)))
		}
	}
}

func TestUBN(t *testing.T) {
	// 22099131 is TSMC's published UBN; 04595257 is a well-known public one.
	for _, v := range []string{"22099131", "04595257"} {
		if !ValidUBN(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	if ValidUBN("22099132") {
		t.Error("22099132 should be invalid")
	}
}

func TestLuhn(t *testing.T) {
	if !Luhn("4111111111111111") || Luhn("4111111111111112") {
		t.Fatal("luhn broken")
	}
}

func TestStrictFindsTaiwanPII(t *testing.T) {
	text := "客戶：王小明，身分證 A123456789，手機 0912-345-678，" +
		"市話 (02)2345-6789，email wang@corp-mail.com.tw，" +
		"住台北市大安區忠孝東路四段100號5樓，卡號 4111 1111 1111 1111。"
	got := kinds(strict().Find(text))
	want := []string{
		"NAME=王小明", "TWID=A123456789", "PHONE=0912-345-678", "PHONE=(02)2345-6789",
		"EMAIL=wang@corp-mail.com.tw", "ADDRESS=台北市大安區忠孝東路四段100號5樓", "CARD=4111 1111 1111 1111",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestStrictFindsFinance(t *testing.T) {
	text := "報價：1,250,000，預算 NT$ 3,000,000，合約金額 250萬元，月薪: 68000，帳號：012-345678901"
	got := kinds(strict().Find(text))
	want := []string{"AMOUNT=1,250,000", "AMOUNT=NT$ 3,000,000", "AMOUNT=250萬元", "AMOUNT=68000", "BANKACCT=012-345678901"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestStrictFindsOrganisations(t *testing.T) {
	text := "甲方：台灣積體電路製造股份有限公司（統一編號：22099131），乙方 Acme Widgets Inc."
	got := kinds(strict().Find(text))
	want := []string{"COMPANY=台灣積體電路製造股份有限公司", "UBN=22099131", "COMPANY=Acme Widgets Inc."}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestBasicFindsCredentialsOnly(t *testing.T) {
	d := New(Config{Profile: Basic})
	text := strings.Join([]string{
		`ANTHROPIC_API_KEY=` + fakeAnthropicKey,
		`aws = "` + fakeAWSKey + `"`,
		`db: postgres://admin:S3cr3t!pass@db.internal:5432/app`,
		`token: "` + fakeGitHubToken + `"`,
		`phone 0912345678 and id A123456789 are not credentials`,
	}, "\n")
	got := kinds(d.Find(text))
	want := []string{
		"APIKEY=" + fakeAnthropicKey,
		"APIKEY=" + fakeAWSKey,
		"PASSWORD=S3cr3t!pass",
		"APIKEY=" + fakeGitHubToken,
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	text := "x\n-----BEGIN OPENSSH PRIV" + "ATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\nAAAA\n-----END OPENSSH PRIV" + "ATE KEY-----\ny"
	ms := New(Config{Profile: Basic}).Find(text)
	if len(ms) != 1 || ms[0].Kind != "PRIVKEY" || !strings.HasPrefix(ms[0].Value, "-----BEGIN") || !strings.HasSuffix(ms[0].Value, "KEY-----") {
		t.Fatalf("got %v", kinds(ms))
	}
}

// Ordinary source code must not trip the Basic profile, which runs in every session.
func TestBasicNoFalsePositivesOnCode(t *testing.T) {
	d := New(Config{Profile: Basic})
	code := `
password = request.form["password"]
token = os.environ["GITHUB_TOKEN"]
const apiKey = process.env.API_KEY;
secret: "${SECRET}"
PASSWORD=changeme
api_key = "your-api-key-here"
let t = "Bearer " + token
awk '{print $1}' file
echo $100
`
	if ms := d.Find(code); len(ms) != 0 {
		t.Fatalf("false positives: %q", kinds(ms))
	}
}

func TestTermsAreLiteralAndBounded(t *testing.T) {
	d := New(Config{Profile: Basic, Terms: map[string][]string{
		"client":  {"Acme", "Acme Holdings", "王小明"},
		"project": {"Falcon"},
	}})
	text := "Acme Holdings and ACME and Acmeville; 王小明 asked about Project falcon."
	got := kinds(d.Find(text))
	want := []string{"CLIENT=Acme Holdings", "CLIENT=ACME", "CLIENT=王小明", "PROJECT=falcon"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestAllowList(t *testing.T) {
	d := New(Config{Profile: Strict, Allow: append([]string{"0912345678", ".mycorp.local"}, DefaultAllow...)})
	text := "a@example.com b@real.com 0912345678 0987654321 git@github.com:x/y build.mycorp.local"
	got := kinds(d.Find(text))
	want := []string{"EMAIL=b@real.com", "PHONE=0987654321"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestPlaceholdersAreNeverDetected(t *testing.T) {
	d := strict()
	text := "token: \"⟦APIKEY_001⟧\" id ⟦TWID_002⟧ mail ⟦EMAIL_010⟧@x ⟦AMOUNT_3⟧元"
	for _, m := range d.Find(text) {
		if strings.Contains(m.Value, "⟦") || strings.Contains(m.Value, "⟧") {
			t.Fatalf("detected inside a placeholder: %+v", m)
		}
	}
}

func TestCategoriesSwitch(t *testing.T) {
	d := New(Config{Profile: Strict, Categories: map[Category]bool{PII: true}})
	got := kinds(d.Find("A123456789 NT$500 " + fakeAnthropicKey))
	if strings.Join(got, "|") != "TWID=A123456789" {
		t.Fatalf("got %q", got)
	}
}

func TestInternalDomains(t *testing.T) {
	d := New(Config{Profile: Strict, InternalDomains: []string{"mycorp.com.tw"}})
	got := kinds(d.Find("see https://wiki.mycorp.com.tw/page and mycorp.com.tw"))
	want := []string{"HOST=wiki.mycorp.com.tw", "HOST=mycorp.com.tw"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q", got)
	}
}

func TestMatchesNeverOverlapAndAreOrdered(t *testing.T) {
	seed := int64(7)
	r := rand.New(rand.NewSource(seed))
	pieces := []string{"A123456789", "0912345678", " ", "NT$1,000", "王小明", "客戶：", "台北市信義區松仁路100號",
		"x@y.com", "股份有限公司", "4111111111111111", "⟦EMAIL_001⟧", "\n", "token=\"abcdefgh1234\"", "元", "萬"}
	d := New(Config{Profile: Strict, Terms: map[string][]string{"c": {"小明", "Acme"}}})
	for n := 0; n < 3000; n++ {
		var b strings.Builder
		for k := r.Intn(12); k >= 0; k-- {
			b.WriteString(pieces[r.Intn(len(pieces))])
		}
		s := b.String()
		ms := d.Find(s)
		last := 0
		for _, m := range ms {
			if m.Start < last || m.End <= m.Start || m.End > len(s) || s[m.Start:m.End] != m.Value {
				t.Fatalf("seed %d case %d: bad match %+v in %q (%v)", seed, n, m, s, fmt.Sprint(kinds(ms)))
			}
			last = m.End
		}
	}
}

func FuzzFind(f *testing.F) {
	f.Add("客戶：王小明 A123456789 0912-345-678 NT$1,000")
	f.Add("-----BEGIN RSA PRIV" + "ATE KEY-----\nabc\n-----END RSA PRIV" + "ATE KEY-----")
	f.Add("⟦X_1⟧⟦")
	d := New(Config{Profile: Strict, Terms: map[string][]string{"t": {"ab", "測試"}}})
	f.Fuzz(func(t *testing.T, s string) {
		last := 0
		for _, m := range d.Find(s) {
			if m.Start < last || m.End > len(s) || s[m.Start:m.End] != m.Value {
				t.Fatalf("bad match %+v", m)
			}
			last = m.End
		}
	})
}
