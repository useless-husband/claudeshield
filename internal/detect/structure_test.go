package detect

import (
	"math/rand"
	"strings"
	"testing"
)

func TestCSVColumns(t *testing.T) {
	csv := "name,national_id,phone,email,order_total,note\n" +
		"王小明,A123456789,0912-345-678,wang@acme.com.tw,NT$120000,VIP\n" +
		"\"Lee, Ann\",F131104093,0987-654-321,ann@x.io,45500,\n"
	got := strings.Join(kinds(strict().Find(csv)), "|")
	for _, want := range []string{"NAME=王小明", "NAME=Lee, Ann", "TWID=F131104093", "PHONE=0987-654-321", "EMAIL=ann@x.io", "AMOUNT=45500"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "VIP") || strings.Contains(got, "name") {
		t.Errorf("unrelated cell or header masked: %s", got)
	}
}

func TestTSVAndMarkdownTables(t *testing.T) {
	tsv := "姓名\t部門\t月薪\n陳美玲\t業務部\t68000\n林志豪\t研發部\t72000\n"
	got := strings.Join(kinds(strict().Find(tsv)), "|")
	if got != "NAME=陳美玲|AMOUNT=68000|NAME=林志豪|AMOUNT=72000" {
		t.Fatalf("tsv: %s", got)
	}
	md := "| 客戶 | 金額 |\n|---|---|\n| 張大同 | 1500 |\n"
	got = strings.Join(kinds(strict().Find(md)), "|")
	if got != "NAME=張大同|AMOUNT=1500" {
		t.Fatalf("markdown: %s", got)
	}
}

func TestTableRespectsCategories(t *testing.T) {
	d := New(Config{Profile: Strict, Categories: map[Category]bool{PII: true}})
	got := strings.Join(kinds(d.Find("name,amount\nAnn Lee,500\n")), "|")
	if got != "NAME=Ann Lee" {
		t.Fatalf("got %s", got)
	}
}

func TestNameRuns(t *testing.T) {
	got := strings.Join(kinds(strict().Find("出席：王小明、陳美玲、歐陽娜娜，記錄：林志豪")), "|")
	if got != "NAME=王小明|NAME=陳美玲|NAME=歐陽娜娜|NAME=林志豪" {
		t.Fatalf("got %s", got)
	}
	for _, s := range []string{"高雄市", "林業", "程式碼、白皮書、周年慶、方程式", "黃金價", "今天天氣很好", "王"} {
		if ms := strict().Find(s); len(ms) != 0 {
			t.Errorf("%q: false positive %v", s, kinds(ms))
		}
	}
}

func TestHonorifics(t *testing.T) {
	got := strings.Join(kinds(strict().Find("請轉告陳美玲小姐與張經理，林志豪先生已到。")), "|")
	if !strings.Contains(got, "NAME=陳美玲") || !strings.Contains(got, "NAME=林志豪") {
		t.Fatalf("got %s", got)
	}
}

func TestBasicIgnoresStructure(t *testing.T) {
	if ms := New(Config{Profile: Basic}).Find("name,phone\n王小明,0912345678\n"); len(ms) != 0 {
		t.Fatalf("basic profile masked table cells: %v", kinds(ms))
	}
}

// The automaton must report exactly what a naive search reports.
func TestAhoCorasickMatchesNaiveSearch(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	alpha := []string{"a", "b", "ab", "王", "小明", "c"}
	for n := 0; n < 500; n++ {
		var pats []string
		for k := 1 + r.Intn(8); k > 0; k-- {
			var b strings.Builder
			for m := 1 + r.Intn(3); m > 0; m-- {
				b.WriteString(alpha[r.Intn(len(alpha))])
			}
			pats = append(pats, b.String())
		}
		var tb strings.Builder
		for m := r.Intn(30); m > 0; m-- {
			tb.WriteString(alpha[r.Intn(len(alpha))])
		}
		text := tb.String()
		lens := make([]int, len(pats))
		for i, p := range pats {
			lens[i] = len(p)
		}
		got := map[[3]int]bool{}
		newAhoCorasick(pats).find(text, lens, func(s, e, p int) { got[[3]int{s, e, p}] = true })
		want := map[[3]int]bool{}
		for p, pat := range pats {
			for i := 0; i+len(pat) <= len(text); i++ {
				if text[i:i+len(pat)] == pat {
					want[[3]int{i, i + len(pat), p}] = true
				}
			}
		}
		if len(got) != len(want) {
			t.Fatalf("seed 99 case %d: pats %q text %q: got %d matches, want %d", n, pats, text, len(got), len(want))
		}
		for k := range want {
			if !got[k] {
				t.Fatalf("seed 99 case %d: missing %v", n, k)
			}
		}
	}
}
