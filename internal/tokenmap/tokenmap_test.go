package tokenmap

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/useless-husband/claudeshield/internal/detect"
)

var strict = detect.New(detect.Config{Profile: detect.Strict})

var pieces = []string{
	"A123456789", "F131104093", "0912-345-678", "0987654321", "wang@corp.com.tw", "lee@x.io",
	"NT$1,000", "250萬元", "台北市信義區松仁路100號", "客戶：王小明", "4111111111111111",
	"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "10.0.3.7",
	" ", "，", "\n", "the ", "報告", "abc", "123", "-", ":", "\"",
}

func randomText(r *rand.Rand) string {
	var b strings.Builder
	for k := r.Intn(20); k >= 0; k-- {
		b.WriteString(pieces[r.Intn(len(pieces))])
	}
	return b.String()
}

func TestRoundTripProperty(t *testing.T) {
	seed := int64(42)
	r := rand.New(rand.NewSource(seed))
	m := New()
	for n := 0; n < 5000; n++ {
		s := randomText(r)
		masked, _ := m.Mask(strict, s)
		if left := strict.Find(masked); len(left) != 0 {
			t.Fatalf("seed %d case %d: %q still has %v after masking -> %q", seed, n, s, left, masked)
		}
		again, _ := m.Mask(strict, masked)
		if again != masked {
			t.Fatalf("seed %d case %d: masking not idempotent: %q -> %q", seed, n, masked, again)
		}
		back, _, unknown := m.Unmask(masked)
		if back != s || len(unknown) != 0 {
			t.Fatalf("seed %d case %d: round trip %q -> %q -> %q (unknown %v)", seed, n, s, masked, back, unknown)
		}
	}
}

func TestSameValueSameToken(t *testing.T) {
	m := New()
	a, _ := m.Mask(strict, "客戶：王小明 A123456789")
	b, _ := m.Mask(strict, "A123456789 又出現了")
	if !strings.Contains(a, "⟦TWID_001⟧") || !strings.HasPrefix(b, "⟦TWID_001⟧") {
		t.Fatalf("a=%q b=%q", a, b)
	}
	if v, ok := m.Value("⟦TWID_001⟧"); !ok || v != "A123456789" {
		t.Fatalf("value = %q %v", v, ok)
	}
}

func TestUnknownPlaceholdersAreReported(t *testing.T) {
	m := New()
	m.TokenFor("EMAIL", "a@b.co")
	out, n, unknown := m.Unmask("to ⟦EMAIL_001⟧ and ⟦EMAIL_002⟧")
	if out != "to a@b.co and ⟦EMAIL_002⟧" || n != 1 || len(unknown) != 1 || unknown[0] != "⟦EMAIL_002⟧" {
		t.Fatalf("out=%q n=%d unknown=%v", out, n, unknown)
	}
}

func TestPersistenceAndPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "maps", "w.json")
	var first string
	if err := Update(path, func(m *Map) error {
		first, _ = m.Mask(strict, "mail wang@corp.com.tw")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("map file mode %v, want 0600", st.Mode().Perm())
	}
	if dst, _ := os.Stat(filepath.Dir(path)); dst.Mode().Perm() != 0o700 {
		t.Fatalf("map dir mode %v, want 0700", dst.Mode().Perm())
	}
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Mask(strict, "mail wang@corp.com.tw"); got != first {
		t.Fatalf("token changed across processes: %q vs %q", got, first)
	}
}

func TestLoadMissingIsEmpty(t *testing.T) {
	m, err := Load(filepath.Join(t.TempDir(), "nope", "x.json"))
	if err != nil || m.Len() != 0 {
		t.Fatalf("m=%v err=%v", m, err)
	}
}

func TestCorruptMapIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(path, []byte("{not json"), 0o600)
	if err := Update(path, func(*Map) error { return nil }); err == nil {
		t.Fatal("expected error for corrupt map")
	}
}

func TestJSONWalkKeepsShape(t *testing.T) {
	m := New()
	in := map[string]any{
		"type": "text",
		"file": map[string]any{"filePath": "/x/a.txt", "content": "客戶：王小明\n電話 0912345678", "numLines": 2},
		"list": []any{"A123456789", 3, true, nil},
	}
	out, n, kinds := m.MaskJSON(strict, in)
	if n != 3 || kinds["PHONE"] != 1 || kinds["NAME"] != 1 || kinds["TWID"] != 1 {
		t.Fatalf("n=%d kinds=%v", n, kinds)
	}
	o := out.(map[string]any)
	f := o["file"].(map[string]any)
	if f["numLines"] != 2 || f["filePath"] != "/x/a.txt" || o["list"].([]any)[1] != 3 {
		t.Fatalf("shape changed: %#v", out)
	}
	if in["file"].(map[string]any)["content"] != "客戶：王小明\n電話 0912345678" {
		t.Fatal("input was mutated")
	}
	if !JSONHasTokens(out) || JSONHasTokens(in) {
		t.Fatal("JSONHasTokens wrong")
	}
	back, r, unknown := m.UnmaskJSON(out)
	if r != 3 || len(unknown) != 0 || back.(map[string]any)["file"].(map[string]any)["content"] != in["file"].(map[string]any)["content"] {
		t.Fatalf("unmask: %#v", back)
	}
}

// Many writers in one process: every value gets exactly one token and none is lost.
func TestConcurrentUpdatesInProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.json")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				v := fmt.Sprintf("user%d_%d@corp.com.tw", g, i)
				if err := Update(path, func(m *Map) error { m.Mask(strict, v); return nil }); err != nil {
					t.Error(err)
				}
			}
		}(g)
	}
	wg.Wait()
	checkUnique(t, path, 200)
}

// Many writer processes, the way parallel hooks really run.
func TestConcurrentUpdatesAcrossProcesses(t *testing.T) {
	if os.Getenv("TOKENMAP_CHILD") != "" {
		return
	}
	path := filepath.Join(t.TempDir(), "m.json")
	var cmds []*exec.Cmd
	for p := 0; p < 6; p++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestChildWriter$")
		cmd.Env = append(os.Environ(), "TOKENMAP_CHILD="+strconv.Itoa(p), "TOKENMAP_PATH="+path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	checkUnique(t, path, 6*30)
}

func TestChildWriter(t *testing.T) {
	id := os.Getenv("TOKENMAP_CHILD")
	if id == "" {
		t.Skip("helper for TestConcurrentUpdatesAcrossProcesses")
	}
	for i := 0; i < 30; i++ {
		v := fmt.Sprintf("p%s_%d@corp.com.tw", id, i)
		if err := Update(os.Getenv("TOKENMAP_PATH"), func(m *Map) error { m.Mask(strict, v); return nil }); err != nil {
			t.Fatal(err)
		}
	}
}

func checkUnique(t *testing.T, path string, want int) {
	t.Helper()
	m, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	seenT, seenV := map[string]bool{}, map[string]bool{}
	for _, e := range m.Entries() {
		if seenT[e.Token] || seenV[e.Value] {
			t.Fatalf("duplicate entry %+v", e)
		}
		seenT[e.Token], seenV[e.Value] = true, true
	}
	if m.Len() != want {
		t.Fatalf("got %d entries, want %d", m.Len(), want)
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add("客戶：王小明 A123456789 0912-345-678 NT$1,000")
	f.Add("x@y.co ⟦")
	f.Fuzz(func(t *testing.T, s string) {
		if strings.Contains(s, "⟦") {
			return // input that already contains placeholders is not round-trippable by design
		}
		m := New()
		masked, _ := m.Mask(strict, s)
		back, _, _ := m.Unmask(masked)
		if back != s {
			t.Fatalf("%q -> %q -> %q", s, masked, back)
		}
	})
}
