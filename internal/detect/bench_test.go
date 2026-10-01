package detect

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// corpus builds about n bytes of mixed text: code, Chinese prose, a CSV
// block, and sensitive values at a realistic density (roughly one per line
// of data, none in the code).
func corpus(n int) string {
	r := rand.New(rand.NewSource(1))
	var b strings.Builder
	code := "func handler(w http.ResponseWriter, r *http.Request) {\n\tif err := json.NewDecoder(r.Body).Decode(&req); err != nil {\n\t\treturn\n\t}\n}\n"
	prose := "本季營運狀況穩定，業務部與研發部持續合作，預計下個月完成第二階段的系統整合與測試。\n"
	b.WriteString("name,national_id,phone,email,amount\n")
	for b.Len() < n {
		switch r.Intn(4) {
		case 0:
			b.WriteString(code)
		case 1:
			b.WriteString(prose)
		default:
			fmt.Fprintf(&b, "王小明,A123456789,0912-%03d-%03d,user%d@corp.com.tw,NT$%d\n", r.Intn(1000), r.Intn(1000), r.Intn(1e6), r.Intn(1e7))
		}
	}
	return b.String()
}

func benchFind(b *testing.B, p Profile, size int) {
	s := corpus(size)
	d := New(Config{Profile: p, Allow: DefaultAllow, Terms: map[string][]string{"CLIENT": {"Acme Holdings", "台積電"}}})
	b.SetBytes(int64(len(s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Find(s)
	}
}

func BenchmarkFindBasic100KB(b *testing.B)  { benchFind(b, Basic, 100<<10) }
func BenchmarkFindStrict100KB(b *testing.B) { benchFind(b, Strict, 100<<10) }

// A workspace that has seen many values matches each of them literally.
func BenchmarkFindStrict100KBWith2000Known(b *testing.B) {
	s := corpus(100 << 10)
	terms := map[string][]string{}
	for i := 0; i < 2000; i++ {
		terms["EMAIL"] = append(terms["EMAIL"], fmt.Sprintf("known%d@corp.com.tw", i))
	}
	d := New(Config{Profile: Strict, Terms: terms})
	b.SetBytes(int64(len(s)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Find(s)
	}
}
