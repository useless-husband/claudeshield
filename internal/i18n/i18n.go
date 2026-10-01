// Package i18n picks between Traditional Chinese and English messages.
//
// Every user-facing string in claudeshield is written twice, inline, at the
// call site: T("中文", "English"). That keeps the two versions next to each
// other in review and avoids a separate catalogue drifting out of date.
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	mu   sync.RWMutex
	lang = fromEnv()
)

func fromEnv() string {
	if v := os.Getenv("CLAUDESHIELD_LANG"); v != "" {
		return normalize(v)
	}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && v != "C" && v != "POSIX" {
			return normalize(v)
		}
	}
	return "en"
}

func normalize(v string) string {
	if strings.HasPrefix(strings.ToLower(v), "zh") {
		return "zh"
	}
	return "en"
}

// Set overrides the language ("zh" or "en"). An explicit CLAUDESHIELD_LANG in
// the environment still wins, so a user can flip one run without editing config.
func Set(v string) {
	if os.Getenv("CLAUDESHIELD_LANG") != "" || v == "" {
		return
	}
	mu.Lock()
	lang = normalize(v)
	mu.Unlock()
}

// Lang reports the active language.
func Lang() string {
	mu.RLock()
	defer mu.RUnlock()
	return lang
}

// T returns zh or en depending on the active language.
func T(zh, en string) string {
	if Lang() == "zh" {
		return zh
	}
	return en
}

// Tf is T followed by fmt.Sprintf.
func Tf(zh, en string, args ...any) string {
	return fmt.Sprintf(T(zh, en), args...)
}
