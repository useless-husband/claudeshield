// Package app wires the packages together the same way for the CLI and for
// the hooks, so `claudeshield check` and a hook see identical results.
package app

import (
	"path/filepath"
	"strings"

	"github.com/useless-husband/claudeshield/internal/audit"
	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/hook"
	"github.com/useless-husband/claudeshield/internal/i18n"
	"github.com/useless-husband/claudeshield/internal/preflight"
	"github.com/useless-husband/claudeshield/internal/settings"
	"github.com/useless-husband/claudeshield/internal/vault"
)

// UserSettings is ~/.claude/settings.json.
func UserSettings(p config.Paths) string { return filepath.Join(p.ClaudeDir, "settings.json") }

// Self is the executable the installed hooks point at, or "" if not installed.
func Self(g config.Global) string {
	if g.Installed != nil {
		return g.Installed.Executable
	}
	return ""
}

// DenyRules are the user-level permission rules that keep Claude away from
// claudeshield's state and the vault's claudeshield folder.
func DenyRules(p config.Paths, g config.Global) []string {
	home := config.Canonical(p.Home)
	rules := settings.DenyRules(config.Canonical(p.State), home)
	if vault.Configured(g) {
		rules = append(rules, settings.DenyRules(vault.DataDir(p, g), home)...)
	}
	return rules
}

// PreflightOptions builds the full check set.
func PreflightOptions(p config.Paths, g config.Global, cwd string, network bool) preflight.Options {
	return preflight.Options{
		Paths: p, Global: g, Cwd: cwd, Network: network,
		Audit: func(cwd string) []preflight.Finding {
			return audit.Findings(audit.Options{Paths: p, Cwd: cwd, Self: Self(g)})
		},
		HooksInstalled: func() (bool, string) {
			ok, why := settings.Installed(UserSettings(p), Self(g))
			if missing := settings.HasDeny(UserSettings(p), DenyRules(p, g)); len(missing) > 0 {
				ok, why = false, strings.TrimSpace(why+" "+i18n.Tf("缺少權限規則：%s", "missing permission rules: %s", strings.Join(missing, ", ")))
			}
			return ok, why
		},
	}
}

// Preflight runs every check and applies acknowledgements.
func Preflight(p config.Paths, g config.Global, cwd string, network bool) preflight.Report {
	r := preflight.Run(PreflightOptions(p, g, cwd, network))
	r.ApplyAcks(g.Acknowledged)
	return r
}

// HookEnv is the environment for a hook process.
func HookEnv(p config.Paths, g config.Global, cfgErr error) hook.Env {
	return hook.Env{
		Paths: p, Global: g, ConfigErr: cfgErr,
		Preflight: func(cwd string) preflight.Report {
			// A hook that is running is proof the hooks are active, and they
			// may legitimately come from another settings scope (a project's
			// settings, or --settings), so the install check is a CLI matter.
			o := PreflightOptions(p, g, cwd, true)
			o.HooksInstalled = nil
			return preflight.Run(o)
		},
	}
}
