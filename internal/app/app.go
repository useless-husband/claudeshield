// Package app wires the packages together the same way for the CLI and for
// the hooks, so `claudeshield check` and a hook see identical results.
package app

import (
	"path/filepath"

	"github.com/useless-husband/claudeshield/internal/audit"
	"github.com/useless-husband/claudeshield/internal/config"
	"github.com/useless-husband/claudeshield/internal/hook"
	"github.com/useless-husband/claudeshield/internal/preflight"
	"github.com/useless-husband/claudeshield/internal/settings"
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

// PreflightOptions builds the full check set.
func PreflightOptions(p config.Paths, g config.Global, cwd string, network bool) preflight.Options {
	return preflight.Options{
		Paths: p, Global: g, Cwd: cwd, Network: network,
		Audit: func(cwd string) []preflight.Finding {
			return audit.Findings(audit.Options{Paths: p, Cwd: cwd, Self: Self(g)})
		},
		HooksInstalled: func() (bool, string) { return settings.Installed(UserSettings(p)) },
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
			return preflight.Run(PreflightOptions(p, g, cwd, true))
		},
	}
}
