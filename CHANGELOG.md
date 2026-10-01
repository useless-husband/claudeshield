# Changelog

## v0.1.0 — 2026-10-02

First release.

- Masking round trip: PostToolUse replaces sensitive values in tool results with placeholders; PreToolUse restores them for local tools only; MessageDisplay restores them on screen.
- Detection: credentials, Taiwan national IDs and resident certificates, UBNs, cards, phones, addresses, e-mail, amounts, companies, table columns, name lists, names before titles, user terms; values seen once are re-matched with Aho–Corasick.
- Prompt checks: refuse prompts while a safety check fails, prompts with sensitive values (offering a masked version), `@` file mentions and Remote Control in sensitive workspaces.
- Egress analysis for shell commands and URLs; placeholders are never expanded into network commands to hosts off the allowlist.
- Preflight: redirects and proxies in the environment and every settings scope, disabled TLS verification, `SSLKEYLOGFILE`, injected libraries, system proxies, user-trusted roots, packet capture, remote-desktop tools, DNS and peer address against Anthropic's ranges, TLS chain against pinned roots, account terms.
- Encrypted vault (AES-256 sparse bundle) for Claude Code's transcripts with verified migration and restore.
- Extension audit with content hashes and an approved baseline.
- Sensitive workspaces: `claudeshield init` turns on Claude Code's sandbox without the unsandboxed escape hatch and denies reads of protected paths and ClaudeShield's own state; shell commands are wrapped so failed output is masked too.
