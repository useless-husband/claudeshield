# Design

This document explains how ClaudeShield is put together, which problems were hard, and which approaches were tried and dropped.

## Goal and threat model

The goal is narrow: let a person give Claude Code real working files (customer lists, contracts, finance sheets, code with credentials) while keeping the sensitive values in them on the machine.

ClaudeShield defends against:

1. **The provider receiving the values.** Whatever reaches the API is processed and retained on the provider's side under the account's terms. Masking means the values never reach it.
2. **Redirection and interception of the connection.** An `ANTHROPIC_BASE_URL` or proxy variable planted in a shell profile or in a repository's `.claude/settings.json`; a root certificate installed on the Mac that lets a proxy decrypt TLS; DNS or `/etc/hosts` pointing `api.anthropic.com` elsewhere.
3. **Data at rest.** Claude Code writes transcripts, pre-edit file snapshots and prompt history to `~/.claude` in plaintext.
4. **Data leaving through tools.** A command Claude runs (on its own or after a prompt injection) that uploads files, posts data, opens a socket, encodes data into DNS lookups, or publishes to GitHub.
5. **Quiet changes to what can see the conversation.** A plugin update adding a hook, a cloned repository's `.mcp.json`, an edited skill.

It does not defend against a compromised operating system or user account, against someone watching the screen, or against the provider's handling of what is sent anyway. Pattern-based detection misses what it has no pattern for; the README's limitations list is part of the design, not an afterthought.

## Architecture

```
cmd/claudeshield      CLI: check, run, install, init, scan, mask/unmask, vault, audit, ...
internal/app          wires the packages the same way for the CLI and the hooks
internal/hook         SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, MessageDisplay
internal/detect       what is sensitive (regex + validators + tables + names + Aho–Corasick terms)
internal/tokenmap     value <-> placeholder table, flock + atomic replace
internal/egress       shell lexer and per-program outbound analysis
internal/preflight    environment, settings, trust store, DNS, pinned TLS, account, vault checks
internal/audit        inventory of extensions and the approved baseline
internal/vault        hdiutil sparse bundle, migration with symlinks
internal/settings     editing Claude Code settings: install/uninstall, workspace sandbox rules
internal/config       paths, global config, workspace marker, canonical paths
```

Every hook invocation is a fresh process: Claude Code writes a JSON object to stdin and reads one from stdout. State that must survive between invocations lives in files: the token table (in the vault), the per-session preflight report (`~/.claudeshield/sessions`), and an append-only decision log that records what happened but never a value.

### Two modes

- **Ordinary sessions** run the *Basic* detector: vendor-format API keys, private keys, JWTs, connection-string passwords, `.env`-style secrets. This catches the common accident (Claude reads a `.env`) with very few false positives, which matters because it runs on every tool call in every project.
- **Sensitive workspaces** are folders with a `.claudeshield.json` marker. They run the *Strict* detector (all categories), require a vault, turn on Claude Code's sandbox with no unsandboxed escape hatch, refuse binary reads and `@` mentions, and treat outbound data as a denial rather than a question.

## The masking round trip

PostToolUse receives a tool's structured result (`{"type":"text","file":{"content":...}}` for Read, `{"stdout":...,"stderr":...}` for Bash). ClaudeShield walks the JSON and masks every string leaf, leaving keys, numbers and booleans untouched, so the result keeps the shape Claude Code validates; values under a `base64` key and image results are skipped. The masked structure goes back as `updatedToolOutput`.

PreToolUse does the reverse for tools whose effect stays on the machine: `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Glob`, `Grep`, `LS`, and shell commands that do not reach the network. Placeholders in their input are replaced with the real values and returned as `updatedInput`. A placeholder that is not in the table (Claude invented one) makes `Write`/`Edit` fail with a reason, rather than writing `⟦PHONE_009⟧` into a file. Placeholders are never expanded for `WebFetch`, `WebSearch` or MCP tools.

### Placeholders

`⟦KIND_NNN⟧` uses the mathematical white square brackets (U+27E6/U+27E7). They are vanishingly rare in real text, survive being copied by the model, and are easy to match. The kind tells Claude what the value is (`NAME`, `AMOUNT`), which keeps its answers useful. Numbering is per kind and per workspace, and the same value always gets the same placeholder, so Claude can still see that two documents mention the same customer.

### Idempotence and the fixpoint

Masking must be idempotent: Claude Code may hand a tool result containing placeholders back through a hook. The detector never reports anything overlapping a placeholder. That turned out not to be enough. In `NT$1,000sk-ant-…`, the key has no word boundary before it, so it is not detected; after the amount becomes `⟦AMOUNT_001⟧`, it is. A property test found this. `Mask` therefore repeats until nothing more is found. Each pass only shrinks the unmasked text, so it terminates; the loop has a cap of 8 as a guard.

### Remembering values

A name detected because it follows `客戶：` must stay masked when it later appears alone in a file listing. Every value in the token table (except amounts and very short values, which would mask unrelated text as bare literals) is therefore added to the detector as a literal term. A busy workspace has thousands, so matching them one by one cost O(terms × text): 227 ms on a 100 KB CSV. An Aho–Corasick automaton built per process (compact sorted edge slices, not 256-entry tables) brought that to 78 ms, most of which is now reading and writing the table.

### Concurrency

Claude Code runs matching hooks in parallel and may issue parallel tool calls, so several hook processes can update the same table at once. Every update takes an exclusive `flock` on a sibling `.lock` file, re-reads the table, applies changes, and replaces the file with write-to-temp + `fsync` + `rename`. The lock file is never deleted, because deleting it while another process waits would admit two writers. A test starts six processes that each add 30 values and checks that all 180 survive with unique placeholders.

## Detection

Regular expressions with validators do most of the work: the Taiwan national ID check digit, the UBN checksum (the 2023 "divisible by 5" rule, with the special case for a 7 in the seventh digit), Luhn for cards, octet ranges for private IPv4. Credential rules filter placeholders and references (`${SECRET}`, `os.environ[...]`, `changeme`) and low-entropy strings.

Names are the hard part: Chinese names have no pattern. Three heuristics cover the common business cases:

- **Table columns.** A CSV, TSV or Markdown table whose header names a sensitive field (`姓名`, `name`, `電話`, `金額`, `email`, …) has every cell in that column masked. Cells are split with quote awareness, so `"Lee, Ann"` is one cell.
- **Standalone runs.** Chinese prose does not separate words, so a run of exactly three Han characters with nothing Han on either side mostly occurs in lists, headers and tables. If it starts with one of ~100 common surnames and does not end in a character that ends place names and nouns (市, 路, 部, 碼, 價, …), it is reported. Two-character runs are not, because too many ordinary words (林業, 高雄) start with a surname character.
- **Titles.** A two-to-four character run directly before 先生, 小姐, 經理, 醫師 and similar, starting with a surname.

Everything else is the user's `terms` list, which is matched literally and case-insensitively for ASCII.

### Making it fast

Profiling showed the regexp engine's NFA dominating: every rule scanned the whole text. Two changes made the Strict detector nine times faster:

1. Rules (except the multi-line private key rule) run per line, which keeps inputs small.
2. Each rule declares literals of which at least one must appear in the line (`@` for e-mail, `號` for addresses, `sk-ant-` for Anthropic keys) and an optional minimum digit run. Most lines fail these `strings.Contains` checks and never reach the regexp.

## The failed-command problem

This took the most iterations, and every step was established by running Claude Code, not by reading documentation.

1. A command that exits non-zero is reported through **PostToolUseFailure**, not PostToolUse. Its documented output fields do not include a replacement for the error text, so a failing `python3 report.py` that prints a customer's ID before crashing would show it to Claude unmasked.
2. **Can the hook stop the turn instead?** The probe `scripts/probes/failure.py` returns `"continue": false` from PostToolUseFailure. Claude still received the output and repeated the secret: the field is ignored on that event.
3. **Make failures look like successes.** Wrap the command so it always exits 0 and appends its real status. The first version used `trap '…' EXIT` (which also catches an explicit `exit N`). Claude Code's Bash tool refused it outright: *"'trap' evaluates arguments as shell code"*.
4. **A brace group with `$?`** passed the shell's tests but Claude Code's permission parser could not trace it: *"Part of this command (a group of commands in braces or double parentheses) cannot be checked in advance"*, and a version without braces failed the same way on the variable. Every wrapped command would need a manual approval.
5. **Return `allow` for the wrapped command, but only where that grants nothing.** Inside a workspace whose sandbox is enabled, has no unsandboxed escape hatch, auto-allows sandboxed commands (the default), and excludes no commands from the sandbox at any settings level, Claude Code already runs every command without a prompt, confined by the OS sandbox. Returning `allow` there changes nothing about who approves what; deny and ask rules are still evaluated after a hook's allow. `scripts/probes/wrap_allow.py` confirmed that the wrapped command runs, its failure output is masked, and the sandbox still blocks a request to a host outside the allowlist.

So: inside a properly set-up workspace, failures are masked; outside one, commands are not wrapped and failures are a documented gap. A workspace whose sandbox is not set up fails its preflight.

## Egress analysis

`internal/egress` has a small shell lexer: single and double quotes, backslash escapes, `$(…)`, backticks, `<(…)`, `$VAR`, `$'…'`, comments, redirections and here-documents. Text computed at run time becomes a sentinel byte; a URL or host containing it is *dynamic*, which is how data is usually smuggled into a request.

Each program has a rule that answers two questions: where does it connect, and does it send data or only fetch? `curl -d`, `-F`, `-T`, `--json`, a non-GET `-X`; `wget --post-*`; `http POST` with fields; `nc`, `socat`, `ssh`, `scp`, `rsync host:`; `mail`; DNS tools given a label of 25+ characters or a dynamic one; URLs whose path or query holds a long high-entropy segment; `git push`; non-read-only `gh`; `npm publish` and friends; cloud copy commands; interpreter one-liners and here-documents that use network APIs. Wrappers (`sudo`, `env`, `nohup`, `timeout`, `xargs`, …) are unwrapped; `sh -c` and `eval` are analysed recursively; decode-and-run and download-and-run pipelines and ANSI-C escapes are flagged as obfuscation.

The decision table:

| Situation | Ordinary session | Sensitive workspace |
| --- | --- | --- |
| Placeholders + network + any host off the allowlist | deny | deny |
| Placeholders + network, all hosts allowed | expand, normal flow | expand, ask |
| Obfuscated | ask | deny |
| Sends data to a host off the allowlist | ask | deny |
| Publishes (git push, gh create, npm publish) | normal flow | ask |
| Fetches from a host off the allowlist | normal flow | ask |

In a workspace this is a second layer: the sandbox enforces the network allowlist at the OS level whatever the analysis concludes. Outside a workspace it is the only layer, and it is best effort.

## Preflight

The checks run at SessionStart, again on a prompt when the cached report is older than ten minutes or last failed (so a fix is noticed on the next prompt), and before launch with `claudeshield run`. Each finding has a stable ID, a severity, a fix written for a person, and for acknowledgeable findings a fingerprint of the underlying value. `claudeshield ack <id>` stores the fingerprint; if the value changes (a different proxy, a new root certificate), the finding blocks again. Some findings cannot be acknowledged at all: TLS verification disabled, `SSLKEYLOGFILE`, a closed vault, unapproved extensions.

**TLS pinning.** ClaudeShield completes a handshake with `api.anthropic.com`, takes the server's chain, and verifies it with Go's `x509` against an embedded pool of five roots (GTS Root R1–R4 and GlobalSign Root CA, exported from the macOS system root store) instead of the system trust store. A root added to the keychain by an inspecting proxy is exactly what the system store would accept and the pinned pool rejects. If Anthropic changes certificate authority, the check blocks; `claudeshield tls trust` re-pins only after the chain also verifies against the system store and the user confirms, from a second network, that the change is real.

**Address ranges.** The DNS answers and the connected peer must fall in Anthropic's published API ranges (160.79.104.0/23 and 2607:6bc0::/48).

**Account.** `~/.claude.json` tells consumer plans from commercial ones. The consumer "Help improve Claude" switch lives on the website and cannot be read locally, so a sensitive workspace on a consumer plan requires the user's own confirmation, renewed every 30 days.

## The vault

An AES-256 encrypted, APFS-formatted sparse bundle made with `hdiutil`. Sparse bundles are stored as many small band files, so Time Machine copies only changed bands, all of them ciphertext. A test writes a marker string inside the mounted volume, detaches it, and checks that no band contains it.

Migration moves Claude Code's data directories (`projects`, `file-history`, `plans`, `paste-cache`, `shell-snapshots`, …) and `history.jsonl` into the vault and leaves symlinks. Per item: copy to `<name>.partial`, compare file count and bytes, rename into place, move the original aside, create the link, delete the original. A failure at any step leaves either the original in place or the verified copy linked.

The useful property is what happens when the vault is closed. The links point into `/Volumes/ClaudeVault`, and `/Volumes` belongs to root, so no ordinary process can create the missing directory: writes fail instead of silently creating plaintext files. The test suite verifies this with a real image.

## Verified platform behaviour

ClaudeShield depends on details of Claude Code's hook contract. These were checked against v2.1.287 with the probes in `scripts/probes` and the end-to-end script:

| Behaviour | Evidence |
| --- | --- |
| `updatedInput` without `permissionDecision` is applied, and permission rules are evaluated against it | `rewrite.py`: `echo ALPHA` ran as `echo BRAVO` under an `echo` allow rule |
| `updatedToolOutput` replaces what Claude sees for Read and Bash | `rewrite.py`: Claude reported `the code word is ⟦X_001⟧` |
| The transcript stores the replaced tool output | `e2e.sh` scans the transcript's conversation records |
| The transcript also stores each hook's raw stdout as an attachment record | found while running `e2e.sh`; why the vault matters even with masking |
| PostToolUseFailure cannot stop the turn | `failure.py` |
| Bash rejects `trap`; `{ }` and `$?` cannot be pre-checked | e2e runs before the sandbox-gated wrapper |
| A wrapped command with `allow` in a strict sandbox runs, masks failures, stays confined | `wrap_allow.py` |
| `@file` mentions are inlined without tool calls | Claude Code documentation; ClaudeShield refuses them in workspaces |

## Approaches rejected

- **A TLS-terminating proxy in front of the API.** It would see and rewrite everything, but it requires installing a root certificate (the very thing preflight treats as an attack), breaks with certificate pinning, and would need to understand the streaming API protocol. Hooks see structured tool data with clear semantics.
- **An LLM or NER model for detection.** Better recall on free-text names, but hooks run on every tool call; a model adds hundreds of milliseconds and a large dependency. Patterns plus user terms keep it a single ~6 MB binary running in single-digit milliseconds.
- **Masking file contents on disk** (keeping a masked working copy and syncing back). Two copies drift, and Claude's edits would have to be merged back. Masking at the hook boundary keeps one copy.
- **Failing open everywhere.** A bug in a security hook that silently allows is worse than one that refuses. ClaudeShield fails closed inside workspaces (a prompt or tool call it could not inspect does not go through) and open elsewhere with a visible warning, so a bug cannot freeze every session on the machine.

## Self-review findings

After the first complete version, the code was reread as an attacker would read it. Each finding below was fixed and has a regression test.

| Finding | Fix |
| --- | --- |
| A command that expands placeholders can print a *transformed* copy of the values (`echo ⟦ID_001⟧ \| base64`, `cut -c1-3`, a string comparison), which no pattern recognises | `egress` marks encoders, slicers, hashes, comparisons and inline interpreter code as *Transform*; with placeholders in the command it is refused in a workspace and confirmed elsewhere. The detector also decodes base64 and hex runs in results and masks those that decode to something sensitive |
| Uploads to an allowlisted host (`curl -d @file https://api.github.com/gists`) passed silently in a workspace | Any command that sends or publishes data from a workspace asks, whatever the host |
| Background commands write their output to a file outside the workspace, which is then read with `Read` under the ordinary profile (`scripts/probes/background.py`) | A workspace session masks strictly whatever it reads, wherever the file is, and keeps commands in the foreground |
| A session started outside a workspace could read the workspace's files with weaker rules | `init` registers workspaces; a session outside one may not touch its files |
| A protected folder named after a client reached the hook as `⟦CLIENT_001⟧/…` and escaped the path check | Path checks run on the expanded input |
| A symlink inside the workspace pointing at a protected file, created by a background command between check and read | Symlinks under the workspace root are not followed at all |
| An image or PDF with a text extension is returned as an image, which masking skips | Files are sniffed by signature, not only by extension |
| `pbcopy` and scripted applications (`osascript … tell app "Mail"`) leave the machine without a network command | Treated as outbound data |
| Go code such as `name, err := f()` followed by a similar line looked like a two-column table with a `name` header | Header cells must look like labels: short, no operators or brackets |
| A handler whose command *began* with the installed path (`…/claudeshield hook pre-tool; curl …`) counted as ClaudeShield's own, so the audit skipped it and `Installed` accepted it | Exact exec-form match: the installed path and `["hook", <event>]` |
| Any disk image attached under the vault's name passed as the vault | A random identity written into the vault at creation and checked on every mount; preflight also asks `hdiutil` which image backs the mount point |
| Missing hooks were only a warning, so `claudeshield run` would start Claude Code with nothing enforcing anything inside | A blocking finding that cannot be acknowledged |
| Edits to settings during a session (`disableAllHooks`, a redirecting `env`, hooks removed, a workspace's sandbox turned off) took effect immediately | A `ConfigChange` hook keeps such edits from applying to the running session; preflight reports them at the next start |
| Claude's file tools could reach `~/.claudeshield` from an ordinary session through a differently spelled path | `install` adds `Read`/`Edit` deny rules for the state directory and the vault's folder, which Claude Code applies to its file tools, `@` mentions and recognised shell file commands |
| A panic inside the PostToolUse hook would let the original result through | The hook recovers and returns the result with every string blanked |
| `claudeshield init` in the home directory would make everything a workspace | Refused, as are ClaudeShield's and Claude Code's own folders |

Two findings are limits rather than fixes, and are stated in the README: a script that reads the real files locally can print any derived form of them (a total, a first character), and the Spotlight index, APFS snapshots and the per-session scratch directory under the system temp folder can hold plaintext that the vault does not cover.
