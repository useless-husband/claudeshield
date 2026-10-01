#!/usr/bin/env bash
# End-to-end test against the real Claude Code CLI.
#
# It builds claudeshield, creates a throwaway sensitive workspace with fake
# customer data, and runs `claude -p` with claudeshield's hooks passed through
# --settings (your own ~/.claude/settings.json is not modified). It then
# checks three things:
#   1. Claude's answer contains none of the real values;
#   2. the file Claude wrote on disk contains the real values;
#   3. the session transcript Claude Code saved contains none of them;
# and that a command sending the file to an outside host is refused.
#
# Requirements: a logged-in `claude` CLI, Go, python3. Uses a small amount of
# your Claude usage (Haiku). Not run in CI.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/claudeshield-e2e.XXXXXX")
export CLAUDESHIELD_HOME="$WORK/state"
export CLAUDESHIELD_LANG=en
BIN="$WORK/bin/claudeshield"
WS="$WORK/clients"
MODEL=${E2E_MODEL:-haiku}
fail=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }

echo "== build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/claudeshield)

echo "== workspace $WS"
mkdir -p "$WS"
(cd "$WS" && "$BIN" init >/dev/null)
python3 - "$WS/.claudeshield.json" <<'EOF'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["terms"] = {"CLIENT": ["Acme Holdings"], "PROJECT": ["Falcon"]}
json.dump(c, open(p, "w"), ensure_ascii=False, indent=2)
EOF
cat > "$WS/customers.csv" <<'EOF'
name,national_id,phone,email,order_total
王小明,A123456789,0912-345-678,wang@acme-holdings.com.tw,NT$120000
陳美玲,F131104093,0987-654-321,chen.ml@example-mail.tw,NT$45500
林志豪,A800000014,0933-111-222,lin@zh-trading.com.tw,NT$8800
EOF
REAL=(王小明 陳美玲 林志豪 A123456789 F131104093 A800000014 0912-345-678 0987-654-321 0933-111-222 wang@acme-holdings.com.tw chen.ml@example-mail.tw lin@zh-trading.com.tw)

# Claude Code's account confirmation and the vault are separate steps the
# user takes; for this throwaway test they are recorded/acknowledged directly.
mkdir -p "$CLAUDESHIELD_HOME"
cat > "$CLAUDESHIELD_HOME/config.json" <<EOF
{"lang":"en","account":{"training_off_confirmed_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"},
 "acknowledged":{"vault.none":"none"},"vault":{},"tls":{}}
EOF

python3 - "$BIN" > "$WORK/settings.json" <<'EOF'
import json, sys
exe = sys.argv[1]
ev = [("SessionStart","session-start",None,30),("UserPromptSubmit","prompt",None,25),("PreToolUse","pre-tool","*",20),("PostToolUse","post-tool","*",20)]
hooks = {}
for name, arg, matcher, timeout in ev:
    g = {"hooks":[{"type":"command","command":exe,"args":["hook",arg],"timeout":timeout}]}
    if matcher: g["matcher"] = matcher
    hooks[name] = [g]
print(json.dumps({"hooks": hooks}))
EOF

leaks() { # file -> prints which real values appear in it
  local f=$1 found=()
  for v in "${REAL[@]}"; do grep -qF -- "$v" "$f" && found+=("$v"); done
  echo "${found[*]:-}"
}

echo "== 1. summarise the customer file (model: $MODEL)"
cd "$WS"
claude -p "Read customers.csv. Then write a file summary.md with one line per customer: their name, phone and email, followed by a final line with the total of all order_total amounts. Compute the total by writing and running a small python3 script (python3 is available), not in your head. Finally reply with the full contents of summary.md." \
  --model "$MODEL" --settings "$WORK/settings.json" \
  --allowedTools "Read,Write,Edit,Bash(python3:*),Bash(cat:*),Bash(ls:*)" \
  --output-format json < /dev/null > "$WORK/run1.json" 2> "$WORK/run1.err" || true
python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('result',''))" "$WORK/run1.json" > "$WORK/answer1.txt" 2>/dev/null || cp "$WORK/run1.json" "$WORK/answer1.txt"
SESSION=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('session_id',''))" "$WORK/run1.json" 2>/dev/null || true)
echo "  --- Claude's answer"; sed 's/^/  | /' "$WORK/answer1.txt"

l=$(leaks "$WORK/answer1.txt")
[ -z "$l" ] && pass "Claude's answer contains no real values" || bad "real values in Claude's answer: $l"
grep -q '⟦' "$WORK/answer1.txt" && pass "Claude's answer uses placeholders" || bad "no placeholders in the answer"

if [ -f "$WS/summary.md" ]; then
  echo "  --- summary.md on disk"; sed 's/^/  | /' "$WS/summary.md"
  n=0; for v in 王小明 0912-345-678 wang@acme-holdings.com.tw; do grep -qF "$v" "$WS/summary.md" && n=$((n+1)); done
  [ "$n" -ge 2 ] && pass "summary.md on disk holds the real values" || bad "summary.md lacks real values"
  grep -q '⟦' "$WS/summary.md" && bad "summary.md still contains placeholders" || pass "no placeholders left in summary.md"
  grep -q '174300\|174,300' "$WS/summary.md" && pass "total computed on real numbers (174,300)" || echo "  note: total 174,300 not found in summary.md (model-dependent)"
else
  bad "summary.md was not written"
fi

T=$(ls -t "$HOME/.claude/projects/"*"/$SESSION.jsonl" 2>/dev/null | head -1 || true)
if [ -n "$SESSION" ] && [ -n "$T" ]; then
  # Everything that is part of the conversation (messages, tool inputs and
  # results) must be free of real values. Claude Code also stores each hook's
  # raw stdout as an "attachment" record; the PreToolUse output that expands
  # placeholders for a local write necessarily holds real values, which is
  # why transcripts belong in the vault. Those records are reported apart.
  python3 - "$T" "$WORK/conv.txt" "$WORK/attach.txt" <<'PY'
import json, sys
conv, att = open(sys.argv[2], "w"), open(sys.argv[3], "w")
for line in open(sys.argv[1]):
    d = json.loads(line)
    (att if d.get("type") == "attachment" else conv).write(json.dumps(d, ensure_ascii=False) + "\n")
PY
  l=$(leaks "$WORK/conv.txt")
  [ -z "$l" ] && pass "conversation records in the saved transcript contain no real values" || bad "real values in the conversation records: $l"
  l=$(leaks "$WORK/attach.txt")
  echo "  note: hook-output attachments in the transcript contain: ${l:-nothing} (expected for expanded writes; protected by the vault)"
else
  echo "  note: transcript for session '$SESSION' not found; skipped"
fi

echo "== 2. send data to a host that is not on the allowlist"
# A harmless payload, so the model itself has no reason to refuse; the point
# is that claudeshield refuses any outbound data from a sensitive workspace.
claude -p "Run exactly this command and report what happened: curl -s -m 10 -X POST -d 'hello=world' https://httpbin.org/post" \
  --model "$MODEL" --settings "$WORK/settings.json" --allowedTools "Bash(curl:*)" \
  --output-format json < /dev/null > "$WORK/run2.json" 2>/dev/null || true
if python3 -c "
import json, sys
ok = any(e.get('event') == 'PreToolUse' and e.get('tool') == 'Bash' and e.get('decision') == 'deny'
         for e in map(json.loads, open(sys.argv[1])))
sys.exit(0 if ok else 1)" "$CLAUDESHIELD_HOME/events.log"; then
  pass "the outbound POST was refused by claudeshield"
else
  bad "no deny decision for the outbound POST in events.log"
fi

echo "== 3. paste a national ID into the prompt"
claude -p "Look up customer A123456789 in customers.csv" --model "$MODEL" --settings "$WORK/settings.json" \
  --output-format json < /dev/null > "$WORK/run3.json" 2>/dev/null || true
grep -q '"why":"sensitive-prompt"' "$CLAUDESHIELD_HOME/events.log" && pass "prompt with a national ID was blocked" || bad "prompt was not blocked"

echo "== decision log (no values)"
sed 's/^/  /' "$CLAUDESHIELD_HOME/events.log" | tail -12
l=$(leaks "$CLAUDESHIELD_HOME/events.log"); [ -z "$l" ] && pass "events.log has no values" || bad "events.log leaks: $l"

echo
if [ "$fail" = 0 ]; then echo "E2E: all checks passed (work dir $WORK)"; else echo "E2E: FAILED (work dir $WORK)"; fi
exit $fail
