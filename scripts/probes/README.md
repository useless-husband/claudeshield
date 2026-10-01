# Platform probes

Small hooks used to establish how Claude Code treats hook output. Each one is
run with `claude -p ... --settings <file>` in a scratch directory; none touches
your own settings. They were run against Claude Code v2.1.287; rerun them
after upgrading Claude Code to see whether the behaviour ClaudeShield relies
on still holds.

| Probe | Question | Observed on v2.1.287 |
| --- | --- | --- |
| `rewrite.py` | Is `updatedInput` applied without a `permissionDecision`? Does `updatedToolOutput` change what Claude sees for Bash and Read? | Yes and yes; the transcript stores the replaced output |
| `failure.py` | Can a PostToolUseFailure hook stop the turn with `"continue": false`? | No: Claude still received the failed command's output |
| `wrap_allow.py` | In a sandboxed folder, does a wrapped command returned with `allow` run, mask failures, and stay sandboxed? | Yes, yes, yes (a request to example.com was still denied by the sandbox) |

Run one:

```sh
cd "$(mktemp -d)"
python3 - <<'PY'
import json, os
probe = os.path.abspath("PATH/TO/scripts/probes/rewrite.py")
hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": probe}]}],
         "PostToolUse": [{"matcher": "Bash|Read", "hooks": [{"type": "command", "command": probe}]}]}
json.dump({"hooks": hooks}, open("settings.json", "w"))
PY
echo "the code word is SECRETVALUE" > note.txt
claude -p "Run exactly: echo ALPHA. Then read note.txt. Reply with the bash output and the file content." \
  --model haiku --settings "$PWD/settings.json" --allowedTools "Bash(echo:*),Read" < /dev/null
# expected: BRAVO, and "the code word is ⟦X_001⟧"
```

`wrap_allow.py` needs `.claude/settings.local.json` with
`{"sandbox": {"enabled": true, "allowUnsandboxedCommands": false}}` in the
scratch directory, and hooks for PreToolUse, PostToolUse and
PostToolUseFailure on `Bash`.
