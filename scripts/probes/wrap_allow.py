#!/usr/bin/env python3
# PreToolUse: wrap Bash commands so failures exit 0 with the status appended,
# and return allow. PostToolUse: mask "ZEBRA-7731".
import json, sys

d = json.load(sys.stdin)
ev = d.get("hook_event_name")
if ev == "PreToolUse" and d.get("tool_name") == "Bash":
    ti = dict(d["tool_input"])
    ti["command"] = "# wrapped\n{ " + ti["command"] + "\n}; __cs=$?; [ $__cs -eq 0 ] || echo \"[exit status $__cs]\"; true"
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": ti}}))
elif ev == "PostToolUse" and isinstance(d.get("tool_response"), dict):
    r = {k: (v.replace("ZEBRA-7731", "⟦SECRET_001⟧") if isinstance(v, str) else v) for k, v in d["tool_response"].items()}
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": r}}, ensure_ascii=False))
