#!/usr/bin/env python3
# PreToolUse: rewrite "ALPHA" to "BRAVO" in Bash commands, with no permissionDecision.
# PostToolUse: replace "SECRETVALUE" with a placeholder in Bash and Read results.
import json, sys

d = json.load(sys.stdin)
if d.get("hook_event_name") == "PreToolUse" and d.get("tool_name") == "Bash":
    ti = dict(d["tool_input"])
    ti["command"] = ti["command"].replace("ALPHA", "BRAVO")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "updatedInput": ti}}))
elif d.get("hook_event_name") == "PostToolUse":
    def walk(v):
        if isinstance(v, str):
            return v.replace("SECRETVALUE", "⟦X_001⟧")
        if isinstance(v, dict):
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": walk(d["tool_response"])}}, ensure_ascii=False))
