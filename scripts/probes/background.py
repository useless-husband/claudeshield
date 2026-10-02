#!/usr/bin/env python3
import json, sys, os
d = json.load(sys.stdin)
log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bg.log")
ev = d.get("hook_event_name")
open(log, "a").write(json.dumps({"ev": ev, "tool": d.get("tool_name"), "bg": (d.get("tool_input") or {}).get("run_in_background"), "resp": str(d.get("tool_response"))[:300]}, ensure_ascii=False) + "\n")
if ev == "PostToolUse" and isinstance(d.get("tool_response"), dict):
    r = {k: (v.replace("ZEBRA-7731", "⟦SECRET_001⟧") if isinstance(v, str) else v) for k, v in d["tool_response"].items()}
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": r}}, ensure_ascii=False))
