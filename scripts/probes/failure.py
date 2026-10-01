#!/usr/bin/env python3
# PostToolUseFailure: try to stop the turn when a failed command printed a secret.
# Run with a script that prints "ZEBRA-7731" and exits non-zero, and ask Claude
# to report what it printed. On v2.1.287 Claude still reports the code.
import json, sys

d = json.load(sys.stdin)
if d.get("hook_event_name") == "PostToolUseFailure" and "ZEBRA-7731" in (d.get("error") or ""):
    print(json.dumps({"continue": False, "stopReason": "stopped: a failed command printed a secret"}))
