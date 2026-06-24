import json
from typing import Any

def stdout_text(result: Any) -> str:
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    if isinstance(result, bytes):
        return result.decode("utf-8", "replace")
    for attr in ("stdout", "output", "text", "stdout_text"):
        val = getattr(result, attr, None)
        if isinstance(val, (str, bytes)):
            return val.decode("utf-8", "replace") if isinstance(val, bytes) else val
    if isinstance(result, dict):
        for key in ("stdout", "output", "text"):
            if isinstance(result.get(key), str):
                return result[key]
    return str(result)

def last_json(text: str) -> dict:
    depth, end = 0, -1
    for i in range(len(text) - 1, -1, -1):
        c = text[i]
        if c == "}":
            if depth == 0:
                end = i
            depth += 1
        elif c == "{":
            depth -= 1
            if depth == 0 and end != -1:
                try:
                    return json.loads(text[i:end + 1])
                except json.JSONDecodeError:
                    end = -1
                    depth = 0
    return {}

def parse_verdict(text: str) -> dict:
    verdict = last_json(text)
    if not verdict or "score" not in verdict:
        return {"score": 0.0, "full_pass": False, "error": "unparseable verifier output"}
    try:
        verdict["score"] = max(0.0, min(1.0, float(verdict["score"])))
    except (TypeError, ValueError):
        verdict["score"] = 0.0
    return verdict
