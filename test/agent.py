"""
linkpulse discovery agent.

Given ONLY the root URL, this agent:
  1. Reads / to learn what the service is.
  2. Reads the well-known manifests to understand the tools.
  3. Mints an API key.
  4. Starts a credit purchase and completes it autonomously.
  5. Makes exactly 10 real paid calls across check/diff/resolve/classify,
     including at least one dead URL (to exercise wayback fallback) and
     one redirect (to exercise final_url).
  6. Reports what it learned.

No prior knowledge of the API surface is hard-coded.
Claude Haiku drives every decision via tool-use.
"""
import json
import os
import sys
import urllib.request
import urllib.error
from anthropic import Anthropic

ROOT = "https://linkpulse-neon.vercel.app/"
MODEL = "claude-haiku-4-5-20251001"

client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


def http_request(method: str, url: str, headers: dict | None = None, body: str | None = None, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    data = body.encode("utf-8") if isinstance(body, str) else body
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout) as r:
            raw = r.read().decode("utf-8", errors="replace")
            status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        status = e.code
    except Exception as e:
        return {"status": 0, "error": str(e), "body_text": ""}
    return {"status": status, "body_text": raw[:12000]}


TOOLS = [
    {
        "name": "http_request",
        "description": (
            "Make an HTTP request to linkpulse. Always pass a full https URL. "
            "For POST/JSON, pass headers={'content-type':'application/json','authorization':'Bearer <key>' if needed} and body=<json string>."
        ),
        "input_schema": {
            "type": "object",
            "required": ["method", "url"],
            "properties": {
                "method": {"type": "string", "enum": ["GET", "POST"]},
                "url": {"type": "string"},
                "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                "body": {"type": "string"},
            },
        },
    },
    {
        "name": "report",
        "description": "Final report once 10 paid calls to /v1/check|diff|resolve|classify are done.",
        "input_schema": {
            "type": "object",
            "required": ["summary", "calls_made", "credits_started_with", "credits_remaining", "interesting_findings"],
            "properties": {
                "summary": {"type": "string"},
                "calls_made": {"type": "integer"},
                "credits_started_with": {"type": "integer"},
                "credits_remaining": {"type": "integer"},
                "interesting_findings": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
]

SYSTEM = (
    "You are an autonomous AI agent with NO prior knowledge of the linkpulse service. "
    f"Your ONLY entrypoint is {ROOT}. Discover everything from there. Mission:\n"
    "  1. GET / and the discovery links it returns (/.well-known/ai-plugin.json, /llms.txt) to learn the tools.\n"
    "  2. POST /v1/keys for a free key with 100 credits.\n"
    "  3. POST /v1/credits {\"pack\":\"starter\"} with your key, then GET the returned payment_url to pay autonomously.\n"
    "  4. Make exactly 10 real PAID calls. Spread them across /v1/check, /v1/diff, /v1/resolve, /v1/classify. INCLUDE:\n"
    "     - at least one /v1/check on a known-working page (e.g. https://example.com, https://httpbin.org/get, https://jsonplaceholder.typicode.com/users/1)\n"
    "     - at least one /v1/check on a known-404 page (e.g. https://httpbin.org/status/404, https://github.com/this-repo-definitely-does-not-exist-12345) so you see the wayback fallback\n"
    "     - at least one /v1/resolve on a redirecting URL (e.g. http://github.com or https://httpbin.org/redirect-to?url=https://example.com)\n"
    "     - at least one /v1/diff re-checking a URL with a prior hash from an earlier /v1/check\n"
    "     - at least one /v1/classify call passing pre-fetched content (you can invent status/content_type/body_sample)\n"
    "  5. Call report with a summary and interesting_findings (classifications you saw, whether wayback fallback appeared, any drift detected).\n"
    "Only use tools. Never invent URLs beyond the starting root and legitimate public URLs to test against. Stop after calling report."
)


def run() -> int:
    messages = [{"role": "user", "content": f"Begin. Start by GETting {ROOT}."}]
    turns = 0
    max_turns = 40
    transcript = []
    final_report = None
    while turns < max_turns and final_report is None:
        turns += 1
        resp = client.messages.create(
            model=MODEL,
            max_tokens=2048,
            system=SYSTEM,
            tools=TOOLS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})
        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            break
        tool_results = []
        for tu in tool_uses:
            name, args = tu.name, tu.input
            if name == "report":
                final_report = args
                tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": "OK"})
                continue
            if name == "http_request":
                result = http_request(
                    method=args.get("method", "GET"),
                    url=args["url"],
                    headers=args.get("headers"),
                    body=args.get("body"),
                )
                trimmed = (result.get("body_text") or "")[:4000]
                tool_results.append({"type": "tool_result", "tool_use_id": tu.id, "content": json.dumps({"status": result.get("status"), "body": trimmed})})
                transcript.append({
                    "turn": turns,
                    "method": args.get("method"),
                    "url": args.get("url"),
                    "status": result.get("status"),
                    "body_preview": trimmed[:300],
                })
        messages.append({"role": "user", "content": tool_results})

    print("=" * 72)
    print("TRANSCRIPT")
    print("=" * 72)
    for i, t in enumerate(transcript, 1):
        print(f"[{i:02d}] {t['method']} {t['url']}  ->  HTTP {t['status']}")
        if t.get("body_preview"):
            print("     " + t["body_preview"].replace("\n", " ")[:220])
    print()
    print("=" * 72)
    print("FINAL REPORT")
    print("=" * 72)
    if final_report:
        print(json.dumps(final_report, indent=2))
    else:
        print("Agent ended without calling report tool. Turns used:", turns)
    print("=" * 72)
    print(f"turns={turns} total_http_calls={len(transcript)}")
    return 0 if final_report else 2


if __name__ == "__main__":
    sys.exit(run())
