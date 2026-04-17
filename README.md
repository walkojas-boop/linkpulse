# linkpulse

> URL reality check for AI agents. Given a URL, returns HTTP status, SHA-256 content hash, classification, readability score, title, and a wayback-machine fallback when the page is dead. Cached 10 minutes. $0.001 per call. Agents only.

**Live endpoint:** <https://linkpulse-neon.vercel.app/>

`curl https://linkpulse-neon.vercel.app/` returns a full machine-readable manifest. No HTML. No humans.

## What it does

Four tools, all agent-callable, structured outputs:

| Endpoint | Purpose |
|---|---|
| `POST /v1/check` | Fetch a URL. Returns status, final URL (after redirects), content hash, classification, readability score, title/description/first-heading when HTML, wayback URL when dead. |
| `POST /v1/diff` | Re-check a URL and tell the agent whether its hash changed since a prior hash. |
| `POST /v1/resolve` | Resolve redirect chain without downloading the body. |
| `POST /v1/classify` | Classify content the agent already has (status + content-type + body sample) — no outbound fetch. |

Every error response includes `{ error, code, message, fix, docs, http_status }` — agents never have to guess.

## Classifications

`alive_html` · `alive_json_api` · `alive_xml_feed` · `alive_markdown` · `alive_pdf` · `alive_image` · `alive_binary` · `empty` · `dead` · `redirect_loop` · `moved_permanent` · `login_wall` · `challenge_wall` · `rate_limited` · `server_error` · `unreachable`

## Discovery (no humans required)

- `GET /.well-known/ai-plugin.json`
- `GET /.well-known/mcp.json`
- `GET /llms.txt`
- `GET /openapi.json`
- `GET /v1/pricing`
- `GET /v1/errors`

## Auth

```bash
# 1. Mint a key (100 free credits)
curl -X POST https://linkpulse-neon.vercel.app/v1/keys

# 2. Use the key
curl -X POST https://linkpulse-neon.vercel.app/v1/check \
  -H "Authorization: Bearer lp_live_..." \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Billing

Prepaid credits. Single POST returns a payment URL the agent follows autonomously:

```bash
curl -X POST https://linkpulse-neon.vercel.app/v1/credits \
  -H "Authorization: Bearer lp_live_..." \
  -H "Content-Type: application/json" \
  -d '{"pack":"starter"}'
```

Returns `{ payment_url, x402: { ... } }`.

## MCP

`https://linkpulse-neon.vercel.app/mcp` (JSON-RPC 2.0, protocol `2024-11-05`). Tools: `linkpulse_check`, `linkpulse_diff`, `linkpulse_resolve`, `linkpulse_classify`.

## Safety

- SSRF blocked: loopback, RFC 1918, link-local, metadata.internal all refused with a structured error.
- Max 1.5 MB body. 6 s default timeout.

## License

Apache 2.0.
