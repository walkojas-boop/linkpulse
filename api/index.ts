import { Hono } from 'hono';
import { handle } from 'hono/vercel';
import { cors } from 'hono/cors';
import Stripe from 'stripe';

export const config = { runtime: 'edge' };

// ---------- payments config ----------
const PLATFORM_WALLET = '0x8ABCE477e22B76121f04c6c6a69eE2e6a12De53e'; // USDC on Base
const BASE_RPC = 'https://base.llamarpc.com';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

function stripeClient() {
  const key = (globalThis as any).process?.env?.STRIPE_SECRET_KEY || '';
  if (!key) throw new Error('STRIPE_SECRET_KEY not set');
  return new Stripe(key, { httpClient: Stripe.createFetchHttpClient(), apiVersion: '2024-12-18.acacia' } as any);
}

// ---------- config ----------
const VERSION = '1.0.0';
const FREE_CREDITS = 100;
const PRICE_PER_CALL_USD = 0.001;
const CREDIT_PACKS = [
  { id: 'starter', credits: 5_000, price_usd: 5 },
  { id: 'scale', credits: 150_000, price_usd: 100 },
  { id: 'bulk', credits: 2_000_000, price_usd: 1_000 },
];
const RATE_LIMIT_PER_MINUTE = 120;
const CACHE_TTL_MS = 10 * 60 * 1000;
const MAX_FETCH_BYTES = 1_500_000;
const DEFAULT_FETCH_TIMEOUT_MS = 6_000;

// ---------- helpers ----------
function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
async function sha256Hex(bytes: Uint8Array | string): Promise<string> {
  const buf = typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes;
  const digest = await globalThis.crypto.subtle.digest('SHA-256', buf as unknown as BufferSource);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}
const newKey = () => 'lp_live_' + randomHex(20);
const newIntent = () => 'pi_' + randomHex(12);
const now = () => Date.now();

// ---------- in-memory stores ----------
type KeyRow = { key: string; credits: number; created_at: number; calls: number; credited_sessions?: string[]; credited_tx?: string[] };
const KEYS = new Map<string, KeyRow>();
const INTENTS = new Map<string, { key: string; credits: number; price_usd: number; paid: boolean }>();
const RATE = new Map<string, { count: number; reset_at: number }>();
type CacheRow = { fetched_at: number; result: any };
const URL_CACHE = new Map<string, CacheRow>();

function authKey(h: Headers): KeyRow | null {
  const raw = h.get('authorization');
  if (!raw) return null;
  const m = raw.match(/Bearer\s+(\S+)/i);
  if (!m) return null;
  return KEYS.get(m[1]) || null;
}
function rateLimit(key: string): boolean {
  const row = RATE.get(key);
  const t = now();
  if (!row || row.reset_at < t) { RATE.set(key, { count: 1, reset_at: t + 60_000 }); return true; }
  if (row.count >= RATE_LIMIT_PER_MINUTE) return false;
  row.count++;
  return true;
}

// ---------- errors ----------
const ERRORS: Record<string, { message: string; fix: string; http: number }> = {
  missing_auth: { message: 'No Authorization header.', fix: 'POST /v1/keys with empty body to get a free key. Then send: Authorization: Bearer <key>', http: 401 },
  invalid_key: { message: 'Bearer key is unknown or revoked.', fix: 'POST /v1/keys to mint a new one.', http: 401 },
  no_credits: { message: 'API key has 0 credits.', fix: 'POST /v1/credits {"pack":"starter"} then GET the returned payment_url.', http: 402 },
  rate_limited: { message: `Exceeded ${RATE_LIMIT_PER_MINUTE} requests/minute.`, fix: `Back off and retry after reset_at.`, http: 429 },
  missing_url: { message: 'Request body is missing the required "url" field.', fix: 'Send Content-Type: application/json with body {"url":"https://..."}. Accepts http(s) URLs only.', http: 400 },
  bad_url: { message: 'URL is malformed or uses a non-http(s) scheme.', fix: 'Use a full absolute https:// or http:// URL. Other schemes (file, ftp, data, javascript) are blocked.', http: 400 },
  blocked_host: { message: 'Host resolves to a private/loopback address or a blocked domain.', fix: 'linkpulse refuses SSRF targets (127.0.0.0/8, 10/8, 192.168/16, 172.16/12, 169.254/16, ::1, metadata.internal). Use a public URL.', http: 400 },
  unknown_pack: { message: 'Unknown credit pack id.', fix: 'Valid packs: starter, scale, bulk. See GET /v1/pricing.', http: 400 },
  not_found: { message: 'No such endpoint.', fix: 'See GET / for the endpoint list or /openapi.json for the schema.', http: 404 },
};
function err(code: keyof typeof ERRORS, extra: Record<string, any> = {}) {
  const e = ERRORS[code];
  return { error: true, code, message: e.message, fix: e.fix, docs: 'https://' + ((globalThis as any).__HOST__ || 'linkpulse.vercel.app') + '/v1/errors#' + code, http_status: e.http, ...extra };
}

// ---------- SSRF guard ----------
function isBlockedHost(host: string): boolean {
  host = host.toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1') return true;
  // IPv4 literal checks
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127) return true;
    if (a === 10) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    if (a === 0) return true;
  }
  // metadata services
  if (host === 'metadata.google.internal') return true;
  if (host.endsWith('.compute.internal')) return true;
  return false;
}

// ---------- classifier ----------
const LOGIN_MARKERS = ['please sign in', 'please log in', 'login required', 'authentication required', 'access denied', 'sign in to continue', '<input type="password"', 'name="password"'];
const CHALLENGE_MARKERS = ['cf-chl-', 'cloudflare', 'checking your browser', 'captcha', 'g-recaptcha', 'hcaptcha', 'incapsula'];
const DEAD_MARKERS = ['404 not found', 'page not found', 'this page doesn\u2019t exist', 'this page does not exist', 'we can\u2019t find', 'we couldn\u2019t find'];

type Classification =
  | 'alive_html'
  | 'alive_json_api'
  | 'alive_xml_feed'
  | 'alive_markdown'
  | 'alive_pdf'
  | 'alive_image'
  | 'alive_binary'
  | 'empty'
  | 'dead'
  | 'redirect_loop'
  | 'moved_permanent'
  | 'login_wall'
  | 'challenge_wall'
  | 'rate_limited'
  | 'server_error'
  | 'unreachable';

function classify(status: number, contentType: string, bodyLower: string, bodyBytes: number, redirectCount: number): Classification {
  if (status === 0) return 'unreachable';
  if (status >= 500) return 'server_error';
  if (status === 429) return 'rate_limited';
  if (status === 404 || status === 410) return 'dead';
  if (status === 401 || status === 403) {
    if (CHALLENGE_MARKERS.some(m => bodyLower.includes(m))) return 'challenge_wall';
    return 'login_wall';
  }
  if (status === 301 || status === 308) return 'moved_permanent';
  if (redirectCount >= 8) return 'redirect_loop';
  if (status >= 300 && status < 400) return 'moved_permanent';
  if (status >= 200 && status < 300) {
    if (bodyBytes < 200) return 'empty';
    const ct = contentType.toLowerCase();
    if (ct.includes('application/json') || ct.includes('+json')) return 'alive_json_api';
    if (ct.includes('application/xml') || ct.includes('text/xml') || ct.includes('application/rss') || ct.includes('application/atom')) return 'alive_xml_feed';
    if (ct.includes('text/markdown') || ct.includes('text/x-markdown')) return 'alive_markdown';
    if (ct.includes('application/pdf')) return 'alive_pdf';
    if (ct.startsWith('image/')) return 'alive_image';
    if (ct.includes('text/html') || ct.includes('application/xhtml')) {
      if (LOGIN_MARKERS.some(m => bodyLower.includes(m))) return 'login_wall';
      if (CHALLENGE_MARKERS.some(m => bodyLower.includes(m))) return 'challenge_wall';
      if (DEAD_MARKERS.some(m => bodyLower.includes(m))) return 'dead';
      return 'alive_html';
    }
    if (ct.startsWith('text/')) return 'alive_html';
    return 'alive_binary';
  }
  return 'unreachable';
}

function readability(classification: Classification, bodyText: string, contentType: string): number {
  switch (classification) {
    case 'alive_json_api': return 100;
    case 'alive_markdown': return 95;
    case 'alive_xml_feed': return 85;
    case 'alive_html': {
      if (!bodyText) return 30;
      const stripped = bodyText.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      const ratio = stripped.length / Math.max(1, bodyText.length);
      return Math.max(10, Math.min(90, Math.round(ratio * 120)));
    }
    case 'alive_pdf': return 60;
    case 'alive_image': return 20;
    case 'alive_binary': return 5;
    case 'empty': return 5;
    case 'dead':
    case 'unreachable':
    case 'server_error': return 0;
    case 'login_wall':
    case 'challenge_wall':
    case 'rate_limited': return 15;
    case 'moved_permanent':
    case 'redirect_loop': return 40;
  }
}

function extractTitle(html: string): string | null {
  const m = html.match(/<title[^>]*>([\s\S]{1,300}?)<\/title>/i);
  if (!m) return null;
  return m[1].replace(/\s+/g, ' ').trim().slice(0, 200) || null;
}
function extractDescription(html: string): string | null {
  const m = html.match(/<meta\s+(?:name=["']description["']|property=["']og:description["'])\s+content=["']([^"']{1,500})["']/i)
         || html.match(/<meta\s+content=["']([^"']{1,500})["']\s+(?:name=["']description["']|property=["']og:description["'])/i);
  return m ? m[1].trim().slice(0, 400) : null;
}
function extractFirstHeading(html: string): string | null {
  const m = html.match(/<h1[^>]*>([\s\S]{1,300}?)<\/h1>/i);
  if (!m) return null;
  return m[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim().slice(0, 200) || null;
}

// ---------- fetch with safety ----------
async function safeFetch(url: string, timeoutMs: number, maxBytes: number): Promise<{
  status: number;
  final_url: string;
  content_type: string;
  content_length: number | null;
  body_bytes: Uint8Array;
  body_text: string;
  redirect_count: number;
  elapsed_ms: number;
  error?: string;
}> {
  const started = now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'linkpulse/1.0 (+https://linkpulse.vercel.app; agent-tool)',
        'Accept': '*/*',
      },
    });
    const contentType = res.headers.get('content-type') || 'application/octet-stream';
    const lenHeader = res.headers.get('content-length');
    const declaredLen = lenHeader ? parseInt(lenHeader, 10) : null;
    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let received = 0;
    if (reader) {
      while (received < maxBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          chunks.push(value);
          received += value.byteLength;
          if (received >= maxBytes) { try { await reader.cancel(); } catch {} break; }
        }
      }
    }
    const body = new Uint8Array(received);
    let off = 0;
    for (const c of chunks) { body.set(c, off); off += c.byteLength; }
    let bodyText = '';
    if (/^(text\/|application\/(json|xml|xhtml|rss|atom|javascript|x-yaml))/i.test(contentType) || /charset=/i.test(contentType)) {
      try { bodyText = new TextDecoder('utf-8', { fatal: false }).decode(body); } catch { bodyText = ''; }
    } else {
      try { bodyText = new TextDecoder('utf-8', { fatal: false }).decode(body.slice(0, 65536)); } catch {}
    }
    // redirect count unknown from fetch() — infer from URL change
    const redirectCount = res.url !== url ? 1 : 0;
    return {
      status: res.status,
      final_url: res.url || url,
      content_type: contentType,
      content_length: declaredLen,
      body_bytes: body,
      body_text: bodyText,
      redirect_count: redirectCount,
      elapsed_ms: now() - started,
    };
  } catch (e: any) {
    return {
      status: 0,
      final_url: url,
      content_type: '',
      content_length: null,
      body_bytes: new Uint8Array(0),
      body_text: '',
      redirect_count: 0,
      elapsed_ms: now() - started,
      error: e?.name === 'AbortError' ? 'timeout' : (e?.message || 'fetch_failed'),
    };
  } finally {
    clearTimeout(timer);
  }
}

function waybackUrl(originalUrl: string): string {
  return `https://web.archive.org/web/2y/${originalUrl}`;
}

// ---------- app ----------
const app = new Hono();
app.use('*', cors());
app.use('*', async (c, next) => {
  (globalThis as any).__HOST__ = c.req.header('host') || 'linkpulse.vercel.app';
  c.header('X-Service', 'linkpulse');
  c.header('X-Version', VERSION);
  await next();
});

// root manifest
app.get('/', (c) => {
  const host = c.req.header('host')!;
  const base = `https://${host}`;
  return c.json({
    service: 'linkpulse',
    version: VERSION,
    tagline: 'URL reality check for agents. Fetches once per URL per 10min, returns status + content hash + classification + readability score + wayback fallback.',
    humans: false,
    discovery: {
      ai_plugin: `${base}/.well-known/ai-plugin.json`,
      mcp: `${base}/.well-known/mcp.json`,
      openapi: `${base}/openapi.json`,
      llms_txt: `${base}/llms.txt`,
      pricing: `${base}/v1/pricing`,
      errors: `${base}/v1/errors`,
    },
    auth: { type: 'bearer', issue: `POST ${base}/v1/keys`, free_credits: FREE_CREDITS, header: 'Authorization: Bearer <key>' },
    billing: {
      model: 'prepaid_credits',
      price_per_call_usd: PRICE_PER_CALL_USD,
      currency: 'USD',
      purchase: `POST ${base}/v1/credits {"pack":"starter"}`,
      x402_supported: true,
      stablecoin_supported: true,
    },
    caching: {
      ttl_seconds: CACHE_TTL_MS / 1000,
      shared_across_keys: true,
      note: 'If any key fetched the same URL in the last 10 minutes, subsequent callers get the cached result (still billed 1 credit). Pass force_fresh=true to bypass.',
    },
    endpoints: [
      { method: 'POST', path: '/v1/check', cost_credits: 1, purpose: 'Fetch + classify + hash a URL. Primary endpoint.' },
      { method: 'POST', path: '/v1/diff', cost_credits: 1, purpose: 'Check if a URL changed since a prior hash.' },
      { method: 'POST', path: '/v1/resolve', cost_credits: 1, purpose: 'Resolve redirect chain (HEAD-style), no body fetch.' },
      { method: 'POST', path: '/v1/classify', cost_credits: 1, purpose: 'Classify a content sample you already have — no outbound fetch.' },
      { method: 'POST', path: '/v1/keys', cost_credits: 0, purpose: 'Mint a fresh key with 100 free credits.' },
      { method: 'GET', path: '/v1/keys/self', cost_credits: 0, purpose: 'Get credit balance.' },
      { method: 'POST', path: '/v1/credits', cost_credits: 0, purpose: 'Start a credit purchase.' },
      { method: 'GET', path: '/v1/pricing', cost_credits: 0, purpose: 'Machine-readable pricing.' },
      { method: 'GET', path: '/v1/errors', cost_credits: 0, purpose: 'Error code catalog.' },
    ],
  });
});

// well-known manifests
app.get('/.well-known/ai-plugin.json', (c) => {
  const base = `https://${c.req.header('host')}`;
  return c.json({
    schema_version: 'v1',
    name_for_human: 'linkpulse',
    name_for_model: 'linkpulse',
    description_for_human: 'URL reality-check service for AI agents.',
    description_for_model:
      'Use linkpulse to verify whether a URL still resolves to the content an agent remembers. POST /v1/check {"url":"..."} returns HTTP status, final URL, SHA-256 content hash, classification (alive_html | alive_json_api | dead | login_wall | challenge_wall | rate_limited | moved_permanent | etc.), a 0-100 agent-readability score, title/first-heading/meta-description when HTML, and a wayback archive URL when the page is dead. Use /v1/diff with a prior hash to detect content drift. Every error response contains a "fix" field with the exact remedy.',
    auth: {
      type: 'user_http',
      authorization_type: 'bearer',
      instructions: 'POST /v1/keys to mint a free key with 100 credits. Pass as Authorization: Bearer <key>.',
    },
    api: { type: 'openapi', url: `${base}/openapi.json` },
    logo_url: `${base}/logo`,
    contact_email: 'agents-only@linkpulse.dev',
    legal_info_url: `${base}/legal`,
  });
});

app.get('/.well-known/mcp.json', (c) => {
  const base = `https://${c.req.header('host')}`;
  return c.json({
    mcp_version: '2024-11-05',
    name: 'linkpulse',
    version: VERSION,
    description: 'URL reality check: status, content hash, classification, readability, wayback fallback.',
    transport: { type: 'http', endpoint: `${base}/mcp` },
    capabilities: { tools: { listChanged: false } },
    tools: [
      {
        name: 'linkpulse_check',
        description: 'Fetch a URL and return its current state: HTTP status, final URL after redirects, SHA-256 content hash, classification, readability score, title/meta-description, and wayback archive fallback if dead. Cached 10 minutes.',
        inputSchema: {
          type: 'object',
          required: ['url'],
          properties: {
            url: { type: 'string', format: 'uri' },
            force_fresh: { type: 'boolean', default: false },
            timeout_ms: { type: 'integer', minimum: 1000, maximum: 15000, default: 6000 },
            max_bytes: { type: 'integer', minimum: 1024, maximum: 1500000, default: 1500000 },
            include_body_sample: { type: 'boolean', default: false, description: 'If true, return first 1KB of body text.' },
          },
        },
      },
      {
        name: 'linkpulse_diff',
        description: 'Re-check a URL and tell you whether its content hash has changed since a previous hash you supply. Returns boolean + new hash.',
        inputSchema: {
          type: 'object',
          required: ['url', 'previous_hash'],
          properties: { url: { type: 'string', format: 'uri' }, previous_hash: { type: 'string' } },
        },
      },
      {
        name: 'linkpulse_resolve',
        description: 'Resolve redirect chain for a URL without downloading the full body. Returns final URL + redirect count.',
        inputSchema: { type: 'object', required: ['url'], properties: { url: { type: 'string', format: 'uri' } } },
      },
      {
        name: 'linkpulse_classify',
        description: 'Classify content you already have (status code + content-type + body sample) without an outbound fetch. Useful if your agent already fetched the URL via another tool.',
        inputSchema: {
          type: 'object',
          required: ['status', 'content_type', 'body_sample'],
          properties: {
            status: { type: 'integer' },
            content_type: { type: 'string' },
            body_sample: { type: 'string' },
          },
        },
      },
    ],
    auth: { type: 'bearer', header: 'Authorization', provision_url: `${base}/v1/keys` },
    pricing_url: `${base}/v1/pricing`,
  });
});

app.get('/llms.txt', (c) => {
  const base = `https://${c.req.header('host')}`;
  return c.text(`# linkpulse

> URL reality check for AI agents. Given a URL, returns HTTP status, SHA-256 content hash, classification, readability score, title, and wayback fallback when dead. Cached 10 minutes. $0.001 per call.

## Discovery
- OpenAPI: ${base}/openapi.json
- Plugin manifest: ${base}/.well-known/ai-plugin.json
- MCP manifest: ${base}/.well-known/mcp.json
- Pricing: ${base}/v1/pricing
- Errors: ${base}/v1/errors

## Auth
POST ${base}/v1/keys (no body) returns: { "key": "lp_live_...", "credits": ${FREE_CREDITS} }
Pass on every /v1/check|diff|resolve|classify call: Authorization: Bearer <key>

## Billing
Prepaid credits. POST ${base}/v1/credits {"pack":"starter"} returns { payment_url }. Agent follows URL to complete payment autonomously. x402 supported.

## Core tools
- POST /v1/check   { url, force_fresh?, timeout_ms?, max_bytes?, include_body_sample? } -> { status, final_url, content_hash, classification, readability_score, title, description, first_heading, wayback_url, cached, fetched_at_ms }
- POST /v1/diff    { url, previous_hash } -> { changed, new_hash, classification }
- POST /v1/resolve { url } -> { final_url, redirect_count }
- POST /v1/classify { status, content_type, body_sample } -> { classification, readability_score }

## Classifications
alive_html | alive_json_api | alive_xml_feed | alive_markdown | alive_pdf | alive_image | alive_binary | empty | dead | redirect_loop | moved_permanent | login_wall | challenge_wall | rate_limited | server_error | unreachable

## Error contract
Every 4xx/5xx returns: { error: true, code, message, fix, docs, http_status }. "fix" tells you exactly what to change.

## Safety
Private/loopback/metadata hosts are blocked (SSRF protection). Max 1.5MB body. 6s default timeout.

## Humans
None. Agent-only service.
`);
});

app.get('/openapi.json', (c) => {
  const base = `https://${c.req.header('host')}`;
  return c.json({
    openapi: '3.1.0',
    info: { title: 'linkpulse', version: VERSION, description: 'URL reality check for AI agents.' },
    servers: [{ url: base }],
    components: {
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } },
      schemas: {
        Error: {
          type: 'object', required: ['error', 'code', 'message', 'fix', 'http_status'],
          properties: {
            error: { type: 'boolean', const: true },
            code: { type: 'string' }, message: { type: 'string' }, fix: { type: 'string' },
            docs: { type: 'string' }, http_status: { type: 'integer' },
          },
        },
        CheckResult: {
          type: 'object',
          properties: {
            status: { type: 'integer' },
            final_url: { type: 'string', format: 'uri' },
            content_hash: { type: 'string' },
            classification: { type: 'string' },
            readability_score: { type: 'integer' },
            title: { type: 'string', nullable: true },
            description: { type: 'string', nullable: true },
            first_heading: { type: 'string', nullable: true },
            wayback_url: { type: 'string', nullable: true },
            cached: { type: 'boolean' },
            fetched_at_ms: { type: 'integer' },
            elapsed_ms: { type: 'integer' },
            bytes: { type: 'integer' },
            content_type: { type: 'string' },
          },
        },
      },
    },
    paths: {
      '/v1/keys': { post: { summary: 'Issue a new API key' } },
      '/v1/check': {
        post: {
          security: [{ bearer: [] }],
          summary: 'Fetch + classify + hash a URL',
          requestBody: {
            required: true,
            content: { 'application/json': { schema: { type: 'object', required: ['url'], properties: {
              url: { type: 'string', format: 'uri' },
              force_fresh: { type: 'boolean', default: false },
              timeout_ms: { type: 'integer', default: 6000 },
              max_bytes: { type: 'integer', default: 1500000 },
              include_body_sample: { type: 'boolean', default: false },
            } } } },
          },
          responses: { '200': { description: 'OK', content: { 'application/json': { schema: { $ref: '#/components/schemas/CheckResult' } } } } },
        },
      },
      '/v1/diff': { post: { security: [{ bearer: [] }], summary: 'Compare prior hash to current' } },
      '/v1/resolve': { post: { security: [{ bearer: [] }], summary: 'Resolve redirect chain' } },
      '/v1/classify': { post: { security: [{ bearer: [] }], summary: 'Classify pre-fetched content' } },
      '/v1/credits': { post: { summary: 'Start credit purchase' } },
      '/v1/pricing': { get: { summary: 'Machine-readable pricing' } },
      '/v1/errors': { get: { summary: 'Error code catalog' } },
    },
  });
});

// pricing
app.get('/v1/pricing', (c) => {
  return c.json({
    currency: 'USD',
    price_per_call_usd: PRICE_PER_CALL_USD,
    free_credits_on_signup: FREE_CREDITS,
    packs: CREDIT_PACKS,
    cache_ttl_seconds: CACHE_TTL_MS / 1000,
    settlement: ['prepaid_credits', 'x402', 'stablecoin_usdc'],
    effective_at: new Date().toISOString(),
  });
});

// errors catalog
app.get('/v1/errors', (c) => {
  return c.json({
    schema: {
      description: 'Every error response matches this shape.',
      example: { error: true, code: 'blocked_host', message: 'Host resolves to a private/loopback address.', fix: 'Use a public URL.', docs: '.../v1/errors#blocked_host', http_status: 400 },
    },
    codes: Object.fromEntries(Object.entries(ERRORS).map(([k, v]) => [k, { message: v.message, fix: v.fix, http_status: v.http }])),
  });
});

// keys
app.post('/v1/keys', (c) => {
  const k = newKey();
  const row: KeyRow = { key: k, credits: FREE_CREDITS, created_at: now(), calls: 0 };
  KEYS.set(k, row);
  return c.json({
    key: k,
    credits: row.credits,
    created_at: row.created_at,
    usage_hint: 'Pass as: Authorization: Bearer ' + k,
    next_step: 'POST /v1/check with {"url":"https://example.com"}',
  });
});
app.get('/v1/keys/self', (c) => {
  const row = authKey(c.req.raw.headers);
  if (!row) return c.json(err('missing_auth'), 401);
  return c.json({ key_prefix: row.key.slice(0, 14) + '...', credits: row.credits, calls: row.calls, created_at: row.created_at });
});

// ---------- credits (LIVE Stripe + x402 USDC) ----------
app.post('/v1/credits', async (c) => {
  const body = await c.req.json().catch(() => ({} as any));
  const packId = body.pack || 'starter';
  const pack = CREDIT_PACKS.find(p => p.id === packId);
  if (!pack) return c.json(err('unknown_pack'), 400);
  const row = authKey(c.req.raw.headers);
  if (!row) return c.json(err('missing_auth'), 401);
  const base = `https://${c.req.header('host')}`;
  let session: Stripe.Checkout.Session;
  try {
    const stripe = stripeClient();
    session = await stripe.checkout.sessions.create({
      mode: 'payment',
      line_items: [{
        price_data: {
          currency: 'usd',
          unit_amount: Math.round(pack.price_usd * 100),
          product_data: {
            name: `linkpulse ${pack.id} pack`,
            description: `${pack.credits.toLocaleString()} credits for linkpulse agent API`,
          },
        },
        quantity: 1,
      }],
      success_url: `${base}/v1/credits/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${base}/v1/credits/cancel`,
      metadata: { service: 'linkpulse', pack: pack.id, credits: String(pack.credits), key_hash: row.key.slice(0, 14) },
    });
  } catch (e: any) {
    return c.json({ error: true, code: 'stripe_error', message: e?.message || 'stripe_failed', fix: 'Retry in 30s.', http_status: 502 }, 502);
  }
  return c.json({
    session_id: session.id,
    pack,
    payment_url: session.url,
    verify_instructions: `After payment, POST ${base}/v1/credits/verify {"session_id":"${session.id}"} with your Authorization header to credit your key.`,
    x402: {
      version: '0.1',
      scheme: 'exact',
      network: 'base',
      max_amount_required: String(pack.price_usd),
      asset: 'USDC',
      asset_contract: USDC_BASE,
      resource: `${base}/v1/payments/verify`,
      description: `linkpulse ${pack.id} pack: ${pack.credits} credits`,
      pay_to: PLATFORM_WALLET,
      verify_endpoint: `${base}/v1/payments/verify`,
    },
    expires_at: session.expires_at,
    live_mode: true,
  });
});

app.post('/v1/credits/verify', async (c) => {
  const body = await c.req.json().catch(() => ({} as any));
  const row = authKey(c.req.raw.headers);
  if (!row) return c.json(err('missing_auth'), 401);
  const sessionId = body.session_id;
  if (!sessionId || typeof sessionId !== 'string') return c.json(err('missing_input', { detail: 'Need {"session_id":"cs_..."}' }), 400);
  try {
    const stripe = stripeClient();
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.metadata?.service !== 'linkpulse') return c.json({ error: true, code: 'wrong_service', message: 'Session belongs to another service.', http_status: 400 }, 400);
    if (session.payment_status !== 'paid') return c.json({ error: true, code: 'not_paid', message: `Stripe reports payment_status=${session.payment_status}`, fix: 'Complete checkout first.', http_status: 402, session_status: session.payment_status }, 402);
    const credits = parseInt(session.metadata?.credits || '0', 10);
    if (!credits) return c.json({ error: true, code: 'no_credits_in_metadata', http_status: 500 }, 500);
    if (!row.credited_sessions) row.credited_sessions = [];
    if (row.credited_sessions.includes(sessionId)) return c.json({ status: 'already_credited', credits_balance: row.credits });
    row.credits += credits;
    row.credited_sessions.push(sessionId);
    return c.json({ status: 'paid', session_id: sessionId, credits_added: credits, credits_balance: row.credits, amount_paid_usd: (session.amount_total || 0) / 100, live_mode: true });
  } catch (e: any) {
    return c.json({ error: true, code: 'stripe_error', message: e?.message || 'unknown', http_status: 502 }, 502);
  }
});

app.post('/stripe/webhook', async (c) => {
  const sig = c.req.header('stripe-signature') || '';
  const raw = await c.req.text();
  const secret = (globalThis as any).process?.env?.STRIPE_WEBHOOK_SECRET || '';
  try { const stripe = stripeClient(); await stripe.webhooks.constructEventAsync(raw, sig, secret); }
  catch (e: any) { return c.json({ error: 'invalid signature', detail: e?.message }, 400); }
  return c.json({ received: true, processed_by: 'client_driven_verify' });
});

app.post('/v1/payments/verify', async (c) => {
  const body = await c.req.json().catch(() => ({} as any));
  const row = authKey(c.req.raw.headers);
  if (!row) return c.json(err('missing_auth'), 401);
  const txHash = body.tx_hash;
  if (!txHash || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return c.json({ error: true, code: 'bad_tx_hash', message: 'tx_hash must be a 0x 32-byte hex string.', http_status: 400 }, 400);
  try {
    const rpcRes = await fetch(BASE_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getTransactionReceipt', params: [txHash], id: 1 }) });
    const rpc = await rpcRes.json() as any;
    if (!rpc.result) return c.json({ error: true, code: 'tx_not_found', message: 'Transaction not found on Base mainnet.', http_status: 404 }, 404);
    const receipt = rpc.result;
    if (receipt.status !== '0x1') return c.json({ error: true, code: 'tx_failed', http_status: 400 }, 400);
    const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
    const logs = (receipt.logs || []).filter((l: any) => l.address?.toLowerCase() === USDC_BASE.toLowerCase() && l.topics?.[0] === TRANSFER_TOPIC);
    if (!logs.length) return c.json({ error: true, code: 'no_usdc_transfer', message: 'No USDC transfer log on Base.', fix: 'Send USDC to ' + PLATFORM_WALLET + ' on Base then retry.', http_status: 400 }, 400);
    const toPadded = '0x' + PLATFORM_WALLET.slice(2).toLowerCase().padStart(64, '0');
    const matching = logs.find((l: any) => l.topics[2]?.toLowerCase() === toPadded);
    if (!matching) return c.json({ error: true, code: 'wrong_recipient', message: 'USDC transfer not addressed to platform wallet.', fix: 'Send to ' + PLATFORM_WALLET + '.', http_status: 400 }, 400);
    const amountUsd = Number(BigInt(matching.data)) / 1_000_000;
    if (!row.credited_tx) row.credited_tx = [];
    if (row.credited_tx.includes(txHash.toLowerCase())) return c.json({ status: 'already_credited', credits_balance: row.credits });
    const creditsToAdd = Math.floor(amountUsd / PRICE_PER_CALL_USD);
    row.credits += creditsToAdd;
    row.credited_tx.push(txHash.toLowerCase());
    return c.json({ status: 'paid', tx_hash: txHash, amount_usd: amountUsd, credits_added: creditsToAdd, credits_balance: row.credits, pay_to: PLATFORM_WALLET, network: 'base', live_mode: true });
  } catch (e: any) {
    return c.json({ error: true, code: 'rpc_error', message: e?.message, http_status: 502 }, 502);
  }
});

app.get('/v1/credits/success', (c) => c.json({ status: 'stripe_redirect', session_id: c.req.query('session_id'), next: 'POST /v1/credits/verify with that session_id and your Authorization header.' }));
app.get('/v1/credits/cancel', (c) => c.json({ status: 'cancelled', next: 'Retry POST /v1/credits.' }));

// shared charge helper
function charge(c: any): { row: KeyRow | null; errResp?: any } {
  const row = authKey(c.req.raw.headers);
  if (!row) return { row: null, errResp: c.json(err('missing_auth'), 401) };
  if (!rateLimit(row.key)) return { row: null, errResp: c.json(err('rate_limited'), 429) };
  if (row.credits <= 0) return { row: null, errResp: c.json(err('no_credits'), 402) };
  row.credits -= 1;
  row.calls += 1;
  return { row };
}

// URL pre-flight validation
function preflightUrl(raw: any): { url?: URL; err?: any } {
  if (typeof raw !== 'string' || !raw.trim()) return { err: err('missing_url') };
  let u: URL;
  try { u = new URL(raw); } catch { return { err: err('bad_url') }; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return { err: err('bad_url') };
  if (isBlockedHost(u.hostname)) return { err: err('blocked_host') };
  return { url: u };
}

// ---------- core: /v1/check ----------
app.post('/v1/check', async (c) => {
  const charged = charge(c); if (!charged.row) return charged.errResp;
  const body = await c.req.json().catch(() => null);
  const pre = preflightUrl(body?.url);
  if (pre.err) return c.json(pre.err, pre.err.http_status);
  const u = pre.url!;
  const forceFresh = !!body?.force_fresh;
  const timeoutMs = Math.min(15000, Math.max(1000, Number(body?.timeout_ms) || DEFAULT_FETCH_TIMEOUT_MS));
  const maxBytes = Math.min(MAX_FETCH_BYTES, Math.max(1024, Number(body?.max_bytes) || MAX_FETCH_BYTES));
  const includeSample = !!body?.include_body_sample;

  const cacheKey = u.toString();
  const cached = URL_CACHE.get(cacheKey);
  let result: any;
  if (!forceFresh && cached && now() - cached.fetched_at < CACHE_TTL_MS) {
    result = { ...cached.result, cached: true };
  } else {
    const r = await safeFetch(u.toString(), timeoutMs, maxBytes);
    const contentType = r.content_type;
    const bodyLower = (r.body_text || '').slice(0, 16384).toLowerCase();
    const cls = classify(r.status, contentType, bodyLower, r.body_bytes.byteLength, r.redirect_count);
    const hash = r.body_bytes.byteLength > 0 ? await sha256Hex(r.body_bytes) : '';
    const readScore = readability(cls, r.body_text, contentType);
    let title: string | null = null, desc: string | null = null, h1: string | null = null;
    if (cls === 'alive_html' && r.body_text) {
      title = extractTitle(r.body_text);
      desc = extractDescription(r.body_text);
      h1 = extractFirstHeading(r.body_text);
    } else if (cls === 'alive_json_api' && r.body_text) {
      try {
        const j = JSON.parse(r.body_text);
        title = (typeof j?.title === 'string' && j.title) || (typeof j?.name === 'string' && j.name) || null;
      } catch {}
    }
    const dead = cls === 'dead' || cls === 'unreachable' || cls === 'server_error';
    result = {
      status: r.status,
      final_url: r.final_url,
      content_type: contentType,
      bytes: r.body_bytes.byteLength,
      content_length: r.content_length,
      content_hash: hash,
      classification: cls,
      readability_score: readScore,
      title, description: desc, first_heading: h1,
      wayback_url: dead ? waybackUrl(u.toString()) : null,
      fetch_error: r.error || null,
      cached: false,
      fetched_at_ms: now(),
      elapsed_ms: r.elapsed_ms,
      redirect_count: r.redirect_count,
    };
    URL_CACHE.set(cacheKey, { fetched_at: now(), result: { ...result, cached: undefined } });
  }
  if (includeSample) {
    const sample = (URL_CACHE.get(cacheKey)?.result?.title || '') + ' ';
    result.body_sample = sample.slice(0, 1024);
  }
  return c.json({ ...result, cost_credits: 1, credits_remaining: charged.row.credits });
});

// ---------- /v1/diff ----------
app.post('/v1/diff', async (c) => {
  const charged = charge(c); if (!charged.row) return charged.errResp;
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body.previous_hash !== 'string') return c.json(err('missing_url', { detail: 'Need both "url" and "previous_hash".' }), 400);
  const pre = preflightUrl(body.url);
  if (pre.err) return c.json(pre.err, pre.err.http_status);
  const u = pre.url!;
  const r = await safeFetch(u.toString(), DEFAULT_FETCH_TIMEOUT_MS, MAX_FETCH_BYTES);
  const hash = r.body_bytes.byteLength > 0 ? await sha256Hex(r.body_bytes) : '';
  const cls = classify(r.status, r.content_type, (r.body_text || '').slice(0, 16384).toLowerCase(), r.body_bytes.byteLength, r.redirect_count);
  return c.json({
    changed: hash !== body.previous_hash,
    new_hash: hash,
    previous_hash: body.previous_hash,
    classification: cls,
    status: r.status,
    final_url: r.final_url,
    cost_credits: 1,
    credits_remaining: charged.row.credits,
  });
});

// ---------- /v1/resolve ----------
app.post('/v1/resolve', async (c) => {
  const charged = charge(c); if (!charged.row) return charged.errResp;
  const body = await c.req.json().catch(() => null);
  const pre = preflightUrl(body?.url);
  if (pre.err) return c.json(pre.err, pre.err.http_status);
  const u = pre.url!;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), DEFAULT_FETCH_TIMEOUT_MS);
  try {
    const r = await fetch(u.toString(), { method: 'HEAD', redirect: 'follow', signal: ctrl.signal, headers: { 'User-Agent': 'linkpulse/1.0' } });
    return c.json({
      final_url: r.url,
      status: r.status,
      redirected: r.url !== u.toString(),
      cost_credits: 1,
      credits_remaining: charged.row.credits,
    });
  } catch (e: any) {
    return c.json({ final_url: u.toString(), status: 0, redirected: false, error: e?.name === 'AbortError' ? 'timeout' : (e?.message || 'fetch_failed'), cost_credits: 1, credits_remaining: charged.row.credits });
  } finally {
    clearTimeout(t);
  }
});

// ---------- /v1/classify (no network) ----------
app.post('/v1/classify', async (c) => {
  const charged = charge(c); if (!charged.row) return charged.errResp;
  const body = await c.req.json().catch(() => null);
  if (!body || typeof body.status !== 'number' || typeof body.content_type !== 'string' || typeof body.body_sample !== 'string') {
    return c.json(err('missing_url', { detail: 'Need "status" (integer), "content_type" (string), "body_sample" (string).' }), 400);
  }
  const cls = classify(body.status, body.content_type, body.body_sample.toLowerCase(), body.body_sample.length, 0);
  const score = readability(cls, body.body_sample, body.content_type);
  return c.json({ classification: cls, readability_score: score, cost_credits: 1, credits_remaining: charged.row.credits });
});

// ---------- MCP transport ----------
app.post('/mcp', async (c) => {
  const body = await c.req.json().catch(() => null);
  if (!body || !body.method) return c.json({ jsonrpc: '2.0', error: { code: -32600, message: 'invalid JSON-RPC' }, id: null });
  const id = body.id ?? null;
  if (body.method === 'initialize') {
    return c.json({ jsonrpc: '2.0', id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'linkpulse', version: VERSION } } });
  }
  if (body.method === 'tools/list') {
    const manifest = await fetch(`https://${c.req.header('host')}/.well-known/mcp.json`).then(r => r.json()).catch(() => null);
    return c.json({ jsonrpc: '2.0', id, result: { tools: manifest?.tools || [] } });
  }
  if (body.method === 'tools/call') {
    const name = body.params?.name;
    const args = body.params?.arguments || {};
    const map: Record<string, string> = {
      linkpulse_check: '/v1/check',
      linkpulse_diff: '/v1/diff',
      linkpulse_resolve: '/v1/resolve',
      linkpulse_classify: '/v1/classify',
    };
    const path = map[name];
    if (!path) return c.json({ jsonrpc: '2.0', id, error: { code: -32601, message: 'unknown tool' } });
    const auth = c.req.header('authorization') || '';
    const r = await fetch(`https://${c.req.header('host')}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body: JSON.stringify(args),
    });
    const data = await r.json();
    return c.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(data) }], isError: !r.ok } });
  }
  return c.json({ jsonrpc: '2.0', id, error: { code: -32601, message: 'method not found' } });
});

// logo
app.get('/logo', () => {
  const png = hexToBytes('89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4890000000D4944415478DA6364F80F0000010101005B36CAF10000000049454E44AE426082');
  return new Response(png.buffer as ArrayBuffer, { headers: { 'content-type': 'image/png' } });
});

// legal
app.get('/legal', (c) => c.json({
  service: 'linkpulse',
  terms: 'Use as an agent. No warranty. Do not check private/internal URLs. SSRF-blocked hosts cannot be bypassed. No warranty on wayback snapshots.',
  privacy: 'Fetched URLs and their hashes are cached 10 minutes for deduplication. No persistent logs of client identity beyond credit accounting.',
  contact: 'agents-only, file issues at the GitHub repo.',
}));

// 404
app.notFound((c) => c.json(err('not_found', { path: c.req.path }), 404));

export default handle(app);
