// src/worker.js

const PNG_1x1 = Uint8Array.from([
  0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
  0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x60, 0x00, 0x00, 0x00,
  0x02, 0x00, 0x01, 0xE2, 0x26, 0x05, 0x9B, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
  0x42, 0x60, 0x82
])

// Minimal 1x1 GIF
const GIF_1x1 = Uint8Array.from([
  0x47,0x49,0x46,0x38,0x39,0x61,0x01,0x00,0x01,0x00,0x80,0x00,0x00,
  0x00,0x00,0x00,0xFF,0xFF,0xFF,0x21,0xF9,0x04,0x01,0x00,0x00,0x00,
  0x00,0x2C,0x00,0x00,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x02,0x02,
  0x44,0x01,0x00,0x3B
])

// Tiny ICO (16x16, single color)
const ICO_MINI = Uint8Array.from([
  0x00,0x00,0x01,0x00,0x01,0x00,0x10,0x10,0x00,0x00,0x01,0x00,0x20,0x00,
  0x68,0x01,0x00,0x00,0x16,0x00,0x00,0x00,
  // DIB header (BITMAPINFOHEADER)
  0x28,0x00,0x00,0x00,0x10,0x00,0x00,0x00,0x20,0x00,0x00,0x00,0x01,0x00,
  0x20,0x00,0x00,0x00,0x00,0x00,0x40,0x01,0x00,0x00,0x13,0x0B,0x00,0x00,
  0x13,0x0B,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
  // Pixel data (ARBG, 16x32 rows incl. AND mask space)
  // Simple transparent icon with one colored pixel in top-left
  0x00,0x00,0x00,0x00, /* ... repeated transparent ... */
])

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    const { pathname, searchParams, origin, host } = url

    const ADMIN_BASE = (env.ADMIN_BASE && env.ADMIN_BASE.startsWith('/')) ? env.ADMIN_BASE : '/admin'

    // Basic CORS (useful for the CSS/Font endpoints in emails)
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors("*") })
    }

    try {
      // ---------- PUBLIC CANARY ENDPOINTS ----------
      // Pixel: /t/<id>.png
      const mPx = pathname.match(/^\/t\/([A-Za-z0-9_-]{8,64})(?:\.png)?$/)
      if (mPx) {
        const id = mPx[1]
        await ensureToken(env, id, "pixel")
        ctx.waitUntil(writeLog(env, "pixel", id, request, url))
        // No-store to keep hits “fresh” (avoid caches skipping the fetch)
        return new Response(PNG_1x1, {
          headers: {
            "Content-Type": "image/png",
            "Content-Length": String(PNG_1x1.length),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
          },
        })
      }

      // Lure: /l/<id>  (optional decoy redirect)
      const mLure = pathname.match(/^\/l\/([A-Za-z0-9_-]{8,64})$/)
      if (mLure) {
        const id = mLure[1]
        const token = await ensureToken(env, id, "lure")
        ctx.waitUntil(writeLog(env, "lure", id, request, url))
        const decoy = token?.decoy_url || ""
        return decoy ? Response.redirect(decoy, 302) : new Response(null, { status: 204 })
      }

      // Canary Font binary: /f/<id>.woff2
      const mFont = pathname.match(/^\/f\/([A-Za-z0-9_-]{8,64})\.woff2$/)
      if (mFont) {
        const id = mFont[1]
        await ensureToken(env, id, "font")
        ctx.waitUntil(writeLog(env, "font", id, request, url))
        const obj = env.FONTS ? await env.FONTS.get(`${id}.woff2`) : null

        if (obj) {
          return new Response(obj.body, {
            headers: {
              "Content-Type": "font/woff2", // correct MIME
              "Cache-Control": "no-store",  // force fetch for canary purposes
              "Access-Control-Allow-Origin": "*",
              "Timing-Allow-Origin": "*",
            },
          })
        }

        // Fallback: proxy a configured upstream font (still logs the hit)
        const upstream = (env.FONT_UPSTREAM || "").trim()
        if (upstream) {
          const r = await fetch(upstream, { cf: { cacheTtl: 0, cacheEverything: false } })
          // Ensure proper MIME regardless of upstream’s header quality
          const h = new Headers(r.headers)
          h.set("Content-Type", "font/woff2")
          h.set("Cache-Control", "no-store")
          h.set("Access-Control-Allow-Origin", "*")
          h.set("Timing-Allow-Origin", "*")
          return new Response(r.body, { status: r.status, headers: h })
        }
        // If you didn’t provision a font, return 404 (hit is still logged)
        return new Response("font not provisioned", { status: 404, headers: cors("*") })
      }

      // Embeddable CSS for email HTML: /css/<id>.css
      // Returns a ready-to-embed @font-face rule pointing to /f/<id>.woff2
      const mCss = pathname.match(/^\/css\/([A-Za-z0-9_-]{8,64})\.css$/)
      if (mCss) {
        const id = mCss[1]
        await ensureToken(env, id, "font")
        // CSS itself isn’t the signal you care about; the font fetch is.
        const css = `
@font-face{
  font-family:"C-Canary-${id}";
  src:url("${origin}/f/${id}.woff2") format("woff2");
  font-display: swap;
}
html,body,*{ font-family:"C-Canary-${id}", system-ui, sans-serif !important; }
`.trim()
        return new Response(css, {
          headers: {
            "Content-Type": "text/css; charset=utf-8",
            "Cache-Control": "no-store",
            ...cors("*"),
          },
        })
      }

      // --- Additional HEAD handlers for existing canaries ---
      if (request.method === 'HEAD') {
        let m
        m = pathname.match(/^\/t\/([A-Za-z0-9_-]{8,64})(?:\.png)?$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id, "pixel")
          ctx.waitUntil(writeLog(env, "pixel", id, request, url, { tokenKnown: !!token }))
          return new Response(null, { headers: {
            "Content-Type": "image/png",
            "Content-Length": String(PNG_1x1.length),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Timing-Allow-Origin": "*",
          } })
        }
        m = pathname.match(/^\/f\/([A-Za-z0-9_-]{8,64})\.woff2$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id, "font")
          ctx.waitUntil(writeLog(env, "font", id, request, url, { tokenKnown: !!token }))
          return new Response(null, { headers: {
            "Content-Type": "font/woff2",
            "Cache-Control": "no-store",
            "Access-Control-Allow-Origin": "*",
            "Timing-Allow-Origin": "*",
            "Cross-Origin-Resource-Policy": "cross-origin",
          } })
        }
        m = pathname.match(/^\/css\/([A-Za-z0-9_-]{8,64})\.css$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id, "font")
          ctx.waitUntil(writeLog(env, "css-font", id, request, url, { tokenKnown: !!token }))
          return new Response(null, { headers: {
            "Content-Type": "text/css; charset=utf-8",
            "Cache-Control": "no-store",
            "Cross-Origin-Resource-Policy": "cross-origin",
            ...cors("*"),
          } })
        }
        m = pathname.match(/^\/l\/([A-Za-z0-9_-]{8,64})$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id, "lure")
          ctx.waitUntil(writeLog(env, "lure", id, request, url, { tokenKnown: !!token }))
          const s = await env.TOKENS.get(`token:${id}`)
          const decoy = s ? (JSON.parse(s).decoy_url || "") : ""
          if (decoy) return new Response(null, { status: 302, headers: new Headers({ Location: decoy }) })
          return new Response(null, { status: 204 })
        }
      }

      // --- New canary endpoints ---
      // 1x1 GIF: /g/<id>.gif
      {
        const m = pathname.match(/^\/g\/([A-Za-z0-9_-]{8,64})\.gif$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "gif", id, request, url, { tokenKnown: !!token }))
          const headers = {
            "Content-Type": "image/gif",
            "Content-Length": String(GIF_1x1.length),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Timing-Allow-Origin": "*",
          }
          if (request.method === 'HEAD') return new Response(null, { headers })
          return new Response(GIF_1x1, { headers })
        }
      }

      // Favicon: /ico/<id>.ico
      {
        const m = pathname.match(/^\/ico\/([A-Za-z0-9_-]{8,64})\.ico$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "ico", id, request, url, { tokenKnown: !!token }))
          const headers = {
            "Content-Type": "image/x-icon",
            "Content-Length": String(PNG_1x1.length),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
            "Cross-Origin-Resource-Policy": "cross-origin",
            "Timing-Allow-Origin": "*",
          }
          if (request.method === 'HEAD') return new Response(null, { headers })
          return new Response(PNG_1x1, { headers })
        }
      }

      // JS: /js/<id>.js
      {
        const m = pathname.match(/^\/js\/([A-Za-z0-9_-]{8,64})\.js$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "js", id, request, url, { tokenKnown: !!token }))
          const headers = { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "cross-origin", ...cors("*") }
          if (request.method === 'HEAD') return new Response(null, { headers })
          return new Response(`/* Canary JS ${id} */\n`, { headers })
        }
      }

      // CSS: /s/<id>.css
      {
        const m = pathname.match(/^\/s\/([A-Za-z0-9_-]{8,64})\.css$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "css", id, request, url, { tokenKnown: !!token }))
          const headers = { "Content-Type": "text/css; charset=utf-8", "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "cross-origin", ...cors("*") }
          if (request.method === 'HEAD') return new Response(null, { headers })
          return new Response(`/* Canary CSS ${id} */\n`, { headers })
        }
      }

      // Basic-Auth: /auth/<id>
      {
        const m = pathname.match(/^\/auth\/([A-Za-z0-9_-]{8,64})$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "auth", id, request, url, { tokenKnown: !!token }))
          return new Response("", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="Canary", charset="UTF-8"', "Cache-Control": "no-store" } })
        }
      }

      // OpenGraph/Unfurl: /o/<id>
      {
        const m = pathname.match(/^\/o\/([A-Za-z0-9_-]{8,64})$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "og", id, request, url, { tokenKnown: !!token }))
          const img = `${origin}/t/${id}.png`
          const html = `<!doctype html><meta charset="utf-8"><meta property="og:title" content="Preview"><meta property="og:description" content="Canary"><meta property="og:image" content="${img}"><meta name="twitter:card" content="summary_large_image"><title>Canary OG</title><link rel="icon" href="${origin}/ico/${id}.ico"><body><img src="${img}" alt="" width="1" height="1"></body>`
          const headers = { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
          if (request.method === 'HEAD') return new Response(null, { headers })
          return new Response(html, { headers })
        }
      }

      // Calendar ICS: /cal/<id>.ics
      {
        const m = pathname.match(/^\/cal\/([A-Za-z0-9_-]{8,64})\.ics$/)
        if (m) {
          const id = m[1]
          const token = await ensureToken(env, id)
          ctx.waitUntil(writeLog(env, "ics", id, request, url, { tokenKnown: !!token }))
          const dt = new Date()
          const toIcs = (d) => d.toISOString().replace(/[-:]/g, '').replace(/\..+/, 'Z')
          const dtStart = toIcs(dt)
          const dtEnd = toIcs(new Date(dt.getTime() + 15 * 60 * 1000))
          const uid = `${id}@${url.hostname}`
          const ics = [
            'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//Canary//EN', 'METHOD:PUBLISH', 'BEGIN:VEVENT',
            `UID:${uid}`, `DTSTAMP:${dtStart}`, `DTSTART:${dtStart}`, `DTEND:${dtEnd}`, `SUMMARY:Meeting`, `URL:${origin}/l/${id}`,
            'END:VEVENT', 'END:VCALENDAR'
          ].join('\r\n') + '\r\n'
          const headers = { "Content-Type": "text/calendar; charset=utf-8", "Cache-Control": "no-store" }
          if (request.method === 'HEAD') return new Response(null, { headers })
          return new Response(ics, { headers })
        }
      }

      // ---------- ADMIN API (protect this path with Cloudflare Access) ----------

      if (pathname.startsWith("/api/")) {
        // Protect API with Cloudflare Access JWT and scope by tenant
        const claims = await verifyAccessJWT(request, env).catch(() => null)
        if (!claims) return j({ error: "unauthorized" }, 401)
        const tenantId = getTenantIdFromClaims(claims)

        if (request.method === "POST" && pathname === "/api/new") {
          const body = await safeJson(request)
          const type = (body?.type || "").toLowerCase()
          if (!["pixel", "lure", "font"].includes(type)) {
            return j({ error: "type must be pixel | lure | font" }, 400)
          }
          const id = await newId()
          const token = {
            id,
            type,
            label: body?.label || "",
            decoy_url: type === "lure" ? (body?.decoy_url || "") : "",
            created_at: new Date().toISOString(),
            tenant_id: tenantId,
            created_by: claims.email || "",
          }
          await env.TOKENS.put(`token:${id}`, JSON.stringify(token))
          return j({ token, endpoints: endpointsFor(origin, token) })
        }

        const mMeta = pathname.match(/^\/api\/token\/([A-Za-z0-9_-]{8,64})$/)
        if (request.method === "GET" && mMeta) {
          const token = await env.TOKENS.get(`token:${mMeta[1]}`).then(s => s && JSON.parse(s))
          if (!token) return j({ error: "not found" }, 404)
          if ((token.tenant_id || "") !== tenantId) return j({ error: "not found" }, 404)
          return j({ token, endpoints: endpointsFor(origin, token) })
        }

        if (request.method === "GET" && pathname === "/api/tokens") {
          const list = await env.TOKENS.list({ prefix: "token:" })
          const all = await Promise.all(list.keys.map(k => env.TOKENS.get(k.name).then(s => s && JSON.parse(s)).catch(() => null)))
          const tokens = (all.filter(Boolean).filter(t => (t.tenant_id || "") === tenantId))
          tokens.sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
          return j({ tokens })
        }

        return j({ error: "unknown endpoint" }, 404)
      }


      // --- Admin Dashboard (protect this route with Cloudflare Access) ---
      if (pathname === ADMIN_BASE) {
        const claims = await verifyAccessJWT(request, env).catch(() => null)
        if (!claims) return new Response("unauthorized", { status: 401 })
        return new Response(
          ADMIN_HTML(origin, ADMIN_BASE).replaceAll('${AE_DATASET_PLACEHOLDER}', env.AE_DATASET || 'canary_events'),
          { headers: { "content-type": "text/html; charset=utf-8" } }
        )
      }

      // --- Admin SQL proxy (behind Access as well) ---
      if (pathname === `${ADMIN_BASE}/api/query` && request.method === "POST") {
        const claims = await verifyAccessJWT(request, env).catch(() => null)
        if (!claims) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } })
        const { sql } = await request.json().catch(() => ({}))
        if (!sql) return new Response(JSON.stringify({ error: "Missing SQL" }), { status: 400, headers: { "content-type": "application/json" } })

        // Optionally: verify Access JWT here for defense-in-depth
        // const jwt = request.headers.get("Cf-Access-Jwt-Assertion"); /* validate if desired */

        // Call WAE SQL API (use account-level Secrets Store for CF_API_TOKEN if bound)
        const apiToken = await getSecret(env, 'CF_API_TOKEN')
        const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/workers/analytics_engine/sql`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${apiToken}`,
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ query: sql.replaceAll('${AE_DATASET_PLACEHOLDER}', env.AE_DATASET || 'canary_events') })
        })

        const j = await r.json()
        return new Response(JSON.stringify(j), { status: r.status, headers: { "content-type": "application/json" } })
      }

      // Root help
      if (pathname === "/") {
        return new Response(
          `DIY Canary Worker (WAE edition)

Pixel: GET ${origin}/t/<id>.png
Lure : GET ${origin}/l/<id>
Font : GET ${origin}/f/<id>.woff2   (and CSS at ${origin}/css/<id>.css)
GIF  : GET ${origin}/g/<id>.gif
Favicon: GET ${origin}/ico/<id>.ico
JS   : GET ${origin}/js/<id>.js
CSS  : GET ${origin}/s/<id>.css
Auth : GET ${origin}/auth/<id> (401 Basic)
OG   : GET ${origin}/o/<id>
ICS  : GET ${origin}/cal/<id>.ics

Admin:
  POST /api/new {"type":"pixel"|"lure"|"font", "label"?, "decoy_url"?}
  GET  /api/tokens
  GET  /api/token/<id>

Console: ${origin}${ADMIN_BASE} (protected by Cloudflare Access)
SQL API: POST ${origin}${ADMIN_BASE}/api/query (protected)

Protect ${ADMIN_BASE} and /api/* with Cloudflare Access.`, { headers: { "content-type": "text/plain; charset=utf-8" } }
        )
      }

      return new Response("Not found", { status: 404 })
    } catch (e) {
      console.error(e)
      return j({ error: "server_error", detail: String(e) }, 500)
    }
  },
}

// ------- Helpers -------

// Fetch a secret from the account-level Secrets Store (preferred), then fall back to per-Worker Secret.
// If both are absent, throw a helpful error.
async function getSecret(env, name) {
  // 1) Account-level Secrets Store (if bound)
  try {
    if (env.SECRETS && typeof env.SECRETS.get === "function") {
      const v = await env.SECRETS.get(name)
      if (v) return v
    }
  } catch (e) {
    // If the store exists but errors (e.g., perms), continue to fallback.
    console.warn(`Secrets Store read failed for ${name}:`, e)
  }

  // 2) Per-Worker Secret fallback
  if (env[name]) return env[name]

  // 3) Neither found → fail clearly
  const msg = `Missing secret: ${name}. Provide it via the account-level Secrets Store (binding SECRETS) or set a per-Worker Secret.`
  throw new Error(msg)
}

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  }
}

async function newId() {
  const buf = new Uint8Array(12)
  crypto.getRandomValues(buf)
  return btoa(String.fromCharCode(...buf)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

async function ensureToken(env, id, expectedType) {
  const s = await env.TOKENS.get(`token:${id}`)
  if (!s) return null
  const t = JSON.parse(s)
  if (expectedType && t.type !== expectedType) return t // allow mixed hits, still log
  return t
}

function endpointsFor(origin, token) {
  const id = token.id, css = `${origin}/css/${id}.css`
  if (token.type === "pixel") return { img: `${origin}/t/${id}.png`, markdown: `![px](${origin}/t/${id}.png)` }
  if (token.type === "lure") return { link: `${origin}/l/${id}` }
  return { css, font: `${origin}/f/${id}.woff2`, html: `<link rel="stylesheet" href="${css}">` }
}

// Write a single event into Workers Analytics Engine
async function writeLog(env, typ, id, request, url) {
  const cf = request.cf || {}
  const h = request.headers
  // NOTE: WAE expects ordered arrays — keep this consistent. :contentReference[oaicite:2]{index=2}
  const blobs = [
    typ,                   // blob1: type ("pixel"|"lure"|"font")
    id,                    // blob2: token_id
    url.hostname,          // blob3: host hit
    url.pathname,          // blob4: path
    cf.country || "",      // blob5
    cf.city || "",         // blob6
    String(cf.asn || ""),  // blob7
    cf.asOrganization || "", // blob8
    cf.colo || "",         // blob9
    (h.get("User-Agent") || "").slice(0, 512),   // blob10
    (h.get("Referer") || "").slice(0, 512),      // blob11
    (h.get("Accept-Language") || "").slice(0, 128) // blob12
  ]
  const doubles = [1]     // double1: count=1 (for SUMs)
  const indexes = [id]    // index (sampling key) → token_id

  env.LOGS.writeDataPoint({ blobs, doubles, indexes }) // fire-and-forget
  // (Optional) webhook summary
  if (env.WEBHOOK_URL) {
    const text = `Canary ${typ.toUpperCase()} hit – ${id}\nIP:${h.get("CF-Connecting-IP") || "?"} • ${cf.city || "?"},${cf.country || "?"} • ASN:${cf.asn || "?"}\nUA:${(h.get("User-Agent") || "").slice(0, 140)}\nPath:${url.pathname}`
    fetch(env.WEBHOOK_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }) }).catch(() => { })
  }
}

// --- Enhanced logging with method/search, bot tagging and IP hash ---
async function hashIpWithSalt(ip, env) {
  if (!ip) return ""
  let salt = ""
  try { salt = await getSecret(env, 'HASH_SALT') } catch { salt = "" }
  const data = new TextEncoder().encode(`${salt}|${ip}`)
  const digest = await crypto.subtle.digest("SHA-256", data)
  const bytes = new Uint8Array(digest).slice(0, 10)
  const b64 = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return b64
}

function detectBot(request) {
  const cf = request.cf || {}
  const ua = (request.headers.get("User-Agent") || "").toLowerCase()
  const bots = [
    'slackbot', 'discordbot', 'twitterbot', 'facebookexternalhit', 'linkedinbot', 'skypeuripreview',
    'whatsapp', 'telegrambot', 'google-structured-data-testing-tool', 'curl', 'wget', 'python-requests',
    'bot ', ' headless', 'selenium', 'phantomjs', 'powershell'
  ]
  for (const k of bots) if (ua.includes(k)) return { bot: 1, reason: k }
  const score = cf.botManagement && typeof cf.botManagement.score === 'number' ? cf.botManagement.score : undefined
  if (typeof score === 'number' && score < 30) return { bot: 1, reason: 'cfbm_low_score' }
  return { bot: 0, reason: '' }
}

// Override writeLog to enrich payload while keeping backward compatibility with callers
async function writeLog(env, typ, id, request, url, opts = {}) {
  const cf = request.cf || {}
  const h = request.headers
  const { bot, reason } = detectBot(request)
  const ip = h.get("CF-Connecting-IP") || ""
  const ipHash = await hashIpWithSalt(ip, env)
  const tokenKnown = opts.tokenKnown ? 1 : 0
  const blobs = [
    typ,
    id,
    url.hostname,
    url.pathname,
    cf.country || "",
    cf.city || "",
    String(cf.asn || ""),
    cf.asOrganization || "",
    cf.colo || "",
    (h.get("User-Agent") || "").slice(0, 512),
    (h.get("Referer") || "").slice(0, 512),
    (h.get("Accept-Language") || "").slice(0, 128),
    request.method || "",
    (url.search || "").slice(0, 256),
    ipHash,
    reason
  ]
  const doubles = [1, bot, tokenKnown]
  const indexes = [id]

  env.LOGS.writeDataPoint({ blobs, doubles, indexes })
  if (env.WEBHOOK_URL) {
    const text = `Canary ${typ.toUpperCase()} hit — ${id}\nIP:${ip || "?"} • ${cf.city || "?"},${cf.country || "?"} • ASN:${cf.asn || "?"}\nUA:${(h.get("User-Agent") || "").slice(0, 140)}\nPath:${url.pathname}${url.search}\nBot:${bot?"yes":"no"}`
    fetch(env.WEBHOOK_URL, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text, typ, id, ip_hash: ipHash, bot, bot_reason: reason }) }).catch(() => { })
  }
}

// Cloudflare Access JWT verification using JWKS (RS256/ES256)
let JWKS_CACHE = { exp: 0, keys: [] }
async function verifyAccessJWT(request, env) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion')
  if (!token) throw new Error('missing access token')
  const [hB64, pB64, sB64] = token.split('.')
  if (!hB64 || !pB64 || !sB64) throw new Error('malformed JWT')
  const dec = (b64) => {
    b64 = b64.replace(/-/g, '+').replace(/_/g, '/')
    const pad = b64.length % 4 === 2 ? '==': b64.length % 4 === 3 ? '=' : ''
    return new Uint8Array([...atob(b64 + pad)].map(c => c.charCodeAt(0)))
  }
  const toJSON = (bytes) => JSON.parse(new TextDecoder().decode(bytes))
  const header = toJSON(dec(hB64))
  const payload = toJSON(dec(pB64))
  // Basic claims
  const team = (env.CF_ACCESS_TEAM_DOMAIN || '').trim() // e.g. your-team.cloudflareaccess.com
  const audSecret = await getSecret(env, 'CANARY_AUD').catch(() => '')
  if (!team || !audSecret) throw new Error('missing CF_ACCESS_TEAM_DOMAIN or CANARY_AUD')
  const now = Math.floor(Date.now()/1000)
  if (typeof payload.exp === 'number' && now > payload.exp) throw new Error('jwt expired')
  if (typeof payload.nbf === 'number' && now < payload.nbf) throw new Error('jwt not yet valid')
  const expectedIss = `https://${team}`
  if ((payload.iss || '').replace(/\/?$/, '') !== expectedIss.replace(/\/?$/, '')) throw new Error('issuer mismatch')
  const reqAuds = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
  const allowedAuds = audSecret.split(',').map(s => s.trim()).filter(Boolean)
  if (!reqAuds.some(a => allowedAuds.includes(a))) throw new Error('audience mismatch')
  // Fetch JWKS (with short cache)
  const nowMs = Date.now()
  if (nowMs > JWKS_CACHE.exp) {
    const jwksUrl = `https://${team}/cdn-cgi/access/certs`
    const r = await fetch(jwksUrl, { cf: { cacheTtl: 300, cacheEverything: true } })
    if (!r.ok) throw new Error('jwks fetch failed')
    const { keys } = await r.json()
    JWKS_CACHE = { keys: keys || [], exp: nowMs + 5*60*1000 }
  }
  const jwk = JWKS_CACHE.keys.find(k => k.kid === header.kid)
  if (!jwk) throw new Error('key not found')
  // Signature verify
  const algo = header.alg
  const data = new TextEncoder().encode(`${hB64}.${pB64}`)
  const sig = dec(sB64)
  let key, ok = false
  if (algo === 'RS256') {
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    ok = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, sig, data)
  } else if (algo === 'ES256') {
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data)
  } else {
    throw new Error('unsupported alg')
  }
  if (!ok) throw new Error('signature invalid')
  return payload
}

function getTenantIdFromClaims(claims) {
  // Start simple: per-user tenant based on email; fallback to sub
  const email = (claims.email || '').toLowerCase()
  if (email) return `user:${email}`
  const sub = (claims.sub || '').toLowerCase()
  if (sub) return `sub:${sub}`
  return 'anonymous'
}

function j(obj, status = 200) { return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...cors("*") } }) }
async function safeJson(req) { try { return await req.json() } catch { return {} } }


      // ---------- ADMIN UI (serve a tiny dashboard; put /admin behind Access) ----------
      /*
      if (pathname === "/admin") {
        const html = `<!doctype html>
<meta charset="utf-8">
<title>DIY Canary – Admin</title>
<style>
  body{font:14px/1.4 system-ui, sans-serif; padding:24px; max-width:900px; margin:auto;}
  code{background:#f4f4f4; padding:2px 4px; border-radius:4px}
  .row{display:flex; gap:12px; margin:8px 0}
  input,button,select{font:inherit; padding:8px}
  table{border-collapse:collapse; width:100%}
  th,td{border-bottom:1px solid #eee; padding:8px}
</style>
<h1>DIY Canary – Admin</h1>
<div class="row">
  <select id="type">
    <option value="pixel">Pixel</option>
    <option value="lure">Lure</option>
    <option value="font">Font</option>
  </select>
  <input id="label" placeholder="Label (optional)">
  <input id="decoy" placeholder="Decoy URL (lure only)">
  <button id="create">Create</button>
</div>
<p>Tokens</p>
<table id="t"></table>
<script>
async function api(path, opts){ const r = await fetch(path, {credentials:'include', ...opts}); return r.json(); }
async function load(){
  const data = await api('/api/tokens');
  const rows = (data.tokens||[]).map(t =>
    '<tr><td>'+t.id+'</td><td>'+t.type+'</td><td>'+t.label+'</td><td>'+
    (t.type==='pixel'?'img: <code>'+location.origin+'/t/'+t.id+'.png</code>':
     t.type==='lure'?'link: <code>'+location.origin+'/l/'+t.id+'</code>':
     'css: <code>'+location.origin+'/css/'+t.id+'.css</code><br>font: <code>'+location.origin+'/f/'+t.id+'.woff2</code>')+
    '</td></tr>').join('');
  document.querySelector('#t').innerHTML = '<tr><th>ID</th><th>Type</th><th>Label</th><th>Endpoints</th></tr>'+rows;
}
document.querySelector('#create').onclick = async () => {
  const type = document.querySelector('#type').value;
  const label = document.querySelector('#label').value;
  const decoy_url = document.querySelector('#decoy').value;
  await api('/api/new', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({type, label, decoy_url})});
  load();
};
load();
</script>`
        return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } })
      }
      */
// Minimal HTML dashboard with 3 panels + token picker
const ADMIN_HTML = (origin, base) => `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIY Canary — Dashboard</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net">
<style>
  :root{--bg:#0b0d10;--fg:#e7eef8;--muted:#a3b0c2;--card:#141821;--accent:#5fb3ff}
  html,body{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;margin:0}
  header{padding:16px 20px;border-bottom:1px solid #1f2732;display:flex;gap:12px;align-items:center;justify-content:space-between}
  header .left{display:flex;gap:12px;align-items:center}
  .pill{background:#0f1320;border:1px solid #223145;color:var(--muted);padding:6px 10px;border-radius:999px}
  main{padding:18px;display:grid;grid-template-columns:1fr;gap:18px}
  @media(min-width:1000px){ main{grid-template-columns:1.2fr 1fr} }
  .card{background:var(--card); border:1px solid #1f2732; border-radius:14px; padding:14px; box-shadow:0 0 0 1px rgba(255,255,255,.02) inset}
  h2{font-size:14px; letter-spacing:.4px; text-transform:uppercase; color:var(--muted); margin:0 0 8px}
  canvas{max-width:100%; height:300px}
  table{width:100%; border-collapse:collapse; font-size:13px}
  th,td{padding:8px 6px; border-bottom:1px solid #273141}
  th{color:var(--muted); text-align:left}
  code{background:#0f1320; padding:2px 6px; border-radius:6px; color:#cfe3ff}
  .row{display:flex; gap:8px; flex-wrap:wrap}
  input,select,button{background:#0f1320; color:var(--fg); border:1px solid #223145; border-radius:10px; padding:8px 10px; font:inherit}
  button.primary{background:var(--accent); color:#041625; border:none}
  .muted{color:var(--muted)}
</style>
<header>
  <div class="left">
    <strong>DIY Canary — Dashboard</strong>
    <span class="pill">${origin}</span>
  </div>
  <div class="row">
    <select id="tokenSelect"></select>
    <button id="refresh" class="primary">Refresh</button>
  </div>
</header>
<main>
  <section class="card">
    <h2>Hits (last 24h) — Top Tokens</h2>
    <canvas id="topTokens"></canvas>
  </section>

  <section class="card">
    <h2>Hits over time by Type (last 6h)</h2>
    <canvas id="hitsSeries"></canvas>
  </section>

  <section class="card" style="grid-column:1 / -1">
    <h2>User Agents (last 7d)</h2>
    <table id="uaTable">
      <thead><tr><th>User-Agent</th><th>Hits</th></tr></thead>
      <tbody></tbody>
    </table>
    <p class="muted">Tip: pick a token to focus UA breakdown.</p>
  </section>
</main>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<script>
async function q(sql){
  const r = await fetch('${base}/api/query', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({sql}) });
  const j = await r.json();
  if(!r.ok) throw new Error(j.errors?.[0]?.message || j.error || 'Query failed');
  return j.result?.rows || [];
}

// Populate token selector from KV through API
async function listTokens(){
  const r = await fetch('/api/tokens', { credentials:'include' });
  const j = await r.json();
  const sel = document.getElementById('tokenSelect');
  sel.innerHTML = '<option value="">(All tokens)</option>' + (j.tokens||[]).map(t => '<option>'+t.id+'</option>').join('');
}

let charts = {};
function upsertChart(id, cfg){
  if(charts[id]) { charts[id].destroy(); }
  charts[id] = new Chart(document.getElementById(id), cfg);
}

async function load(){
  const token = document.getElementById('tokenSelect').value.trim();

  // 1) Top tokens 24h
  const rows1 = await q(\`
    SELECT blob2 AS token_id, SUM(_sample_interval * double1) AS hits
    FROM ${encodeURIComponent('canary_events')}
    WHERE timestamp >= NOW() - INTERVAL '1' DAY
    GROUP BY token_id
    ORDER BY hits DESC
    LIMIT 12;
\`.replace('canary_events', '${AE_DATASET_PLACEHOLDER}'));
  const labels1 = rows1.map(r => r[0]);
  const data1   = rows1.map(r => r[1]);
  upsertChart('topTokens', { type:'bar', data:{ labels:labels1, datasets:[{ label:'Hits', data:data1 }] }, options:{ responsive:true, plugins:{legend:{display:false}} } });

  // 2) Series by type 6h, 5-min bins
  const rows2 = await q(\`
SELECT
intDiv(toUInt32(timestamp), 300) * 300 AS t,
  blob1 AS type,
    SUM(_sample_interval * double1) AS hits
    FROM ${encodeURIComponent('canary_events')}
    WHERE timestamp >= NOW() - INTERVAL '6' HOUR
    GROUP BY t, type
    ORDER BY t ASC, type ASC;
\`.replace('canary_events', '${AE_DATASET_PLACEHOLDER}'));
  const ts = [...new Set(rows2.map(r => r[0]))].sort((a,b)=>a-b);
  const types = [...new Set(rows2.map(r => r[1]))];
  const series = types.map(tp => ts.map(t => {
    const row = rows2.find(r => r[0]===t && r[1]===tp);
    return row ? row[2] : 0;
  }));
  upsertChart('hitsSeries', {
    type:'line',
    data:{ labels: ts.map(t => new Date(t*1000).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})),
           datasets: types.map((tp,i)=>({ label: tp, data: series[i], tension:.2 })) },
    options:{ responsive:true }
  });

  // 3) UA table 7d (optionally filtered by token)
  const where = token ? "AND blob2 = '"+token.replace(/'/g,"''")+"'": "";
  const rows3 = await q(\`
    SELECT blob10 AS user_agent, SUM(_sample_interval * double1) AS hits
    FROM ${encodeURIComponent('canary_events')}
    WHERE timestamp >= NOW() - INTERVAL '7' DAY ${where}
    GROUP BY user_agent
    ORDER BY hits DESC
    LIMIT 50;
\`.replace('canary_events', '${AE_DATASET_PLACEHOLDER}'));
  const tbody = document.querySelector('#uaTable tbody');
  tbody.innerHTML = rows3.map(r => '<tr><td><code>'+ (r[0]||'') +'</code></td><td>'+ r[1] +'</td></tr>').join('');
}

document.getElementById('refresh').onclick = load;
document.getElementById('tokenSelect').onchange = load;
listTokens().then(load);
</script>
`
