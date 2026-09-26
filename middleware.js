/* PG Track access gate.

   Runs on Vercel's edge BEFORE any file is served, so an unapproved visitor
   never receives index.html at all — not the questions, not the plans, not
   even hidden in the page source. A client-side gate could not promise that.

   Who gets in is driven by two environment variables set in the Vercel
   dashboard (never in this repo, which is public on GitHub):
     PGT_CODES   comma-separated access codes, one per person
     PGT_SECRET  random string used to sign the "you're in" cookie

   Adding a person = add a code to PGT_CODES. Revoking = delete their code.
   Changing PGT_SECRET logs everyone out at once. */

const COOKIE = "pgt_pass";
const MAX_AGE = 60 * 60 * 24 * 60; // 60 days

/* Everything is gated except the PWA shell files, which carry no content and
   must stay reachable for install-to-home-screen to work. */
export const config = {
  matcher: ["/((?!icons/|manifest\.webmanifest|sw\.js|favicon\.ico|robots\.txt).*)"],
};

const enc = new TextEncoder();

async function sign(message, secret) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* Compare without leaking, through response time, how much of the value matched. */
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(request, name) {
  const raw = request.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return null;
}

function allowedCodes() {
  return (process.env.PGT_CODES || "")
    .split(",").map(c => c.trim().toUpperCase()).filter(Boolean);
}

async function ticketFor(code, secret) {
  const expiry = Date.now() + MAX_AGE * 1000;
  return `${expiry}.${code}.${await sign(`${expiry}.${code}`, secret)}`;
}

async function ticketValid(ticket, secret) {
  if (!ticket) return false;
  const parts = ticket.split(".");
  if (parts.length !== 3) return false;
  const [expiry, code, sig] = parts;
  if (!/^\d+$/.test(expiry) || Number(expiry) < Date.now()) return false;
  /* A code deleted from PGT_CODES must stop working immediately, even if the
     holder still has an unexpired cookie. */
  if (!allowedCodes().includes(code.toUpperCase())) return false;
  return safeEqual(sig, await sign(`${expiry}.${code}`, secret));
}

function loginPage(message, tone) {
  const note = message
    ? `<p class="note ${tone}">${message}</p>`
    : `<p class="note">Codes are issued by Dr. Andy.</p>`;
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#f6f4f0">
<title>PG Track</title>
<style>
  :root{ --page:#F6F4F0; --card:#FFFFFF; --ink:#2A221D; --muted:#7D7168;
         --soft:#A2958A; --accent:#C2603C; }
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       padding:24px;background:var(--page);color:var(--ink);
       font-family:Calibri,"Segoe UI",system-ui,sans-serif;}
  .card{background:var(--card);border-radius:14px;padding:36px 30px;width:100%;
        max-width:380px;box-shadow:0 1px 3px rgba(42,34,29,.07);}
  h1{font-family:Cambria,Georgia,serif;font-weight:600;font-size:28px;margin:0 0 6px;}
  .sub{color:var(--muted);font-size:15px;margin:0 0 26px;}
  label{display:block;font-size:14px;color:var(--muted);margin-bottom:8px;}
  input{width:100%;padding:13px 14px;font-size:17px;font-family:inherit;color:var(--ink);
        background:var(--page);border:1px solid #E3DCD3;border-radius:9px;
        letter-spacing:.5px;}
  input:focus{outline:none;border-color:var(--accent);}
  button{width:100%;margin-top:16px;padding:14px;font-size:16px;font-family:inherit;
         color:#F0E7DA;background:#221D18;border:0;border-radius:9px;cursor:pointer;}
  button:hover{background:var(--accent);}
  .note{font-size:13px;color:var(--soft);margin:22px 0 0;line-height:1.5;}
  .note.bad{color:var(--accent);}
  .mark{width:72px;height:72px;border-radius:17px;overflow:hidden;margin:0 0 18px;
        box-shadow:0 12px 26px -16px rgba(60,45,30,.55);}
  .mark svg{display:block;width:100%;height:100%}
  .mark .d{stroke-dasharray:1 1;animation:draw .5s cubic-bezier(.3,0,.4,1) .15s both}
  .mark .g{animation:beat .7s ease-out .5s both}
  @keyframes draw{from{stroke-dashoffset:1;opacity:0}6%{opacity:1}to{stroke-dashoffset:0}}
  @keyframes beat{0%{opacity:0}35%{opacity:1}100%{opacity:.7}}
  @media (prefers-reduced-motion:reduce){.mark *{animation:none!important}}
</style></head><body>
<div class="card">
  <div class="mark" aria-hidden="true"><svg viewBox="0 0 400 400"><defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#e8d7c4"/><stop offset="1" stop-color="#c8ab8d"/></linearGradient><filter id="gl" x="-20%" y="-50%" width="140%" height="200%"><feGaussianBlur stdDeviation="7"/></filter></defs><rect width="400" height="400" fill="url(#g)"/><rect y="300" width="400" height="100" fill="#bfa184" opacity=".45"/><path d="M40 300 H196 L214 300 L230 256 L248 344 L266 176 L284 300 H360" fill="none" stroke="#e9dccd" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/><g fill="none" stroke-width="34" stroke-linecap="round" stroke-linejoin="round"><path d="M110 300 V100 H186 A60 60 0 0 1 186 220 H110" transform="translate(14 16)" stroke="#9c7e61"/><path d="M110 300 V100 H186 A60 60 0 0 1 186 220 H110" transform="translate(7 8)" stroke="#6e5641"/><path d="M110 300 V100 H186 A60 60 0 0 1 186 220 H110" stroke="#201e1d"/></g><g fill="none" stroke-linecap="round" stroke-linejoin="round"><path class="g" d="M40 300 H196 L214 300 L230 256 L248 344 L266 176 L284 300 H360" stroke="#e8603c" stroke-width="22" opacity=".7" filter="url(#gl)"/><path class="d" pathLength="1" d="M40 300 H196 L214 300 L230 256 L248 344 L266 176 L284 300 H360" stroke="#cf5433" stroke-width="12"/><path class="d" pathLength="1" d="M40 300 H196 L214 300 L230 256 L248 344 L266 176 L284 300 H360" stroke="#ffd9c8" stroke-width="3"/></g></svg></div>
  <h1>PG Track</h1>
  <p class="sub">NEET PG coaching &middot; Dr. Andy</p>
  <form method="POST" action="/__gate">
    <label for="code">Enter your access code</label>
    <input id="code" name="code" autocomplete="off" autocapitalize="characters"
           spellcheck="false" autofocus placeholder="NAME-0000-0000">
    <button type="submit">Continue</button>
  </form>
  ${note}
</div></body></html>`;
}

function pageResponse(html, status, cookie) {
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-robots-tag": "noindex, nofollow",
  };
  if (cookie) headers["set-cookie"] = cookie;
  return new Response(html, { status, headers });
}

export default async function middleware(request) {
  const url = new URL(request.url);
  const secret = process.env.PGT_SECRET;
  const codes = allowedCodes();

  if (!secret || codes.length === 0) {
    return pageResponse(
      loginPage("This app is not configured yet. PGT_CODES and PGT_SECRET are missing in Vercel.", "bad"),
      503
    );
  }

  if (url.pathname === "/__gate") {
    if (request.method === "POST") {
      const form = await request.formData();
      const entered = String(form.get("code") || "").trim().toUpperCase();
      if (codes.includes(entered)) {
        const ticket = await ticketFor(entered, secret);
        return new Response(null, {
          status: 303,
          headers: {
            location: "/",
            "set-cookie": `${COOKIE}=${encodeURIComponent(ticket)}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
          },
        });
      }
      return pageResponse(loginPage("That code was not recognised. Check it and try again.", "bad"), 401);
    }
    if (url.searchParams.has("logout")) {
      return pageResponse(
        loginPage("You are signed out.", ""),
        200,
        `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
      );
    }
    return pageResponse(loginPage("", ""), 200);
  }

  if (await ticketValid(readCookie(request, COOKIE), secret)) return; // let the file through

  return pageResponse(loginPage("", ""), 401);
}
