import { connect } from 'cloudflare:sockets';

/* =============================================================================
   ASA Events - registration API (Cloudflare Worker + D1)
   Endpoints:
     POST /v1/invitations/verify   check the invitation code, return a session
                                    token immediately — no email-ownership
                                    check (an invitation may cover more than
                                    one event; returns event_codes it
                                    currently unlocks, not tied to one event)
     POST /v1/registrations        store the submission as under_review — one
                                    row per person, covering every event_code
                                    in event_codes[] they selected
     POST /v1/registrations/edit-link   email a 30-day self-service edit link
                                    for a (reference, email) pair, if it matches
     POST /v1/registrations/edit-fetch  return one registration's data (reference + token)
     POST /v1/registrations/edit        update it in place (reference + token)
     GET  /v1/admin/registrations  read the data back (Bearer ADMIN_TOKEN)
     GET  /v1/admin/export.csv     same data as CSV (summary columns only)
     GET  /v1/admin/export.json    full submissions incl. every form field (Bearer ADMIN_TOKEN or VIEWER_TOKEN).
                                    Pass ?src=<page> (report/dashboard/logistics/badges) so a viewer/named-token
                                    access gets logged as 'report_accessed' with which page it was; skipped for
                                    ADMIN_TOKEN traffic, since logging the admin's own every page load would
                                    just flood the audit trail with nothing anyone needs to see.
     GET  /v1/admin/invitations    list invitation codes (Bearer ADMIN_TOKEN)
     POST /v1/admin/invitations    generate a new invitation code (Bearer ADMIN_TOKEN)
     POST /v1/uploads               store one attachment in R2 (Bearer session), returns its key
     GET  /v1/admin/files?key=...  download a stored attachment (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     GET  /v1/admin/attachments?reference=... list one registration's attachments (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     POST /v1/admin/registrations/status  set status to under_review/approved/rejected, emails the applicant (Bearer ADMIN_TOKEN)
     POST /v1/admin/registrations/tier    set participant_tier to president/vice_president/other, never emailed (Bearer ADMIN_TOKEN)
     POST /v1/admin/registrations/delete  permanently delete one registration, its check-ins, and every file it
                                    uploaded; decrements the invitation's used_count. Full ADMIN_TOKEN only --
                                    never satisfiable by a named token's 'registrations' scope, no matter how
                                    broad. audit_log itself is untouched, only the deletion is logged.
     POST /v1/admin/registrations/edit-token  mint an edit-link token for any reference, opens the same public
                                    edit form; the resulting save is never emailed to the registrant (Bearer ADMIN_TOKEN)
     GET  /v1/admin/field-values?field=organization_name|official_hotel  distinct values in use, with counts (Bearer ADMIN_TOKEN)
     POST /v1/admin/field-values/rename  merge a set of "from" spellings into one "to" value across every
                                    matching registration, e.g. reconciling "JAZ Pyramids" vs "Jaz Pyramids Resort" (Bearer ADMIN_TOKEN)
     POST /v1/admin/reminders/send  email one consolidated "missing data" reminder per selected registration,
                                    covering only the admin-chosen categories (itinerary/hotel/presentation/
                                    accompanying), with the registrant's own edit link (Bearer ADMIN_TOKEN).
                                    Pass preview:true to compose and return the same emails without sending
                                    them or touching the database/audit trail.
     POST /v1/admin/announce/send   free-form broadcast: {subject, body, references[]} to up to 100 confirmed
                                    registrants per call (Bearer ADMIN_TOKEN). Pass preview:true to compose
                                    and return without sending or touching the audit trail.
     GET  /v1/admin/audit           recent audit-trail entries (Bearer ADMIN_TOKEN only — not VIEWER_TOKEN)
     POST /v1/admin/checkin         reception scan/lookup: resolves a badge QR ("regnum|event_code") or a
                                    manual {regnum, event_code} pair, records a check-in the first time and
                                    returns the same participant data either way (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     GET  /v1/admin/checkins        recent check-ins across both events, newest first (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     POST /v1/admin/checkin/undo    remove one (reference, event_code) check-in, correcting a mis-scan
                                    (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     POST /v1/client-error          log one error the browser caught and showed to a registrant before it ever
                                    reached another endpoint (a bad invitation code or email caught by the
                                    gate page's own validation, no event selected, etc.) -- flow/code must be
                                    on the fixed allowlist (CLIENT_ERROR_CODES) or the call is silently ignored
     GET  /v1/admin/backups         list disaster-recovery snapshots held in R2, newest first (Bearer ADMIN_TOKEN)
     GET  /v1/admin/backups/download?key=...  download one snapshot (Bearer ADMIN_TOKEN)
     POST /v1/admin/backups/run     take an on-demand snapshot right now, same as the nightly Cron Trigger
                                    (see the scheduled() export) (Bearer ADMIN_TOKEN)
     GET  /v1/admin/whoami          which tier (admin/viewer/named) and which scopes the supplied token
                                    grants -- the admin hub uses this to show only the pages a token can use
     GET  /v1/admin/access-tokens   list named access tokens (name, scopes, active, last used) (Bearer ADMIN_TOKEN)
     POST /v1/admin/access-tokens   create a named token with an explicit scope subset (see ALL_SCOPES);
                                    the plaintext token is returned exactly once and never stored (Bearer ADMIN_TOKEN)
     POST /v1/admin/access-tokens/revoke  deactivate one named token by id (Bearer ADMIN_TOKEN)
   Everywhere above marked "Bearer ADMIN_TOKEN or VIEWER_TOKEN" also accepts
   a named access token carrying the scope that endpoint needs (see
   ALL_SCOPES/resolveAccess() below) -- ADMIN_TOKEN implicitly has every
   scope, VIEWER_TOKEN implicitly has every report-tier scope, a named
   token has exactly whatever it was created with. Endpoints marked
   "Bearer ADMIN_TOKEN" only accept the real admin token or a named token
   scoped to that specific page (e.g. reminders/send needs the 'reminders'
   scope) -- never satisfiable by VIEWER_TOKEN or an unrelated scope.
   Every error a registrant/editor/uploader can see on the public paths above
   is also written to audit_log as one 'error_shown' action (entity = which
   flow, entity_id = the error code, detail = whatever identifies who hit it).
   The events worth knowing about right away (new registration, edit, status
   change, invalid code, new invitation code, edit-link request, every error)
   also fire a Telegram message when TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID are
   set (secrets) — silently a no-op otherwise.
   Every admin-write request may carry an X-Actor-Name header (the "Your
   name" field stored in the admin pages' localStorage) -- self-reported,
   never trusted for authorization, just a label so the audit trail and
   Telegram alerts show who at the desk did something, not only which
   shared token they were holding.
   Nothing here trusts the browser: every rule in the form is re-checked.
   ============================================================================= */

const CODE_RE = /^ASA-[A-Z0-9]{3,10}-[A-Z]{2,4}-[A-Z0-9]{4}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const FREE_MAIL = ['gmail.com','yahoo.com','hotmail.com','outlook.com','live.com','icloud.com','aol.com','proton.me','protonmail.com','mail.ru','yandex.com','gmx.com'];
const DISPOSABLE = ['mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com','yopmail.com','trashmail.com','sharklasers.com'];
const MIN_FILL_SECONDS = 15;
const UPLOAD_ACCEPT = {
  any: ['application/pdf', 'image/jpeg', 'image/png'],
  image: ['image/jpeg', 'image/png'],
  doc: ['application/pdf', 'application/vnd.openxmlformats-officedocument.presentationml.presentation']
};
const UPLOAD_MAX_MB = { any: 15, image: 10, doc: 50 };
const PUBLIC_PATHS = new Set(['/v1/invitations/verify', '/v1/registrations', '/v1/registrations/edit-link',
  '/v1/registrations/edit-fetch', '/v1/registrations/edit', '/v1/uploads', '/v1/client-error']);

/* ---------- small helpers ---------- */
const now = () => Math.floor(Date.now() / 1000);
const domainOf = (e) => String(e || '').split('@')[1]?.toLowerCase() || '';
const enc = new TextEncoder();

function cors(req, env) {
  const origin = req.headers.get('Origin') || '';
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim());
  return {
    'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0] || '',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
const json = (data, status, headers) =>
  new Response(JSON.stringify(data), { status: status || 200, headers: { 'Content-Type': 'application/json', ...headers } });
const fail = (error, status, headers) => json({ ok: false, error }, status || 400, headers);

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', enc.encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const b64u = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => atob(s.replace(/-/g, '+').replace(/_/g, '/'));

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(text));
  return b64u(String.fromCharCode(...new Uint8Array(sig)));
}
async function signSession(env, payload) {
  const body = b64u(JSON.stringify(payload));
  return body + '.' + await hmac(env.SESSION_SECRET, body);
}
async function readSession(env, token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (await hmac(env.SESSION_SECRET, body) !== sig) return null;
  try {
    const p = JSON.parse(unb64u(body));
    return p.exp > now() ? p : null;
  } catch (e) { return null; }
}

/* Self-service edit links. Namespaced ('edit:' prefix on the signed text) so
   an edit token can never be replayed as a login session or vice versa.
   opts.admin marks a token minted by an admin (not emailed to the
   registrant) -- updateRegistration reads it back off the token to decide
   whether to send the "your registration has been updated" email, so the
   flag travels with the token itself rather than a client-supplied one
   that anyone holding a normal edit link could just as easily claim. */
async function signEditToken(env, registrationId, opts) {
  const body = b64u(JSON.stringify({ r: registrationId, exp: now() + 60 * 60 * 24 * 30, admin: !!(opts && opts.admin) }));
  return body + '.' + await hmac(env.SESSION_SECRET, 'edit:' + body);
}
async function readEditToken(env, token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (await hmac(env.SESSION_SECRET, 'edit:' + body) !== sig) return null;
  try {
    const p = JSON.parse(unb64u(body));
    return p.exp > now() ? p : null;
  } catch (e) { return null; }
}

/* Fixed-window counter in D1. Returns false when the caller is over budget. */
async function allow(env, key, limit, windowSec) {
  const t = now();
  const row = await env.DB.prepare('SELECT n, reset_at FROM throttle WHERE k = ?').bind(key).first();
  if (!row || row.reset_at < t) {
    await env.DB.prepare('INSERT INTO throttle (k,n,reset_at) VALUES (?,1,?) ON CONFLICT(k) DO UPDATE SET n=1, reset_at=excluded.reset_at')
      .bind(key, t + windowSec).run();
    return true;
  }
  if (row.n >= limit) return false;
  await env.DB.prepare('UPDATE throttle SET n = n + 1 WHERE k = ?').bind(key).run();
  return true;
}

/* actor is optional and only ever admin-supplied (see the X-Actor-Name
   header, read once in the router below) -- ADMIN_TOKEN/VIEWER_TOKEN are
   shared secrets, not per-person logins, so without it every admin action
   in the trail is attributed to "whoever had the token" and nothing more.
   Public, registrant-facing actions never carry one. */
async function audit(env, action, entity, entityId, detail, ipHash, actor) {
  await env.DB.prepare('INSERT INTO audit_log (action,entity,entity_id,detail,ip_hash,actor,created_at) VALUES (?,?,?,?,?,?,?)')
    .bind(action, entity || null, entityId || null, detail || null, ipHash || null, actor || null, new Date().toISOString()).run();
}

/* Every error message a registrant (or someone editing/uploading) can actually
   see, logged as one 'error_shown' action -- entity is which flow it happened
   in, entity_id is the error code shown, detail is whatever identifies who hit
   it (email, reference, or a validation field list) when that's known yet.
   Never lets a logging failure break the real response. */
async function auditError(env, flow, code, detail, ipHash) {
  try { await audit(env, 'error_shown', flow, code, detail, ipHash); } catch (e) { /* logging must never break the response */ }
  await notifyTelegram(env, `❗ <b>Error shown</b> — ${esc(flow)}: ${esc(code)}${detail ? '\n' + esc(detail) : ''}`);
}

/* Optional real-time alert to a Telegram chat (TELEGRAM_BOT_TOKEN +
   TELEGRAM_CHAT_ID secrets) for the audit events worth knowing about right
   away. A no-op until both secrets are set; never lets a Telegram outage or
   a bad token break the real response. */
function esc(s) { return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
async function notifyTelegram(env, text) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text, parse_mode: 'HTML', disable_web_page_preview: true })
    });
  } catch (e) { /* a notification failure must never break the real response */ }
}

/* Minimal SMTP client over a raw TLS socket (Workers TCP Sockets), used to
   send genuinely "From" a Gmail address via an App Password — something no
   third-party sender (Resend included) can do, since Google only accepts
   mail claiming to be @gmail.com when it actually comes from Google's own
   servers with real account credentials. */
async function sendMailGmail(env, to, subject, html) {
  const socket = connect({ hostname: 'smtp.gmail.com', port: 465 }, { secureTransport: 'on' });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let buf = '';

  async function readResponse() {
    while (true) {
      const m = buf.match(/(\d{3}) [^\r\n]*\r\n/);
      if (m) {
        const end = buf.indexOf('\r\n', m.index) + 2;
        const block = buf.slice(0, end);
        buf = buf.slice(end);
        return block;
      }
      const { value, done } = await reader.read();
      if (done) throw new Error('smtp_connection_closed');
      buf += dec.decode(value, { stream: true });
    }
  }
  async function cmd(text) {
    await writer.write(enc.encode(text + '\r\n'));
    const resp = await readResponse();
    if (!/^[23]/.test(resp)) throw new Error('smtp_error: ' + resp.trim());
    return resp;
  }

  try {
    const greeting = await readResponse();
    if (!/^2/.test(greeting)) throw new Error('smtp_error: ' + greeting.trim());
    await cmd('EHLO asa-events-api');
    await cmd('AUTH LOGIN');
    await cmd(btoa(env.GMAIL_ADDRESS));
    await cmd(btoa(env.GMAIL_APP_PASSWORD));
    await cmd(`MAIL FROM:<${env.GMAIL_ADDRESS}>`);
    await cmd(`RCPT TO:<${to}>`);
    await cmd('DATA');
    const message = [
      `From: ASA Events <${env.GMAIL_ADDRESS}>`,
      `To: <${to}>`,
      `Subject: ${subject}`,
      `Date: ${new Date().toUTCString()}`,
      `MIME-Version: 1.0`,
      `Content-Type: text/html; charset=UTF-8`,
      ``,
      html
    ].join('\r\n').split('\r\n').map(l => (l.startsWith('.') ? '.' + l : l)).join('\r\n');
    await writer.write(enc.encode(message + '\r\n.\r\n'));
    const dataResp = await readResponse();
    if (!/^2/.test(dataResp)) throw new Error('smtp_error: ' + dataResp.trim());
    await writer.write(enc.encode('QUIT\r\n'));
    return { ok: true };
  } finally {
    try { await writer.close(); } catch (e) { }
    try { socket.close(); } catch (e) { }
  }
}

async function sendMail(env, to, subject, html) {
  if (env.GMAIL_ADDRESS && env.GMAIL_APP_PASSWORD) {
    try {
      const r = await sendMailGmail(env, to, subject, html);
      console.log('gmail_send_ok', to, subject);
      return r;
    } catch (e) {
      console.error('gmail_send_failed', to, subject, String((e && e.message) || e));
      return { ok: false, error: String((e && e.message) || e) };
    }
  }
  if (!env.RESEND_API_KEY) return { skipped: true };
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.MAIL_FROM, to: [to], subject, html,
      ...(env.REPLY_TO ? { reply_to: env.REPLY_TO } : {})
    })
  });
  return { ok: r.ok, status: r.status };
}

const shell = (bodyHtml) => `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;color:#0B2135;line-height:1.6;max-width:560px">
${bodyHtml}
<hr style="border:0;border-top:1px solid #CBD6E0;margin:24px 0">
<p style="font-size:12px;color:#556A7D">The Organizing Secretariat<br>Accountability State Authority (SAI Egypt)</p></div>`;

const VENUE = 'Steigenberger Pyramids Cairo Hotel, Giza';
const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
/* Combined "28–30 September 2026" style range across whichever events were selected. */
function formatDateRange(events) {
  if (!events.length) return '';
  const starts = events.map(e => new Date(e.start_date + 'T00:00:00Z'));
  const ends = events.map(e => new Date(e.end_date + 'T00:00:00Z'));
  const start = new Date(Math.min(...starts));
  const end = new Date(Math.max(...ends));
  const sD = start.getUTCDate(), sM = MONTHS[start.getUTCMonth()], sY = start.getUTCFullYear();
  const eD = end.getUTCDate(), eM = MONTHS[end.getUTCMonth()], eY = end.getUTCFullYear();
  if (sD === eD && sM === eM && sY === eY) return `${sD} ${sM} ${sY}`;
  if (sM === eM && sY === eY) return `${sD}–${eD} ${sM} ${sY}`;
  if (sY === eY) return `${sD} ${sM} – ${eD} ${eM} ${sY}`;
  return `${sD} ${sM} ${sY} – ${eD} ${eM} ${eY}`;
}
const SALUTATION_DISPLAY = { HE: 'H.E.', Dr: 'Dr', Mr: 'Mr', Mrs: 'Mrs', Ms: 'Ms' };
const greetingName = (d) => {
  const sal = SALUTATION_DISPLAY[d.salutation] || d.salutation || '';
  const name = [d.first_name_passport, d.family_name_passport].filter(Boolean).join(' ');
  return [sal, name].filter(Boolean).join(' ');
};

/* ---------- endpoints ---------- */

async function verifyInvitation(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const code = String(b.invitation_code || '').toUpperCase().trim();
  const email = String(b.email || '').toLowerCase().trim();

  if (!await allow(env, 'inv:' + ipHash, 30, 3600)) { await auditError(env, 'invitation_verify', 'rate_limited', email, ipHash); return fail('rate_limited', 429, ch); }
  if (!EMAIL_RE.test(email)) { await auditError(env, 'invitation_verify', 'invalid_email', email, ipHash); return fail('invalid_email', 400, ch); }
  if (DISPOSABLE.includes(domainOf(email))) { await auditError(env, 'invitation_verify', 'disposable_email', email, ipHash); return fail('disposable_email', 403, ch); }
  if (!CODE_RE.test(code)) { await auditError(env, 'invitation_verify', 'invalid_code_format', code, ipHash); return fail('invalid_code', 400, ch); }

  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE code = ? AND is_active = 1').bind(code).first();
  /* One generic message for every failure: never confirm which half was wrong. */
  if (!inv) {
    await audit(env, 'invitation_verify_failed', 'invitation', code, null, ipHash);
    await notifyTelegram(env, `⚠️ <b>Invalid invitation code entered</b>\n"${esc(code)}" — ${esc(email)}`);
    return fail('invalid_code', 400, ch);
  }
  if (inv.expires_at && Date.parse(inv.expires_at + 'T23:59:59Z') < Date.now()) { await auditError(env, 'invitation_verify', 'code_expired', code, ipHash); return fail('invalid_code', 400, ch); }
  if (inv.max_uses !== null && inv.used_count >= inv.max_uses) { await auditError(env, 'invitation_verify', 'code_exhausted', code, ipHash); return fail('invalid_code', 400, ch); }

  /* A code can cover more than one event; only offer the ones still open. */
  const { results: coveredEvents } = await env.DB.prepare(
    `SELECT e.code, e.title_en, e.title_ar, e.registration_closes_at
     FROM invitation_events ie JOIN events e ON e.code = ie.event_code
     WHERE ie.invitation_id = ? AND e.is_active = 1`).bind(inv.invitation_id).all();
  const openEvents = coveredEvents.filter(e => !e.registration_closes_at || Date.parse(e.registration_closes_at) >= Date.now());
  if (!openEvents.length) { await auditError(env, 'invitation_verify', 'registration_closed', code, ipHash); return fail('registration_closed', 410, ch); }

  if (FREE_MAIL.includes(domainOf(email)) && !inv.allow_free_email) {
    await auditError(env, 'invitation_verify', 'free_email_not_allowed', email, ipHash);
    return fail('free_email_not_allowed', 403, ch);
  }

  /* No email-ownership check: a valid invitation code plus a plausible email
     address is enough to unlock the form, and issues a session immediately. */
  /* 24h, not the usual short session window: this form is long enough (passport,
     travel, accommodation, uploads...) that a real applicant filling it in one
     unhurried sitting can plausibly take a couple of hours. */
  const session = await signSession(env, { e: email, iv: inv.invitation_id, exp: now() + 86400 });
  await audit(env, 'invitation_verified', 'invitation', inv.invitation_id, email, ipHash);
  return json({ ok: true, organization_name: inv.organization_name, country: inv.country,
                allow_free_email: !!inv.allow_free_email, session,
                invitation_id: inv.invitation_id, event_codes: openEvents.map(e => e.code) }, 200, ch);
}

/* Shared by create and edit: the rules the browser already checked, re-checked here. */
function requiredFieldErrors(d) {
  const missing = [];
  for (const k of ['first_name_passport','family_name_passport','nationality','mobile',
                   'organization_name','country','job_title','role_in_delegation',
                   'consent_processing','signature_typed_name'])
    if (!d[k]) missing.push(k);
  return missing;
}
const fullNameOf = (d) => [d.first_name_passport, d.family_name_passport].filter(Boolean).join(' ');

/* Free-text fields that every report groups people by (SAI/organisation,
   hotel name) are the ones a stray leading/trailing space silently turns
   into a second, invisible-in-the-UI bucket -- "OFFICE OF THE AUDITOR
   GENERAL " and "OFFICE OF THE AUDITOR GENERAL" look identical but group
   separately everywhere. Trim them at the point of entry so this class of
   duplicate can't be created going forward. Mutates and returns d so the
   same trimmed value ends up in data_json and the top-level column alike. */
function normalizeFreeText(d) {
  for (const k of ['organization_name', 'official_hotel', 'own_hotel_name_address']) {
    if (typeof d[k] === 'string') d[k] = d[k].trim();
  }
  return d;
}

async function createRegistration(req, env, ch, ipHash) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const s = await readSession(env, token);
  if (!s) { await auditError(env, 'registration_submit', 'session_expired', null, ipHash); return fail('session_expired', 401, ch); }
  if (!await allow(env, 'reg:' + ipHash, 10, 3600)) { await auditError(env, 'registration_submit', 'rate_limited', s.e, ipHash); return fail('rate_limited', 429, ch); }

  const b = await req.json().catch(() => ({}));
  const d = normalizeFreeText(b.registration || {});
  const requested = Array.isArray(b.event_codes) ? [...new Set(b.event_codes.map(String))] : [];
  if (!requested.length) { await auditError(env, 'registration_submit', 'no_events_selected', s.e, ipHash); return fail('no_events_selected', 400, ch); }
  if ((b.fill_seconds || 0) < MIN_FILL_SECONDS) { await auditError(env, 'registration_submit', 'too_fast', s.e, ipHash); return fail('too_fast', 400, ch); }

  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE invitation_id = ?').bind(s.iv).first();
  if (!inv) { await auditError(env, 'registration_submit', 'invalid_invitation', s.e, ipHash); return fail('invalid_invitation', 400, ch); }

  /* Never trust which events the client says it wants — only the ones this
     invitation actually covers are eligible, regardless of what was posted. */
  const { results: covered } = await env.DB.prepare(
    `SELECT e.* FROM invitation_events ie JOIN events e ON e.code = ie.event_code
     WHERE ie.invitation_id = ? AND e.is_active = 1`).bind(s.iv).all();
  const coveredMap = new Map(covered.map(e => [e.code, e]));
  const targets = requested.filter(c => coveredMap.has(c));
  if (!targets.length) { await auditError(env, 'registration_submit', 'invalid_event_selection', s.e, ipHash); return fail('invalid_event_selection', 400, ch); }

  const openTargets = targets.filter(c => {
    const ev = coveredMap.get(c);
    return !ev.registration_closes_at || Date.parse(ev.registration_closes_at) >= Date.now();
  });
  if (!openTargets.length) { await auditError(env, 'registration_submit', 'registration_closed', s.e, ipHash); return fail('registration_closed', 410, ch); }

  const missing = requiredFieldErrors(d);
  if (missing.length) {
    await auditError(env, 'registration_submit', 'validation_failed', `${s.e}: ${missing.slice(0, 12).join(', ')}`, ipHash);
    return json({ ok: false, error: 'validation_failed', fields: missing }, 400, ch);
  }

  /* One person, one row — even when the invitation covers more than one event. */
  const dup = await env.DB.prepare('SELECT reference FROM registrations WHERE email = ?').bind(s.e).first();
  if (dup) {
    await auditError(env, 'registration_submit', 'duplicate_registration', `${s.e} (already ${dup.reference})`, ipHash);
    return json({ ok: false, error: 'duplicate_registration', reference: dup.reference }, 409, ch);
  }

  const fullName = fullNameOf(d);
  const orgMismatch = d.organization_name &&
    d.organization_name.trim().toLowerCase() !== String(inv.organization_name).trim().toLowerCase();

  const id = crypto.randomUUID();
  const ref = 'SUB-' + [...crypto.getRandomValues(new Uint8Array(4))]
    .map(x => 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'[x % 31]).join('');

  /* Confirmed immediately — no separate secretariat approval step. */
  const targetEvents = openTargets.map(c => coveredMap.get(c));
  const { count } = await env.DB.prepare(
    'SELECT COUNT(*) AS count FROM registrations WHERE registration_number IS NOT NULL').first();
  const regNumber = `${openTargets[0]}-${String(count + 1).padStart(4, '0')}`;

  await env.DB.prepare(
    `INSERT INTO registrations (registration_id, reference, event_codes, invitation_id, email, full_name,
      organization_name, country, attendance_mode, role_in_delegation, visa_letter_needed, status,
      registration_number, data_json, consents_json, flag_personal_email, flag_org_mismatch, source_ip_hash, fill_seconds, locale, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?, 'approved', ?,?,?,?,?,?,?,?,?)`)
    .bind(id, ref, openTargets.join(','), s.iv, s.e, fullName, d.organization_name || null, d.country || null,
      'in_person', d.role_in_delegation || null, d.visa_letter_needed === 'yes' ? 1 : 0,
      regNumber, JSON.stringify(d), JSON.stringify(b.consents || {}),
      b.personal_email ? 1 : 0, orgMismatch ? 1 : 0, ipHash, b.fill_seconds || null,
      b.locale || 'en', new Date().toISOString()).run();

  await env.DB.prepare('UPDATE invitations SET used_count = used_count + 1 WHERE invitation_id = ?').bind(s.iv).run();
  await audit(env, 'registration_submitted', 'registration', id, ref, ipHash);
  await notifyTelegram(env, `🆕 <b>New registration</b>\n${esc(fullName || '(no name)')} — ${esc(d.organization_name || '?')}\n${esc(regNumber)} · ${esc(ref)}`);

  const combinedLabel = targetEvents.length > 1 ? 'WGITA & KSC Annual Meetings' : targetEvents[0].title_en;
  const dateRange = formatDateRange(targetEvents);
  const eventList = targetEvents.map(e => `<li>${e.title_en}</li>`).join('');
  const editLink = `${env.FRONTEND_BASE || ''}/register/?edit=${encodeURIComponent(ref)}.${encodeURIComponent(await signEditToken(env, id))}`;
  const body = `<h2 style="font-size:18px;margin:0 0 4px">Registration confirmed</h2>
    <p>Dear ${greetingName(d)},</p>
    <p>Your registration for the ${combinedLabel} in Cairo, ${dateRange} has been received successfully.</p>
    <p style="font-size:20px;font-weight:600;letter-spacing:.04em;margin:16px 0">${regNumber}</p>
    <p style="font-weight:600;margin:0 0 4px">Events</p>
    <ul style="margin:0 0 12px;padding-inline-start:20px">${eventList}</ul>
    <p>Venue: ${VENUE}<br>Dates: ${dateRange}</p>
    <p style="margin-top:16px">We look forward to welcoming you in Cairo.</p>
    <hr style="border:0;border-top:1px solid #CBD6E0;margin:20px 0">
    <p style="font-size:13px;color:#556A7D">Submission reference <b>${ref}</b>. Need to review or change something?
       Use <a href="${editLink}">this link</a> (valid 30 days), or request a fresh one from the registration page with this
       reference and the email you registered with.</p>`;
  await sendMail(env, s.e, `Registration confirmed — ${regNumber}`, shell(body));

  return json({ ok: true, status: 'approved', reference: ref, registration_number: regNumber, event_codes: openTargets }, 201, ch);
}

async function requestEditLink(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const email = String(b.email || '').toLowerCase().trim();
  if (!await allow(env, 'editlink:' + ipHash, 20, 3600)) { await auditError(env, 'edit_link_request', 'rate_limited', `${reference} ${email}`, ipHash); return fail('rate_limited', 429, ch); }
  if (!reference || !EMAIL_RE.test(email)) { await auditError(env, 'edit_link_request', 'invalid_request', `${reference} ${email}`, ipHash); return fail('invalid_request', 400, ch); }

  const reg = await env.DB.prepare('SELECT registration_id, reference, email, event_codes FROM registrations WHERE reference = ? AND email = ?')
    .bind(reference, email).first();
  if (reg) {
    const { titlesEn } = await eventTitles(env, reg.event_codes);
    const token = await signEditToken(env, reg.registration_id);
    const link = `${env.FRONTEND_BASE || ''}/register/?edit=${encodeURIComponent(reg.reference)}.${encodeURIComponent(token)}`;
    await sendMail(env, reg.email, `Edit link for registration ${reg.reference}`, shell(
      `<h2 style="font-size:18px;margin:0 0 12px">Edit your registration</h2>
       <p>Use this link to review or update your submission for <b>${titlesEn}</b> (reference <b>${reg.reference}</b>). It is valid for 30 days.</p>
       <p><a href="${link}">${link}</a></p>`));
    await audit(env, 'edit_link_sent', 'registration', reg.registration_id, reg.reference, ipHash);
    await notifyTelegram(env, `✉️ <b>Edit link requested</b>\n${esc(reg.reference)}`);
  }
  /* Same response whether or not a match was found — never confirm which half was wrong. */
  return json({ ok: true }, 200, ch);
}

/* event_codes is a comma-joined list — one registration row can cover more than one event. */
async function eventTitles(env, eventCodesStr) {
  const codes = (eventCodesStr || '').split(',').filter(Boolean);
  if (!codes.length) return { codes, titlesEn: '' };
  const { results } = await env.DB.prepare(
    `SELECT code, title_en FROM events WHERE code IN (${codes.map(() => '?').join(',')})`).bind(...codes).all();
  return { codes, titlesEn: results.map(e => e.title_en).join(' & ') || codes.join(', ') };
}

async function fetchForEdit(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const t = await readEditToken(env, String(b.token || '').trim());
  if (!t) { await auditError(env, 'edit_fetch', 'invalid_edit_link', reference, ipHash); return fail('invalid_edit_link', 401, ch); }
  const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ? AND registration_id = ?')
    .bind(reference, t.r).first();
  if (!reg) { await auditError(env, 'edit_fetch', 'invalid_edit_link', reference, ipHash); return fail('invalid_edit_link', 401, ch); }
  return json({ ok: true, reference: reg.reference, event_codes: (reg.event_codes || '').split(',').filter(Boolean), status: reg.status,
    registration: JSON.parse(reg.data_json || '{}'), consents: JSON.parse(reg.consents_json || '{}') }, 200, ch);
}

async function updateRegistration(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const t = await readEditToken(env, String(b.token || '').trim());
  if (!t) { await auditError(env, 'edit_save', 'invalid_edit_link', reference, ipHash); return fail('invalid_edit_link', 401, ch); }
  if (!await allow(env, 'edit:' + ipHash, 10, 3600)) { await auditError(env, 'edit_save', 'rate_limited', reference, ipHash); return fail('rate_limited', 429, ch); }

  const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ? AND registration_id = ?')
    .bind(reference, t.r).first();
  if (!reg) { await auditError(env, 'edit_save', 'invalid_edit_link', reference, ipHash); return fail('invalid_edit_link', 401, ch); }

  const d = normalizeFreeText(b.registration || {});
  const missing = requiredFieldErrors(d);
  if (missing.length) {
    await auditError(env, 'edit_save', 'validation_failed', `${reg.reference}: ${missing.slice(0, 12).join(', ')}`, ipHash);
    return json({ ok: false, error: 'validation_failed', fields: missing }, 400, ch);
  }

  const inv = reg.invitation_id ? await env.DB.prepare('SELECT organization_name FROM invitations WHERE invitation_id = ?').bind(reg.invitation_id).first() : null;
  const fullName = fullNameOf(d);
  const orgMismatch = inv && d.organization_name &&
    d.organization_name.trim().toLowerCase() !== String(inv.organization_name).trim().toLowerCase();

  await env.DB.prepare(
    `UPDATE registrations SET full_name=?, organization_name=?, country=?, role_in_delegation=?,
       visa_letter_needed=?, data_json=?, consents_json=?, flag_org_mismatch=?
     WHERE registration_id = ?`)
    .bind(fullName, d.organization_name || null, d.country || null,
      d.role_in_delegation || null, d.visa_letter_needed === 'yes' ? 1 : 0,
      JSON.stringify(d), JSON.stringify(b.consents || {}), orgMismatch ? 1 : 0, reg.registration_id).run();

  await audit(env, t.admin ? 'registration_updated_by_admin' : 'registration_updated', 'registration', reg.registration_id, reg.reference, ipHash);
  await notifyTelegram(env, `✏️ <b>Registration edited${t.admin ? ' by admin' : ''}</b>\n${esc(fullName || reg.full_name || '(no name)')} — ${esc(reg.reference)}`);

  const { codes, titlesEn } = await eventTitles(env, reg.event_codes);
  /* Admin-initiated edits (typo fixes, protocol corrections) don't notify the
     registrant -- only their own self-service edits do. */
  if (!t.admin) {
    await sendMail(env, reg.email, `Registration updated — ${reg.reference}`, shell(
      `<h2 style="font-size:18px;margin:0 0 12px">Your registration has been updated</h2>
       <p>Reference <b>${reg.reference}</b> for <b>${titlesEn}</b> has been updated.</p>`));
  }

  return json({ ok: true, status: reg.status, registration_number: reg.registration_number || null, reference: reg.reference, event_codes: codes }, 200, ch);
}

async function adminRead(req, env, ch, csv, access) {
  if (!hasScope(access, 'registrations')) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT reference, registration_number, created_at, status, event_codes, full_name, email, organization_name, country,
            attendance_mode, role_in_delegation, participant_tier, visa_letter_needed, flag_personal_email, flag_org_mismatch
     FROM registrations ORDER BY created_at DESC LIMIT 500`).all();
  if (!csv) return json({ ok: true, count: results.length, registrations: results }, 200, ch);
  const cols = Object.keys(results[0] || { reference: '' });
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const out = [cols.join(','), ...results.map(r => cols.map(c => esc(r[c])).join(','))].join('\n');
  return new Response('\uFEFF' + out, { headers: { 'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="registrations.csv"', ...ch } });
}

/* Every uploaded file leaves a `<field>_key`/`<field>_filename` pair in
   data_json, at the top level or inside a repeat row (e.g. accompanying
   persons). Walk both to build one flat list for the admin UI. */
function extractAttachments(data) {
  const out = [];
  const scan = (obj, prefix) => {
    for (const [k, v] of Object.entries(obj || {})) {
      if (k.endsWith('_key') && typeof v === 'string' && v) {
        const field = k.slice(0, -4);
        out.push({ field: prefix + field, key: v, filename: obj[field + '_filename'] || v.split('/').pop() });
      }
    }
  };
  scan(data, '');
  for (const [k, v] of Object.entries(data || {}))
    if (Array.isArray(v)) v.forEach((row, i) => { if (row && typeof row === 'object') scan(row, `${k}[${i}].`); });
  return out;
}

async function adminAttachments(req, env, ch, access) {
  if (!hasScope(access, ...ALL_SCOPES)) return fail('unauthorized', 401, ch);
  const reference = (new URL(req.url).searchParams.get('reference') || '').toUpperCase();
  const reg = await env.DB.prepare('SELECT data_json FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);
  return json({ ok: true, attachments: extractAttachments(JSON.parse(reg.data_json || '{}')) }, 200, ch);
}

async function adminSetStatus(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'registrations')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const status = String(b.status || '').trim();
  if (!['under_review', 'approved', 'rejected'].includes(status)) return fail('invalid_status', 400, ch);

  const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);

  /* Assigned once, on first approval — re-approving after a revert keeps the same number.
     Numbered off a global running count, prefixed by whichever event is primary for this person. */
  let regNumber = reg.registration_number;
  const primaryEvent = (reg.event_codes || '').split(',')[0] || 'REG';
  if (status === 'approved' && !regNumber) {
    const { count } = await env.DB.prepare(
      'SELECT COUNT(*) AS count FROM registrations WHERE registration_number IS NOT NULL').first();
    regNumber = `${primaryEvent}-${String(count + 1).padStart(4, '0')}`;
  }

  await env.DB.prepare('UPDATE registrations SET status = ?, registration_number = ? WHERE reference = ?')
    .bind(status, regNumber || null, reference).run();
  await audit(env, 'registration_status_changed', 'registration', reg.registration_id, `${reference}:${status}`, ipHash, actor);
  await notifyTelegram(env, `📋 <b>Status changed</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reference)} → <b>${esc(status)}</b>${actor ? `\nby ${esc(actor)}` : ''}`);

  if (status === 'approved' || status === 'rejected') {
    const { titlesEn } = await eventTitles(env, reg.event_codes);
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(regNumber)}`;
    const body = status === 'approved'
      ? `<h2 style="font-size:18px;margin:0 0 12px">Your registration has been confirmed</h2>
         <p>Reference <b>${reference}</b> for <b>${titlesEn}</b> has been confirmed by the Technical Office for International Relations.</p>
         <p>Your registration number is <b style="font-size:20px;letter-spacing:.04em">${regNumber}</b>. Present the QR code below at the accreditation desk.</p>
         <p><img src="${qrUrl}" width="200" height="200" alt="QR code ${regNumber}" style="border:1px solid #CBD6E0;border-radius:8px;padding:8px"></p>`
      : `<h2 style="font-size:18px;margin:0 0 12px">Update on your registration</h2>
         <p>Reference <b>${reference}</b> for <b>${titlesEn}</b> was not approved. Contact the secretariat for details.</p>`;
    await sendMail(env, reg.email, `${status === 'approved' ? 'Registration confirmed' : 'Registration update'} — ${reference}`, shell(body));
  }

  return json({ ok: true, reference, status, registration_number: regNumber || null }, 200, ch);
}

const TIERS = ['president', 'vice_president', 'other'];
const TIER_LABELS = { president: 'President', vice_president: 'Vice President', other: 'Other' };

/* Protocol tier -- purely an internal admin classification for logistics/
   seating/escort planning. Never emailed to the registrant, unlike status. */
async function adminSetTier(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'registrations')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const tier = String(b.tier || '').trim();
  if (!TIERS.includes(tier)) return fail('invalid_tier', 400, ch);

  const reg = await env.DB.prepare('SELECT registration_id, reference, full_name FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);

  await env.DB.prepare('UPDATE registrations SET participant_tier = ? WHERE reference = ?').bind(tier, reference).run();
  await audit(env, 'participant_tier_changed', 'registration', reg.registration_id, `${reference}:${tier}`, ipHash, actor);
  await notifyTelegram(env, `🎖️ <b>Tier changed</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reference)} → <b>${esc(TIER_LABELS[tier])}</b>${actor ? `\nby ${esc(actor)}` : ''}`);

  return json({ ok: true, reference, tier }, 200, ch);
}

/* Permanently erases one registration -- the row, its check-ins, and every
   file it uploaded (passport copy, ticket, photos, slides, accompanying
   persons' passport copies). Admin-token only, checked against the raw
   token directly (requireAdmin) rather than the 'registrations' scope a
   named token could carry -- day-to-day approve/edit work is one thing,
   irreversibly destroying a record is a different order of consequence,
   so no named token gets this no matter how broad its other scopes are.
   audit_log itself is untouched: the deletion is logged, but the rest of
   this reference's history stays exactly as it already reads, matching
   how this app treats the audit trail as a permanent record everywhere
   else (e.g. a revoked access token still shows every prior use). */
async function adminDeleteRegistration(req, env, ch, ipHash, actor) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  if (!reference) return fail('invalid_request', 400, ch);

  const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);

  const attachments = extractAttachments(JSON.parse(reg.data_json || '{}'));
  if (attachments.length) await env.FILES.delete(attachments.map(a => a.key));

  await env.DB.prepare('DELETE FROM checkins WHERE reference = ?').bind(reference).run();
  if (reg.invitation_id) {
    await env.DB.prepare('UPDATE invitations SET used_count = MAX(0, used_count - 1) WHERE invitation_id = ?').bind(reg.invitation_id).run();
  }
  await env.DB.prepare('DELETE FROM registrations WHERE reference = ?').bind(reference).run();

  await audit(env, 'registration_deleted', 'registration', reg.registration_id,
    `${reference}: ${reg.full_name || '(no name)'} — ${reg.email || 'no email'} (${attachments.length} file(s) removed)`, ipHash, actor);
  await notifyTelegram(env, `🗑️ <b>Registration deleted</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reference)}${actor ? `\nby ${esc(actor)}` : ''}`);

  return json({ ok: true, reference, filesDeleted: attachments.length }, 200, ch);
}

/* Lets an admin open any registration in the SAME edit form a registrant
   uses via their emailed link -- no separate admin-only form to build and
   keep in sync with the real one. The minted token is flagged admin:true
   (see signEditToken) so the eventual save doesn't email the registrant. */
async function adminMintEditToken(req, env, ch, access) {
  if (!hasScope(access, 'registrations')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const reg = await env.DB.prepare('SELECT registration_id, reference FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);

  const token = await signEditToken(env, reg.registration_id, { admin: true });
  const editUrl = `${env.FRONTEND_BASE || ''}/register/?edit=${encodeURIComponent(reg.reference)}.${encodeURIComponent(token)}`;
  return json({ ok: true, reference: reg.reference, token, editUrl }, 200, ch);
}

/* organization_name and official_hotel are typed freely by whoever fills in
   the registration form -- the same SAI or hotel can end up spelled three
   different ways across registrations, which quietly splits one group into
   several in every report. These two endpoints let an admin see the
   distinct spellings in use and merge a set of them into one canonical
   value across every matching registration. */
const RENAMEABLE_FIELDS = {
  organization_name: { column: 'organization_name', jsonPath: '$.organization_name' },
  official_hotel: { column: null, jsonPath: '$.official_hotel' },
  own_hotel_name_address: { column: null, jsonPath: '$.own_hotel_name_address' }
};

async function adminFieldValues(req, env, ch, access) {
  if (!hasScope(access, 'registrations')) return fail('unauthorized', 401, ch);
  const field = new URL(req.url).searchParams.get('field');
  const def = RENAMEABLE_FIELDS[field];
  if (!def) return fail('invalid_field', 400, ch);
  const expr = def.column || `json_extract(data_json, '${def.jsonPath}')`;
  /* Grouped by the TRIMMED value, not the raw one -- otherwise "Org" and
     "Org " (an invisible trailing space) list as two identical-looking
     rows with no way to tell them apart, which is exactly the bug this
     tool exists to fix. adminRenameFieldValues matches on TRIM() too, so
     picking the one visible row silently catches every whitespace variant. */
  const { results } = await env.DB.prepare(
    `SELECT TRIM(${expr}) AS value, COUNT(*) AS count FROM registrations
     WHERE ${expr} IS NOT NULL AND TRIM(${expr}) != ''
     GROUP BY TRIM(${expr}) ORDER BY count DESC, value ASC`).all();
  return json({ ok: true, field, values: results }, 200, ch);
}

async function adminRenameFieldValues(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'registrations')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const field = String(b.field || '');
  const def = RENAMEABLE_FIELDS[field];
  if (!def) return fail('invalid_field', 400, ch);
  const to = String(b.to || '').trim();
  const from = Array.isArray(b.from) ? [...new Set(b.from.map(v => String(v || '').trim()).filter(Boolean))] : [];
  if (!to || !from.length) return fail('missing_fields', 400, ch);

  const placeholders = from.map(() => '?').join(',');
  const matchExpr = def.column || `json_extract(data_json, '${def.jsonPath}')`;
  /* TRIM() on the match side too -- "from" is already trimmed above, so a
     row stored with extra leading/trailing whitespace still matches the
     canonical value the admin actually selected, even though it was never
     shown as a separate row to tick. */
  const sql = def.column
    /* Also rewrite the copy embedded in data_json -- the report page's card
       view reads that copy, not the top-level column, and the two must
       never disagree about a person's organisation. */
    ? `UPDATE registrations SET ${def.column} = ?, data_json = json_set(data_json, '${def.jsonPath}', ?) WHERE TRIM(${matchExpr}) IN (${placeholders})`
    : `UPDATE registrations SET data_json = json_set(data_json, '${def.jsonPath}', ?) WHERE TRIM(${matchExpr}) IN (${placeholders})`;
  const binds = def.column ? [to, to, ...from] : [to, ...from];

  const result = await env.DB.prepare(sql).bind(...binds).run();
  const changed = result.meta ? result.meta.changes : 0;
  const fieldLabel = field === 'organization_name' ? 'Organisation' : 'Hotel';
  await audit(env, 'field_values_renamed', field, null, `${from.join(' | ')} → ${to} (${changed} rows)`, ipHash, actor);
  await notifyTelegram(env, `🏷️ <b>${fieldLabel} name merged</b>\n${esc(from.join(', '))} → <b>${esc(to)}</b> (${changed} row${changed === 1 ? '' : 's'})${actor ? `\nby ${esc(actor)}` : ''}`);

  return json({ ok: true, field, to, changed }, 200, ch);
}

/* Recomputed server-side at send time (never trusted from the request) so
   a reminder always describes what's ACTUALLY still missing right now, not
   whatever the admin's browser last happened to compute from a page they
   might have had open for a while. */
const ITINERARY_FIELDS = [
  ['arrival_date', 'Arrival date'], ['arrival_time', 'Arrival time'], ['arrival_airline', 'Arrival airline'],
  ['arrival_flight_no', 'Arrival flight number'], ['arrival_terminal', 'Arrival terminal'],
  ['departure_date', 'Departure date'], ['departure_time', 'Departure time'], ['departure_airline', 'Departure airline'],
  ['departure_flight_no', 'Departure flight number'], ['departure_terminal', 'Departure terminal']
];
function computeMissing(d) {
  const itinerary = ITINERARY_FIELDS.filter(([k]) => !d[k]).map(([, label]) => label);

  const hotel = [];
  if (!d.accommodation_type) hotel.push('Where you will stay (official hotel or own arrangement)');
  else if (d.accommodation_type === 'official' && !d.official_hotel) hotel.push('Official hotel name');
  else if (d.accommodation_type === 'own' && !d.own_hotel_name_address) hotel.push('Hotel name and address');
  if (!d.check_in_date) hotel.push('Check-in date');
  if (!d.check_out_date) hotel.push('Check-out date');

  let presentation = null;
  if (d.wants_to_present === 'yes') {
    presentation = [];
    if (!d.presentation_title) presentation.push('Presentation title');
    if (!d.presentation_abstract) presentation.push('Abstract');
    if (!d.speaker_bio) presentation.push('Short biography');
    if (!d.speaker_photo_key) presentation.push('Portrait photo');
    if (!d.slides_file_key) presentation.push('Presentation slides');
  }

  let accompanying = null;
  if (d.is_accompanied === 'yes' && Array.isArray(d.accompanying) && d.accompanying.length) {
    accompanying = [];
    d.accompanying.forEach((p, i) => {
      const name = p.acc_full_name_passport || `Accompanying person ${i + 1}`;
      const gaps = [];
      if (!p.acc_passport_number) gaps.push('passport number');
      if (!p.acc_passport_expiry_date) gaps.push('passport expiry date');
      if (!p.acc_passport_copy_key) gaps.push('passport copy');
      if (gaps.length) accompanying.push(`${name}: missing ${gaps.join(', ')}`);
    });
  }

  /* The participant's own two document uploads -- both optional on the
     form, neither tracked by any other category (presentation's photo/
     slides and accompanying's passport copies are each other people's
     files; these are the confirmed participant's). */
  const attachments = [];
  if (!d.passport_copy_key) attachments.push('Passport copy');
  if (!d.ticket_file_key) attachments.push('Flight itinerary / ticket file');

  return { itinerary, hotel, presentation, accompanying, attachments };
}
const REMINDER_CATEGORIES = ['itinerary', 'hotel', 'presentation', 'accompanying', 'attachments'];
const REMINDER_LABELS = { itinerary: 'Flight itinerary', hotel: 'Accommodation', presentation: 'Presentation', accompanying: 'Accompanying persons', attachments: 'Attachments' };

/* Builds the exact email a reminder would send, without sending it -- shared
   by the real send and the preview endpoint so a preview can never drift
   from what actually goes out. Mints a real edit token even in preview (it's
   the same harmless operation adminMintEditToken already exposes), so the
   link the admin previews is the same one the recipient would get. */
async function buildReminderEmail(env, reg, categories) {
  const d = JSON.parse(reg.data_json || '{}');
  const missing = computeMissing(d);
  const sections = categories
    .map(c => ({ cat: c, label: REMINDER_LABELS[c], items: missing[c] || [] }))
    .filter(s => s.items.length);
  if (!sections.length) return { ok: false, error: 'nothing_missing' };

  const { titlesEn } = await eventTitles(env, reg.event_codes);
  const token = await signEditToken(env, reg.registration_id);
  const editLink = `${env.FRONTEND_BASE || ''}/register/?edit=${encodeURIComponent(reg.reference)}.${encodeURIComponent(token)}`;
  const sectionsHtml = sections.map(s =>
    `<p style="margin:14px 0 4px;font-weight:600">${s.label}</p><ul style="margin:0 0 4px;padding-inline-start:20px">${s.items.map(x => `<li>${x}</li>`).join('')}</ul>`
  ).join('');
  const body = `<h2 style="font-size:18px;margin:0 0 12px">A few details are still missing</h2>
    <p>Dear ${reg.full_name || 'colleague'},</p>
    <p>Thank you for registering for the ${titlesEn} (reference <b>${reg.reference}</b>). A few details would help us plan for your visit — could you add them when you have a moment?</p>
    ${sectionsHtml}
    <p style="margin-top:18px"><a href="${editLink}" style="display:inline-block;padding:10px 22px;background:#0B2135;color:#fff;text-decoration:none;border-radius:2px">Update my registration</a></p>
    <p style="font-size:13px;color:#556A7D;margin-top:12px">Or use this link (valid 30 days): <a href="${editLink}">${editLink}</a></p>`;

  return {
    ok: true, to: reg.email, subject: `A few details still needed — ${reg.reference}`,
    html: shell(body), categories: sections.map(s => s.cat)
  };
}

/* One consolidated email per person, covering only the categories the admin
   actually ticked for them -- never every gap at once, and never a category
   they were never asked to fill in (presentation/accompanying only exist
   for people who said yes to those questions). Links to the person's own
   normal (non-admin) edit link, so saving it emails them the usual
   "your registration has been updated" confirmation.
   b.preview: true composes and returns the emails without sending them or
   touching the database/audit trail -- lets the admin see exactly what
   would go out (subject, body, edit link) before committing to a send. */
async function adminSendReminders(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'reminders')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const items = Array.isArray(b.items) ? b.items : [];
  const preview = b.preview === true;
  if (!items.length) return fail('missing_fields', 400, ch);

  const results = [];
  for (const item of items) {
    const reference = String(item.reference || '').trim().toUpperCase();
    const categories = Array.isArray(item.categories) ? item.categories.filter(c => REMINDER_CATEGORIES.includes(c)) : [];
    if (!reference || !categories.length) { results.push({ reference, ok: false, error: 'no_categories' }); continue; }
    try {
      const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ?').bind(reference).first();
      if (!reg) { results.push({ reference, ok: false, error: 'not_found' }); continue; }

      const email = await buildReminderEmail(env, reg, categories);
      if (!email.ok) { results.push({ reference, ok: false, error: email.error }); continue; }

      if (preview) {
        results.push({ reference, ok: true, preview: true, to: email.to, subject: email.subject, html: email.html, categories: email.categories });
        continue;
      }

      await sendMail(env, email.to, email.subject, email.html);
      const catStr = email.categories.join(',');
      await env.DB.prepare('UPDATE registrations SET reminder_sent_at = ?, reminder_categories = ? WHERE reference = ?')
        .bind(new Date().toISOString(), catStr, reference).run();
      await audit(env, 'reminder_sent', 'registration', reg.registration_id, `${reference}: ${catStr}`, ipHash, actor);
      await notifyTelegram(env, `📧 <b>Reminder sent</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reference)}: ${esc(catStr)}${actor ? `\nby ${esc(actor)}` : ''}`);
      results.push({ reference, ok: true, categories: email.categories });
    } catch (e) {
      results.push({ reference, ok: false, error: 'send_failed' });
    }
  }
  return json({ ok: true, preview, results }, 200, ch);
}

/* Free-form broadcast to any set of confirmed registrants -- unlike
   Reminders (which only ever sends the exact "still missing" categories),
   this is arbitrary admin-authored content, so it's admin-only like
   Reminders and gets the same preview-before-send discipline. The caller
   is expected to chunk large recipient lists into several calls (each one
   opens a real SMTP connection per email -- see sendMailGmail -- so a
   single call sending to hundreds of people risks the request simply
   running too long); this endpoint still caps at 100 as a backstop against
   a caller that doesn't. One consolidated audit entry per send (not one per
   recipient) -- a broadcast to 200 people is one event with a recipient
   list, not 200 separate happenings. */
async function adminSendAnnouncement(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'announce')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const subject = String(b.subject || '').trim();
  const bodyText = String(b.body || '').trim();
  const references = Array.isArray(b.references)
    ? [...new Set(b.references.map(r => String(r || '').trim().toUpperCase()).filter(Boolean))] : [];
  const preview = b.preview === true;
  if (!subject || !bodyText || !references.length) return fail('missing_fields', 400, ch);
  if (references.length > 100) return fail('too_many_recipients', 400, ch);

  /* Plain text -> simple paragraphs, same minimal-formatting approach as
     every other system email here -- no rich text editor to keep in sync
     with what actually renders in a mail client. */
  const bodyHtml = bodyText.split(/\n{2,}/).map(p => `<p>${esc(p).replace(/\n/g, '<br>')}</p>`).join('\n');

  const results = [];
  for (const reference of references) {
    try {
      const reg = await env.DB.prepare('SELECT registration_id, reference, full_name, email, status FROM registrations WHERE reference = ?').bind(reference).first();
      if (!reg) { results.push({ reference, ok: false, error: 'not_found' }); continue; }
      if (reg.status !== 'approved') { results.push({ reference, ok: false, error: 'not_approved' }); continue; }

      const html = shell(`<p>Dear ${esc(reg.full_name || 'colleague')},</p>${bodyHtml}`);
      if (preview) { results.push({ reference, ok: true, preview: true, to: reg.email, subject, html }); continue; }

      const sendResult = await sendMail(env, reg.email, subject, html);
      if (sendResult.skipped || sendResult.ok === false) { results.push({ reference, ok: false, error: 'send_failed' }); continue; }
      results.push({ reference, ok: true });
    } catch (e) {
      results.push({ reference, ok: false, error: 'send_failed' });
    }
  }

  if (!preview) {
    const sent = results.filter(r => r.ok).length;
    const failed = results.filter(r => !r.ok);
    await audit(env, 'announcement_sent', 'announcement', null,
      `"${subject}" — ${sent} of ${references.length} sent${failed.length ? ' (failed: ' + failed.map(f => f.reference).join(', ') + ')' : ''}`, ipHash, actor);
    await notifyTelegram(env, `📣 <b>Announcement sent</b>\n"${esc(subject)}" — ${sent} of ${references.length} recipient(s)${actor ? `\nby ${esc(actor)}` : ''}`);
  }
  return json({ ok: true, preview, results }, 200, ch);
}

/* The registration form promises registrants their emergency-contact and
   medical/allergy fields are "seen only by the registrar, never included in
   any delegate list or export" -- so unlike the rest of data_json, these
   don't go out to a caller who only holds the narrower VIEWER_TOKEN, even
   though export.json is otherwise their read-only report feed. Only the
   full ADMIN_TOKEN gets them. */
const SENSITIVE_WELFARE_FIELDS = ['emergency_contact_name', 'emergency_contact_relation',
  'emergency_contact_phone', 'emergency_contact_email', 'allergies', 'medical_notes_emergency'];

async function adminExportFull(req, env, ch, access, ipHash) {
  if (!hasScope(access, ...ALL_SCOPES)) return fail('unauthorized', 401, ch);
  const isFullAdmin = access.tier === 'admin';
  await logReportAccess(env, access, new URL(req.url).searchParams.get('src'), ipHash);
  const { results } = await env.DB.prepare(
    `SELECT registration_id, reference, registration_number, created_at, status, event_codes, invitation_id, email, full_name,
            organization_name, country, attendance_mode, role_in_delegation, participant_tier, visa_letter_needed,
            flag_personal_email, flag_org_mismatch, fill_seconds, locale, reminder_sent_at, reminder_categories, data_json, consents_json
     FROM registrations ORDER BY created_at DESC LIMIT 1000`).all();
  const registrations = results.map(r => {
    const data = JSON.parse(r.data_json || '{}');
    if (!isFullAdmin) SENSITIVE_WELFARE_FIELDS.forEach(f => delete data[f]);
    return { ...r, data_json: undefined, consents_json: undefined, data, consents: JSON.parse(r.consents_json || '{}') };
  });
  return json({ ok: true, isAdmin: isFullAdmin, count: registrations.length, exported_at: new Date().toISOString(), registrations }, 200, ch);
}

async function adminAuditLog(req, env, ch, access) {
  if (!hasScope(access, 'audit')) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT id, action, entity, entity_id, detail, ip_hash, actor, created_at
     FROM audit_log ORDER BY id DESC LIMIT 2000`).all();
  return json({ ok: true, count: results.length, entries: results }, 200, ch);
}

/* Reception check-in. Each badge's QR encodes "<regnum>|<event_code>" (see
   admin/badges) rather than just the registration number, because a
   dual-event participant's two cards otherwise carry the exact same
   regnum -- the event_code is what tells the scanner which day's badge was
   actually shown. Idempotent: re-scanning an already-checked-in badge
   returns the original timestamp with already:true instead of erroring or
   writing a second row/audit entry, so a nervous re-scan at a busy desk is
   harmless. */
async function adminCheckin(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'checkin')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const code = String(b.code || '').trim();
  const eventOverride = String(b.event_code || '').trim();
  let regnum, eventCode;
  if (code.includes('|')) {
    const i = code.lastIndexOf('|');
    regnum = code.slice(0, i).trim();
    /* The reception desk's own Event picker, when set, always wins over
       whatever the badge encodes -- it's how a dual-event participant gets
       checked into one specific event without either badge needing to
       "know" which desk it's being scanned at. */
    eventCode = eventOverride || code.slice(i + 1).trim();
  } else {
    /* Manual entry, and a scan whose event picker was set, always send
       event_code explicitly. A scanned code with no "|" and no override is
       a legacy plain-regnum badge (printed, or generated by a browser tab,
       before the event was encoded into the QR) -- fall back to the raw
       scanned text as the regnum and resolve the event below. */
    regnum = String(b.regnum || code).trim();
    eventCode = eventOverride;
  }
  if (!regnum) { await auditError(env, 'checkin', 'invalid_code', `${regnum}|${eventCode}`, ipHash); return fail('invalid_code', 400, ch); }

  const reg = await env.DB.prepare(
    `SELECT * FROM registrations WHERE registration_number = ? OR reference = ?`).bind(regnum, regnum).first();
  if (!reg) { await auditError(env, 'checkin', 'not_found', `${regnum}|${eventCode}`, ipHash); return fail('not_found', 404, ch); }
  if (reg.status !== 'approved') { await auditError(env, 'checkin', 'not_approved', `${reg.reference}|${eventCode}`, ipHash); return fail('not_approved', 409, ch); }
  const codes = (reg.event_codes || '').split(',').filter(Boolean);

  if (!eventCode) {
    /* No event on the badge itself -- fine when the person is only
       registered for one event (the only sensible choice), otherwise
       reception has to say which one via manual entry. */
    if (codes.length === 1) eventCode = codes[0];
    else { await auditError(env, 'checkin', 'event_required', `${reg.reference}|${codes.join('+')}`, ipHash); return fail('event_required', 409, ch); }
  }
  if (!codes.includes(eventCode)) { await auditError(env, 'checkin', 'event_mismatch', `${reg.reference}|${eventCode}`, ipHash); return fail('event_mismatch', 409, ch); }

  const existing = await env.DB.prepare('SELECT checked_in_at FROM checkins WHERE reference = ? AND event_code = ?')
    .bind(reg.reference, eventCode).first();
  const already = !!existing;
  let checkedInAt = existing ? existing.checked_in_at : new Date().toISOString();
  if (!already) {
    await env.DB.prepare('INSERT INTO checkins (reference, event_code, checked_in_at) VALUES (?,?,?)')
      .bind(reg.reference, eventCode, checkedInAt).run();
    await audit(env, 'checked_in', 'registration', reg.registration_id, `${reg.reference}:${eventCode}`, ipHash, actor);
    await notifyTelegram(env, `✅ <b>Checked in</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reg.reference)} · ${esc(eventCode)}${actor ? `\nby ${esc(actor)}` : ''}`);
  }

  return json({
    ok: true, already, checked_in_at: checkedInAt,
    reference: reg.reference, registration_number: reg.registration_number || null,
    event_code: eventCode, full_name: reg.full_name, organization_name: reg.organization_name,
    country: reg.country, role_in_delegation: reg.role_in_delegation, participant_tier: reg.participant_tier
  }, 200, ch);
}

async function adminListCheckins(req, env, ch, access, ipHash) {
  /* Read by three different pages (Reception Check-in, Certificates,
     Announcements' check-in-status filter) -- any authenticated scope can
     read it, same as export.json, since attendance data alone isn't
     sensitive enough to warrant its own scope. Only logged as a report
     access when Certificates is the one calling it (src=certificates) --
     the reception desk and Announcements poll this constantly as an
     operational tool, not "viewing a report." */
  if (!hasScope(access, ...ALL_SCOPES)) return fail('unauthorized', 401, ch);
  if (new URL(req.url).searchParams.get('src') === 'certificates') await logReportAccess(env, access, 'certificates', ipHash);
  const { results } = await env.DB.prepare(
    `SELECT c.reference, c.event_code, c.checked_in_at, r.full_name, r.organization_name, r.country, r.participant_tier
     FROM checkins c JOIN registrations r ON r.reference = c.reference
     ORDER BY c.checked_in_at DESC LIMIT 1000`).all();
  return json({ ok: true, count: results.length, checkins: results }, 200, ch);
}

/* Corrects a mis-scan (wrong badge, wrong desk's event) without leaving a
   phantom "checked in" record behind. Same scope as checking in -- this is
   the same category of action reception is already trusted to do, just in
   reverse, not a step up in sensitivity like the medical report. */
async function adminUndoCheckin(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'checkin')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const eventCode = String(b.event_code || '').trim();
  if (!reference || !eventCode) return fail('invalid_request', 400, ch);

  const existing = await env.DB.prepare('SELECT id FROM checkins WHERE reference = ? AND event_code = ?')
    .bind(reference, eventCode).first();
  if (!existing) return fail('not_found', 404, ch);

  const reg = await env.DB.prepare('SELECT registration_id, full_name FROM registrations WHERE reference = ?').bind(reference).first();
  await env.DB.prepare('DELETE FROM checkins WHERE reference = ? AND event_code = ?').bind(reference, eventCode).run();
  await audit(env, 'checkin_undone', 'registration', reg ? reg.registration_id : null, `${reference}:${eventCode}`, ipHash, actor);
  await notifyTelegram(env, `↩️ <b>Check-in undone</b>\n${esc(reg ? reg.full_name : reference) || '(no name)'} — ${esc(reference)} · ${esc(eventCode)}${actor ? `\nby ${esc(actor)}` : ''}`);

  return json({ ok: true, reference, event_code: eventCode }, 200, ch);
}

function requireAdmin(req, env) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  return !!env.ADMIN_TOKEN && token === env.ADMIN_TOKEN;
}

/* ---------- named, scoped access tokens ---------- */
/* One scope per admin/report page. ADMIN_TOKEN implicitly has all of them;
   VIEWER_TOKEN (a single shared secret, kept only for backward compatibility
   with whoever already has it) implicitly has every report-tier scope. A
   named token (access_tokens table, managed from admin/tokens) carries an
   explicit, admin-assigned subset instead -- e.g. "SAI India" might get
   exactly [report, dashboard, logistics], so Reminders/Announcements/
   Invitations/Backups/Audit/registration edits simply 401 for that token,
   and the admin hub only ever shows them the three pages they can use.
   The five pure "view a report" scopes (report/dashboard/logistics/badges/
   certificates) all draw from the same underlying registration data feed
   (export.json) -- a token scoped to only one of them still technically
   could call that shared feed directly, though the hub would only ever
   show it the one page. Every write action and every admin-tool scope is
   strictly and separately enforced; this shared-feed nuance is the one
   accepted exception, not a general rule. */
const ALL_SCOPES = ['report', 'dashboard', 'logistics', 'badges', 'certificates', 'checkin',
  'invitations', 'registrations', 'reminders', 'announce', 'audit', 'backups'];
const REPORT_SCOPES = ['report', 'dashboard', 'logistics', 'badges', 'certificates', 'checkin'];

async function resolveAccess(req, env) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!token) return { tier: null, scopes: null, name: null };
  if (env.ADMIN_TOKEN && token === env.ADMIN_TOKEN) return { tier: 'admin', scopes: new Set(ALL_SCOPES), name: null };
  if (env.VIEWER_TOKEN && token === env.VIEWER_TOKEN) return { tier: 'viewer', scopes: new Set(REPORT_SCOPES), name: null };
  const hash = await sha256(token);
  const row = await env.DB.prepare('SELECT token_id, name, scopes FROM access_tokens WHERE token_hash = ? AND is_active = 1').bind(hash).first();
  if (!row) return { tier: null, scopes: null, name: null };
  /* Best-effort, never blocks the real request on a slow/failed write. */
  env.DB.prepare('UPDATE access_tokens SET last_used_at = ? WHERE token_id = ?').bind(new Date().toISOString(), row.token_id).run().catch(() => {});
  return { tier: 'named', tokenId: row.token_id, name: row.name, scopes: new Set(row.scopes.split(',').filter(Boolean)) };
}
function hasScope(access, ...allowed) {
  return !!(access && access.scopes && allowed.some(s => access.scopes.has(s)));
}

/* A register of who actually looked at a report and when -- distinct from
   the write-action entries elsewhere in audit_log. Deliberately skips the
   admin's own ADMIN_TOKEN traffic (every page load would otherwise flood
   the trail with entries nobody needs, since the admin already knows they
   opened the page); only viewer-tier and named-token access is worth a
   record, since those are exactly the tokens handed to someone else --
   SAI India, reception staff, whoever a named token was created for. */
async function logReportAccess(env, access, page, ipHash) {
  if (!access || access.tier === 'admin' || access.tier === null) return;
  const who = access.tier === 'named' ? access.name : 'Shared viewer token';
  try { await audit(env, 'report_accessed', 'access', page || 'unknown', who, ipHash, access.tier === 'named' ? access.name : null); }
  catch (e) { /* logging must never break the real response */ }
}

/* Lets a page work out what it's allowed to do with whatever token was
   pasted in -- the admin hub uses this to show only the cards a token can
   actually use, and every other page could use it the same way instead of
   just failing on first load. No scope of its own: anything with SOME
   valid token can ask what that token can see. */
async function adminWhoami(req, env, ch, access) {
  if (!access || !access.tier) return fail('unauthorized', 401, ch);
  return json({ ok: true, tier: access.tier, name: access.name, scopes: [...access.scopes] }, 200, ch);
}

/* Managing named tokens is itself admin-only -- checked against the raw
   ADMIN_TOKEN directly (requireAdmin), never satisfiable by a named token's
   scopes no matter how broad, so a token can never be used to mint or see
   other tokens, including itself. */
function randomAccessToken() {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  const raw = [...crypto.getRandomValues(new Uint8Array(28))].map(x => alphabet[x % alphabet.length]).join('');
  return `ASA-ACCESS-${raw}`;
}

async function adminListAccessTokens(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT token_id, name, scopes, is_active, created_at, last_used_at
     FROM access_tokens ORDER BY created_at DESC`).all();
  const tokens = results.map(r => ({ ...r, scopes: (r.scopes || '').split(',').filter(Boolean), is_active: !!r.is_active }));
  return json({ ok: true, count: tokens.length, tokens }, 200, ch);
}

async function adminCreateAccessToken(req, env, ch, ipHash, actor) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const name = String(b.name || '').trim().slice(0, 80);
  const scopes = [...new Set((Array.isArray(b.scopes) ? b.scopes : []).filter(s => ALL_SCOPES.includes(s)))];
  if (!name || !scopes.length) return fail('missing_fields', 400, ch);

  const tokenId = 'tok-' + crypto.randomUUID();
  const token = randomAccessToken();
  const hash = await sha256(token);
  await env.DB.prepare('INSERT INTO access_tokens (token_id, name, token_hash, scopes, is_active, created_at) VALUES (?,?,?,?,1,?)')
    .bind(tokenId, name, hash, scopes.join(','), new Date().toISOString()).run();
  await audit(env, 'access_token_created', 'access_token', tokenId, `${name}: ${scopes.join(', ')}`, ipHash, actor);
  await notifyTelegram(env, `🔐 <b>Access token created</b>\n${esc(name)} — ${esc(scopes.join(', '))}${actor ? `\nby ${esc(actor)}` : ''}`);
  /* The only moment the plaintext token exists outside this function --
     never stored, never retrievable again, same principle as an app
     password or an API key from any other provider. */
  return json({ ok: true, token_id: tokenId, name, scopes, token }, 201, ch);
}

async function adminRevokeAccessToken(req, env, ch, ipHash, actor) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const tokenId = String(b.token_id || '').trim();
  const row = await env.DB.prepare('SELECT name FROM access_tokens WHERE token_id = ?').bind(tokenId).first();
  if (!row) return fail('not_found', 404, ch);
  await env.DB.prepare('UPDATE access_tokens SET is_active = 0 WHERE token_id = ?').bind(tokenId).run();
  await audit(env, 'access_token_revoked', 'access_token', tokenId, row.name, ipHash, actor);
  await notifyTelegram(env, `🔐 <b>Access token revoked</b>\n${esc(row.name)}${actor ? `\nby ${esc(actor)}` : ''}`);
  return json({ ok: true, token_id: tokenId }, 200, ch);
}

/* Disaster-recovery snapshot of every table that can't be trivially
   regenerated (registrations, invitations, checkins, audit_log) as one
   JSON object in R2 -- runs nightly via a Cron Trigger and on demand from
   the admin hub. Admin-token only to list/download: the file itself holds
   everything a full export would, including the welfare fields that are
   otherwise redacted from export.json for a viewer token, since a backup
   is the registrar's own copy, not a report handed to someone else. */
const BACKUP_PREFIX = 'backups/';
const BACKUP_KEEP = 30; // most recent snapshots kept; older ones pruned automatically after each run

async function runBackupSnapshot(env) {
  const [registrations, invitations, invitationEvents, checkins, auditLog] = await Promise.all([
    env.DB.prepare('SELECT * FROM registrations').all().then(r => r.results),
    env.DB.prepare('SELECT * FROM invitations').all().then(r => r.results),
    env.DB.prepare('SELECT * FROM invitation_events').all().then(r => r.results),
    env.DB.prepare('SELECT * FROM checkins').all().then(r => r.results),
    env.DB.prepare('SELECT * FROM audit_log').all().then(r => r.results)
  ]);
  const generatedAt = new Date().toISOString();
  const snapshot = {
    generated_at: generatedAt,
    counts: { registrations: registrations.length, invitations: invitations.length, checkins: checkins.length, audit_log: auditLog.length },
    registrations, invitations, invitation_events: invitationEvents, checkins, audit_log: auditLog
  };
  const key = `${BACKUP_PREFIX}${generatedAt.replace(/[:.]/g, '-')}.json`;
  await env.FILES.put(key, JSON.stringify(snapshot), { httpMetadata: { contentType: 'application/json' } });

  /* Prune beyond BACKUP_KEEP -- ISO-timestamped filenames sort chronologically
     as plain strings, so the oldest are just the first N once sorted. */
  const listing = await env.FILES.list({ prefix: BACKUP_PREFIX });
  const keys = listing.objects.map(o => o.key).sort();
  const toDelete = keys.slice(0, Math.max(0, keys.length - BACKUP_KEEP));
  if (toDelete.length) await env.FILES.delete(toDelete);

  return { key, counts: snapshot.counts, pruned: toDelete.length };
}

async function adminListBackups(req, env, ch, access) {
  if (!hasScope(access, 'backups')) return fail('unauthorized', 401, ch);
  const listing = await env.FILES.list({ prefix: BACKUP_PREFIX });
  const backups = listing.objects
    .map(o => ({ key: o.key, size: o.size, uploaded: o.uploaded }))
    .sort((a, b) => b.key.localeCompare(a.key));
  return json({ ok: true, count: backups.length, backups }, 200, ch);
}

async function adminDownloadBackup(req, env, ch, access) {
  if (!hasScope(access, 'backups')) return fail('unauthorized', 401, ch);
  const key = new URL(req.url).searchParams.get('key') || '';
  if (!key.startsWith(BACKUP_PREFIX)) return fail('invalid_key', 400, ch);
  const obj = await env.FILES.get(key);
  if (!obj) return fail('not_found', 404, ch);
  const filename = key.split('/').pop();
  return new Response(obj.body, { headers: {
    'Content-Type': 'application/json',
    'Content-Disposition': `attachment; filename="${filename}"`,
    ...ch
  } });
}

async function adminRunBackup(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'backups')) return fail('unauthorized', 401, ch);
  const result = await runBackupSnapshot(env);
  await audit(env, 'backup_run', 'backup', result.key,
    `${result.counts.registrations} registrations, ${result.counts.invitations} invitations, ${result.counts.checkins} check-ins` +
    (result.pruned ? `; pruned ${result.pruned} old snapshot(s)` : ''), ipHash, actor);
  await notifyTelegram(env, `💾 <b>Backup snapshot created</b>\n${esc(result.key)} — ${result.counts.registrations} registrations${actor ? `\nby ${esc(actor)}` : ''}`);
  return json({ ok: true, ...result }, 200, ch);
}

async function adminListInvitations(req, env, ch, access) {
  if (!hasScope(access, 'invitations')) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT i.invitation_id, i.code, i.organization_name, i.country, i.org_type, i.liaison_email,
            i.max_uses, i.used_count, i.allow_free_email, i.expires_at, i.is_active,
            GROUP_CONCAT(ie.event_code) AS event_codes
     FROM invitations i LEFT JOIN invitation_events ie ON ie.invitation_id = i.invitation_id
     GROUP BY i.invitation_id ORDER BY i.rowid DESC LIMIT 500`).all();
  const invitations = results.map(r => ({ ...r, event_codes: (r.event_codes || '').split(',').filter(Boolean) }));
  return json({ ok: true, count: invitations.length, invitations }, 200, ch);
}

async function adminCreateInvitation(req, env, ch, access, ipHash, actor) {
  if (!hasScope(access, 'invitations')) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const eventCodes = [...new Set((Array.isArray(b.event_codes) ? b.event_codes : [b.event_code])
    .map(c => String(c || '').trim()).filter(Boolean))];
  const orgName = String(b.organization_name || '').trim();
  if (!eventCodes.length || !orgName) return fail('missing_fields', 400, ch);

  const { results: foundEvents } = await env.DB.prepare(
    `SELECT code FROM events WHERE code IN (${eventCodes.map(() => '?').join(',')})`).bind(...eventCodes).all();
  if (foundEvents.length !== eventCodes.length) return fail('invalid_event', 400, ch);

  const maxUses = (b.max_uses === '' || b.max_uses === null || b.max_uses === undefined) ? null : parseInt(b.max_uses, 10);
  if (maxUses !== null && (!Number.isFinite(maxUses) || maxUses < 1)) return fail('invalid_max_uses', 400, ch);

  const prefix = eventCodes.length > 1 ? 'MULTI'
    : (eventCodes[0].replace(/[^A-Z0-9]/gi, '').slice(0, 6).toUpperCase() || 'EVT');
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const genTail = () => [...crypto.getRandomValues(new Uint8Array(4))].map(x => alphabet[x % alphabet.length]).join('');

  let code, taken = true;
  for (let i = 0; i < 10 && taken; i++) {
    code = `ASA-${prefix}-INV-${genTail()}`;
    taken = !!(await env.DB.prepare('SELECT 1 FROM invitations WHERE code = ?').bind(code).first());
  }
  if (taken) return fail('code_generation_failed', 500, ch);

  const id = 'inv-' + crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO invitations (invitation_id, event_code, code, organization_name, country, org_type,
      liaison_email, max_uses, allow_free_email, expires_at, is_active)
     VALUES (?,?,?,?,?,?,?,?,?,?,1)`)
    .bind(id, eventCodes[0], code, orgName, b.country || null, b.org_type || null, b.liaison_email || null,
      maxUses, b.allow_free_email ? 1 : 0, b.expires_at || null).run();

  await env.DB.batch(eventCodes.map(ec =>
    env.DB.prepare('INSERT INTO invitation_events (invitation_id, event_code) VALUES (?,?)').bind(id, ec)));

  await audit(env, 'invitation_created', 'invitation', id, code, ipHash, actor);
  await notifyTelegram(env, `🔑 <b>Invitation code created</b>\n${esc(code)} — ${esc(orgName)}${actor ? `\nby ${esc(actor)}` : ''}`);
  return json({ ok: true, invitation_id: id, code, event_codes: eventCodes }, 201, ch);
}

async function uploadFile(req, env, ch, ipHash) {
  // Two distinct callers hit this: a fresh registration (session token, from
  // invitation-verify) and someone editing an existing one via their edit
  // link (edit token, namespaced separately). Accept either.
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const s = await readSession(env, token);
  const t = s ? null : await readEditToken(env, token);
  if (!s && !t) { await auditError(env, 'upload', 'session_expired', null, ipHash); return fail('session_expired', 401, ch); }
  const who = s ? s.e : t.r;

  const form = await req.formData().catch(() => null);
  const file = form && form.get('file');
  const field = form ? String(form.get('field') || '').trim() : '';
  const accept = (form && form.get('accept')) || 'any';
  if (!file || typeof file === 'string' || !field) { await auditError(env, 'upload', 'invalid_request', who, ipHash); return fail('invalid_request', 400, ch); }

  const allow = UPLOAD_ACCEPT[accept] || UPLOAD_ACCEPT.any;
  if (!allow.includes(file.type)) { await auditError(env, 'upload', 'invalid_file_type', `${who} — ${field} (${file.type})`, ipHash); return fail('invalid_file_type', 400, ch); }
  const maxMB = UPLOAD_MAX_MB[accept] || 15;
  if (file.size > maxMB * 1048576) { await auditError(env, 'upload', 'file_too_large', `${who} — ${field} (${(file.size / 1048576).toFixed(1)}MB)`, ipHash); return fail('file_too_large', 400, ch); }

  const safeName = String(file.name || 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(-80);
  const keyPrefix = s ? `regs/${s.iv}/${await sha256(s.e)}` : `regs/edit/${t.r}`;
  const key = `${keyPrefix}/${field}-${crypto.randomUUID()}-${safeName}`;
  await env.FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type } });

  await audit(env, 'file_uploaded', 'file', key, field, null);
  return json({ ok: true, key, filename: file.name, size: file.size, mime: file.type }, 201, ch);
}

/* A handful of validation failures happen entirely in the browser before any
   other endpoint is ever called -- an invitation code that fails its format
   check, a malformed or disposable email, no event picked -- and would
   otherwise never reach the audit trail at all. Fixed allowlist (not free
   text) and rate-limited, since this is the one endpoint anyone can call
   with no session or invitation at all; always answers ok so a logging
   hiccup never surfaces as an error to a real applicant. */
const CLIENT_ERROR_CODES = {
  gate: ['missing_code', 'invalid_code_format', 'missing_email', 'invalid_email', 'disposable_email'],
  events_pick: ['no_events_selected'],
  edit_request: ['missing_reference', 'missing_email', 'invalid_email'],
  /* fetch() itself throwing -- the request never reached this Worker at all
     (blocked/firewalled connection, DNS failure, offline). Best-effort only:
     if the browser can't reach the API for the real request, this report
     can fail exactly the same way and never arrive either. It's worth
     trying anyway, since not every failure here means a full, sustained
     block -- a brief drop or a one-off timeout would still let this
     follow-up call through. detail carries which endpoint the original
     request was for. */
  network: ['network_error']
};
async function logClientError(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const flow = String(b.flow || '').trim();
  const code = String(b.code || '').trim();
  const detail = String(b.detail || '').slice(0, 200) || null;
  const allowed = CLIENT_ERROR_CODES[flow];
  if (allowed && allowed.includes(code) && await allow(env, 'clienterr:' + ipHash, 40, 3600)) {
    await auditError(env, flow, code, detail, ipHash);
  }
  return json({ ok: true }, 200, ch);
}

async function adminGetFile(req, env, ch, access) {
  if (!hasScope(access, ...ALL_SCOPES)) return fail('unauthorized', 401, ch);
  const key = new URL(req.url).searchParams.get('key') || '';
  if (!key.startsWith('regs/')) return fail('invalid_key', 400, ch);
  const obj = await env.FILES.get(key);
  if (!obj) return fail('not_found', 404, ch);
  const filename = key.split('/').pop();
  return new Response(obj.body, { headers: {
    'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${filename}"`,
    ...ch
  } });
}

/* ---------- router ---------- */
export default {
  async fetch(req, env) {
    const ch = cors(req, env);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: ch });
    const { pathname } = new URL(req.url);
    const ipHash = await sha256((req.headers.get('CF-Connecting-IP') || '0') + (env.SESSION_SECRET || ''));
    /* Resolved once per request (admin / viewer / named-token / none) and
       handed to every admin handler instead of each one re-checking a raw
       token -- see resolveAccess()/hasScope() above. */
    const access = await resolveAccess(req, env);
    /* A named token's registered name is real accountability (tied to the
       credential itself, can't be mistyped or spoofed); the self-reported
       "Your name" field is a fallback for the shared ADMIN_TOKEN/VIEWER_TOKEN,
       which have no identity of their own. */
    const actor = access.tier === 'named' ? access.name : (String(req.headers.get('X-Actor-Name') || '').trim().slice(0, 60) || null);

    try {
      if (req.method === 'POST' && pathname === '/v1/invitations/verify') return await verifyInvitation(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations')      return await createRegistration(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit-link')  return await requestEditLink(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit-fetch') return await fetchForEdit(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit')       return await updateRegistration(req, env, ch, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/registrations')return await adminRead(req, env, ch, false, access);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.csv')   return await adminRead(req, env, ch, true, access);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.json')  return await adminExportFull(req, env, ch, access, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/invitations')  return await adminListInvitations(req, env, ch, access);
      if (req.method === 'POST' && pathname === '/v1/admin/invitations')  return await adminCreateInvitation(req, env, ch, access, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/uploads')            return await uploadFile(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/client-error')       return await logClientError(req, env, ch, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/files')        return await adminGetFile(req, env, ch, access);
      if (req.method === 'GET'  && pathname === '/v1/admin/attachments')  return await adminAttachments(req, env, ch, access);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/status') return await adminSetStatus(req, env, ch, access, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/tier')   return await adminSetTier(req, env, ch, access, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/delete') return await adminDeleteRegistration(req, env, ch, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/edit-token') return await adminMintEditToken(req, env, ch, access);
      if (req.method === 'GET'  && pathname === '/v1/admin/field-values')        return await adminFieldValues(req, env, ch, access);
      if (req.method === 'POST' && pathname === '/v1/admin/field-values/rename') return await adminRenameFieldValues(req, env, ch, access, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/admin/reminders/send')     return await adminSendReminders(req, env, ch, access, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/admin/announce/send')      return await adminSendAnnouncement(req, env, ch, access, ipHash, actor);
      if (req.method === 'GET'  && pathname === '/v1/admin/audit')              return await adminAuditLog(req, env, ch, access);
      if (req.method === 'POST' && pathname === '/v1/admin/checkin')              return await adminCheckin(req, env, ch, access, ipHash, actor);
      if (req.method === 'GET'  && pathname === '/v1/admin/checkins')             return await adminListCheckins(req, env, ch, access, ipHash);
      if (req.method === 'POST' && pathname === '/v1/admin/checkin/undo')         return await adminUndoCheckin(req, env, ch, access, ipHash, actor);
      if (req.method === 'GET'  && pathname === '/v1/admin/backups')              return await adminListBackups(req, env, ch, access);
      if (req.method === 'GET'  && pathname === '/v1/admin/backups/download')     return await adminDownloadBackup(req, env, ch, access);
      if (req.method === 'POST' && pathname === '/v1/admin/backups/run')          return await adminRunBackup(req, env, ch, access, ipHash, actor);
      if (req.method === 'GET'  && pathname === '/v1/admin/whoami')               return await adminWhoami(req, env, ch, access);
      if (req.method === 'GET'  && pathname === '/v1/admin/access-tokens')        return await adminListAccessTokens(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/admin/access-tokens')        return await adminCreateAccessToken(req, env, ch, ipHash, actor);
      if (req.method === 'POST' && pathname === '/v1/admin/access-tokens/revoke') return await adminRevokeAccessToken(req, env, ch, ipHash, actor);
      if (pathname === '/v1/health') return json({ ok: true, time: new Date().toISOString() }, 200, ch);
      return fail('not_found', 404, ch);
    } catch (e) {
      /* An unhandled exception on a public, registrant-facing path is exactly
         the kind of thing that should show up in the audit trail -- someone
         saw a generic error and we'd otherwise never know. Admin-tool crashes
         aren't logged here; those are noticed directly by whoever hit them. */
      if (PUBLIC_PATHS.has(pathname)) await auditError(env, 'server', 'server_error', pathname, ipHash);
      return fail('server_error', 500, ch);
    }
  },

  /* Cron Trigger (see wrangler.toml [triggers]) -- nightly backup snapshot,
     no admin action required. A failed run still alerts Telegram instead of
     failing silently, since nobody is watching a scheduled job's logs. */
  async scheduled(controller, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        const result = await runBackupSnapshot(env);
        await notifyTelegram(env, `💾 <b>Nightly backup completed</b>\n${esc(result.key)} — ${result.counts.registrations} registrations, ${result.counts.invitations} invitations, ${result.counts.checkins} check-ins`);
      } catch (e) {
        await notifyTelegram(env, `❗ <b>Nightly backup FAILED</b>\n${esc(String((e && e.message) || e))}`);
      }
    })());
  }
};
