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
     GET  /v1/admin/export.json    full submissions incl. every form field (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     GET  /v1/admin/invitations    list invitation codes (Bearer ADMIN_TOKEN)
     POST /v1/admin/invitations    generate a new invitation code (Bearer ADMIN_TOKEN)
     POST /v1/uploads               store one attachment in R2 (Bearer session), returns its key
     GET  /v1/admin/files?key=...  download a stored attachment (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     GET  /v1/admin/attachments?reference=... list one registration's attachments (Bearer ADMIN_TOKEN or VIEWER_TOKEN)
     POST /v1/admin/registrations/status  set status to under_review/approved/rejected, emails the applicant (Bearer ADMIN_TOKEN)
     POST /v1/admin/registrations/tier    set participant_tier to president/vice_president/other, never emailed (Bearer ADMIN_TOKEN)
     POST /v1/admin/registrations/edit-token  mint an edit-link token for any reference, opens the same public
                                    edit form; the resulting save is never emailed to the registrant (Bearer ADMIN_TOKEN)
     GET  /v1/admin/audit           recent audit-trail entries (Bearer ADMIN_TOKEN only — not VIEWER_TOKEN)
   Every error a registrant/editor/uploader can see on the public paths above
   is also written to audit_log as one 'error_shown' action (entity = which
   flow, entity_id = the error code, detail = whatever identifies who hit it).
   The events worth knowing about right away (new registration, edit, status
   change, invalid code, new invitation code, edit-link request, every error)
   also fire a Telegram message when TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID are
   set (secrets) — silently a no-op otherwise.
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
  '/v1/registrations/edit-fetch', '/v1/registrations/edit', '/v1/uploads']);

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

async function audit(env, action, entity, entityId, detail, ipHash) {
  await env.DB.prepare('INSERT INTO audit_log (action,entity,entity_id,detail,ip_hash,created_at) VALUES (?,?,?,?,?,?)')
    .bind(action, entity || null, entityId || null, detail || null, ipHash || null, new Date().toISOString()).run();
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

async function createRegistration(req, env, ch, ipHash) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const s = await readSession(env, token);
  if (!s) { await auditError(env, 'registration_submit', 'session_expired', null, ipHash); return fail('session_expired', 401, ch); }
  if (!await allow(env, 'reg:' + ipHash, 10, 3600)) { await auditError(env, 'registration_submit', 'rate_limited', s.e, ipHash); return fail('rate_limited', 429, ch); }

  const b = await req.json().catch(() => ({}));
  const d = b.registration || {};
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

  const d = b.registration || {};
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

async function adminRead(req, env, ch, csv) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return fail('unauthorized', 401, ch);
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

async function adminAttachments(req, env, ch) {
  if (!requireAdminOrViewer(req, env)) return fail('unauthorized', 401, ch);
  const reference = (new URL(req.url).searchParams.get('reference') || '').toUpperCase();
  const reg = await env.DB.prepare('SELECT data_json FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);
  return json({ ok: true, attachments: extractAttachments(JSON.parse(reg.data_json || '{}')) }, 200, ch);
}

async function adminSetStatus(req, env, ch, ipHash) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
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
  await audit(env, 'registration_status_changed', 'registration', reg.registration_id, `${reference}:${status}`, ipHash);
  await notifyTelegram(env, `📋 <b>Status changed</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reference)} → <b>${esc(status)}</b>`);

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
async function adminSetTier(req, env, ch, ipHash) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const tier = String(b.tier || '').trim();
  if (!TIERS.includes(tier)) return fail('invalid_tier', 400, ch);

  const reg = await env.DB.prepare('SELECT registration_id, reference, full_name FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);

  await env.DB.prepare('UPDATE registrations SET participant_tier = ? WHERE reference = ?').bind(tier, reference).run();
  await audit(env, 'participant_tier_changed', 'registration', reg.registration_id, `${reference}:${tier}`, ipHash);
  await notifyTelegram(env, `🎖️ <b>Tier changed</b>\n${esc(reg.full_name || '(no name)')} — ${esc(reference)} → <b>${esc(TIER_LABELS[tier])}</b>`);

  return json({ ok: true, reference, tier }, 200, ch);
}

/* Lets an admin open any registration in the SAME edit form a registrant
   uses via their emailed link -- no separate admin-only form to build and
   keep in sync with the real one. The minted token is flagged admin:true
   (see signEditToken) so the eventual save doesn't email the registrant. */
async function adminMintEditToken(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const reg = await env.DB.prepare('SELECT registration_id, reference FROM registrations WHERE reference = ?').bind(reference).first();
  if (!reg) return fail('not_found', 404, ch);

  const token = await signEditToken(env, reg.registration_id, { admin: true });
  const editUrl = `${env.FRONTEND_BASE || ''}/register/?edit=${encodeURIComponent(reg.reference)}.${encodeURIComponent(token)}`;
  return json({ ok: true, reference: reg.reference, token, editUrl }, 200, ch);
}

async function adminExportFull(req, env, ch) {
  if (!requireAdminOrViewer(req, env)) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT registration_id, reference, registration_number, created_at, status, event_codes, invitation_id, email, full_name,
            organization_name, country, attendance_mode, role_in_delegation, participant_tier, visa_letter_needed,
            flag_personal_email, flag_org_mismatch, fill_seconds, locale, data_json, consents_json
     FROM registrations ORDER BY created_at DESC LIMIT 1000`).all();
  const registrations = results.map(r => ({
    ...r,
    data_json: undefined, consents_json: undefined,
    data: JSON.parse(r.data_json || '{}'),
    consents: JSON.parse(r.consents_json || '{}')
  }));
  return json({ ok: true, count: registrations.length, exported_at: new Date().toISOString(), registrations }, 200, ch);
}

async function adminAuditLog(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT id, action, entity, entity_id, detail, ip_hash, created_at
     FROM audit_log ORDER BY id DESC LIMIT 2000`).all();
  return json({ ok: true, count: results.length, entries: results }, 200, ch);
}

function requireAdmin(req, env) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  return !!env.ADMIN_TOKEN && token === env.ADMIN_TOKEN;
}
/* A second, deliberately narrower token: valid only for the read-only report
   endpoints (full data, attachment listing/download), never for generating
   invitation codes or changing a registration's status. Meant to be handed
   to someone who should see the report and nothing else in the admin tools. */
function requireAdminOrViewer(req, env) {
  if (requireAdmin(req, env)) return true;
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  return !!env.VIEWER_TOKEN && token === env.VIEWER_TOKEN;
}

async function adminListInvitations(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT i.invitation_id, i.code, i.organization_name, i.country, i.org_type, i.liaison_email,
            i.max_uses, i.used_count, i.allow_free_email, i.expires_at, i.is_active,
            GROUP_CONCAT(ie.event_code) AS event_codes
     FROM invitations i LEFT JOIN invitation_events ie ON ie.invitation_id = i.invitation_id
     GROUP BY i.invitation_id ORDER BY i.rowid DESC LIMIT 500`).all();
  const invitations = results.map(r => ({ ...r, event_codes: (r.event_codes || '').split(',').filter(Boolean) }));
  return json({ ok: true, count: invitations.length, invitations }, 200, ch);
}

async function adminCreateInvitation(req, env, ch, ipHash) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
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

  await audit(env, 'invitation_created', 'invitation', id, code, ipHash);
  await notifyTelegram(env, `🔑 <b>Invitation code created</b>\n${esc(code)} — ${esc(orgName)}`);
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

async function adminGetFile(req, env, ch) {
  if (!requireAdminOrViewer(req, env)) return fail('unauthorized', 401, ch);
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

    try {
      if (req.method === 'POST' && pathname === '/v1/invitations/verify') return await verifyInvitation(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations')      return await createRegistration(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit-link')  return await requestEditLink(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit-fetch') return await fetchForEdit(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit')       return await updateRegistration(req, env, ch, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/registrations')return await adminRead(req, env, ch, false);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.csv')   return await adminRead(req, env, ch, true);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.json')  return await adminExportFull(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/invitations')  return await adminListInvitations(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/admin/invitations')  return await adminCreateInvitation(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/uploads')            return await uploadFile(req, env, ch, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/files')        return await adminGetFile(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/attachments')  return await adminAttachments(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/status') return await adminSetStatus(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/tier')   return await adminSetTier(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/edit-token') return await adminMintEditToken(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/audit')              return await adminAuditLog(req, env, ch);
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
  }
};
