/* =============================================================================
   ASA Events - registration API (Cloudflare Worker + D1)
   Endpoints:
     POST /v1/invitations/verify   check the invitation code, email the OTP
     POST /v1/otp/verify           check the OTP, return a session token
     POST /v1/registrations        store the submission as under_review
     GET  /v1/admin/registrations  read the data back (Bearer ADMIN_TOKEN)
     GET  /v1/admin/export.csv     same data as CSV (summary columns only)
     GET  /v1/admin/export.json    full submissions incl. every form field (Bearer ADMIN_TOKEN)
     GET  /v1/admin/invitations    list invitation codes (Bearer ADMIN_TOKEN)
     POST /v1/admin/invitations    generate a new invitation code (Bearer ADMIN_TOKEN)
   Nothing here trusts the browser: every rule in the form is re-checked.
   ============================================================================= */

const CODE_RE = /^ASA-[A-Z0-9]{3,10}-[A-Z]{2,4}-[A-Z0-9]{4}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const FREE_MAIL = ['gmail.com','yahoo.com','hotmail.com','outlook.com','live.com','icloud.com','aol.com','proton.me','protonmail.com','mail.ru','yandex.com','gmx.com'];
const DISPOSABLE = ['mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com','yopmail.com','trashmail.com','sharklasers.com'];
const MIN_FILL_SECONDS = 15;

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

async function sendMail(env, to, subject, html) {
  if (!env.RESEND_API_KEY) return { skipped: true };
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM, to: [to], subject, html })
  });
  return { ok: r.ok, status: r.status };
}

const shell = (bodyHtml) => `<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;color:#0B2135;line-height:1.6;max-width:560px">
${bodyHtml}
<hr style="border:0;border-top:1px solid #CBD6E0;margin:24px 0">
<p style="font-size:12px;color:#556A7D">Accountability State Authority — Arab Republic of Egypt<br>
This is a test environment. Do not submit real personal data.<br>
هذه بيئة اختبار. لا تُدخل بيانات شخصية حقيقية.</p></div>`;

/* ---------- endpoints ---------- */

async function verifyInvitation(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const code = String(b.invitation_code || '').toUpperCase().trim();
  const email = String(b.email || '').toLowerCase().trim();
  const eventCode = String(b.event_code || '').trim();

  if (!await allow(env, 'inv:' + ipHash, 10, 3600)) return fail('rate_limited', 429, ch);
  if (!EMAIL_RE.test(email)) return fail('invalid_email', 400, ch);
  if (DISPOSABLE.includes(domainOf(email))) return fail('disposable_email', 403, ch);
  if (!CODE_RE.test(code)) return fail('invalid_code', 400, ch);

  const ev = await env.DB.prepare('SELECT * FROM events WHERE code = ? AND is_active = 1').bind(eventCode).first();
  if (!ev) return fail('invalid_code', 400, ch);
  if (ev.registration_closes_at && Date.parse(ev.registration_closes_at) < Date.now())
    return fail('registration_closed', 410, ch);

  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE code = ? AND event_code = ? AND is_active = 1')
    .bind(code, eventCode).first();
  /* One generic message for every failure: never confirm which half was wrong. */
  if (!inv) { await audit(env, 'invitation_verify_failed', 'invitation', code, eventCode, ipHash); return fail('invalid_code', 400, ch); }
  if (inv.expires_at && Date.parse(inv.expires_at + 'T23:59:59Z') < Date.now()) return fail('invalid_code', 400, ch);
  if (inv.max_uses !== null && inv.used_count >= inv.max_uses) return fail('invalid_code', 400, ch);

  if (FREE_MAIL.includes(domainOf(email)) && !inv.allow_free_email)
    return fail('free_email_not_allowed', 403, ch);

  const otp = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const ttl = (parseInt(env.OTP_TTL_MINUTES || '10', 10)) * 60;
  await env.DB.prepare(
    `INSERT INTO otps (email,event_code,otp_hash,expires_at,attempts,invitation_id) VALUES (?,?,?,?,0,?)
     ON CONFLICT(email,event_code) DO UPDATE SET otp_hash=excluded.otp_hash, expires_at=excluded.expires_at, attempts=0, invitation_id=excluded.invitation_id`)
    .bind(email, eventCode, await sha256(otp + env.SESSION_SECRET), now() + ttl, inv.invitation_id).run();

  await sendMail(env, email, `Verification code ${otp} — ${ev.title_en}`, shell(
    `<h2 style="font-size:18px;margin:0 0 12px">Your verification code</h2>
     <p style="font-size:32px;letter-spacing:.25em;margin:16px 0">${otp}</p>
     <p>Enter this code to continue your registration for <b>${ev.title_en}</b>. It expires in ${env.OTP_TTL_MINUTES || 10} minutes.</p>
     <p style="direction:rtl;text-align:right">أدخل هذا الرمز لمتابعة تسجيلك في <b>${ev.title_ar}</b>. صلاحيته ${env.OTP_TTL_MINUTES || 10} دقائق.</p>`));

  await audit(env, 'otp_sent', 'invitation', inv.invitation_id, email, ipHash);
  return json({ ok: true, organization_name: inv.organization_name, country: inv.country,
                allow_free_email: !!inv.allow_free_email, otp_sent: true }, 200, ch);
}

async function verifyOtp(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const email = String(b.email || '').toLowerCase().trim();
  const eventCode = String(b.event_code || '').trim();
  const otp = String(b.otp || '').trim();

  if (!await allow(env, 'otp:' + ipHash, 20, 3600)) return fail('rate_limited', 429, ch);
  const row = await env.DB.prepare('SELECT * FROM otps WHERE email = ? AND event_code = ?').bind(email, eventCode).first();
  if (!row) return fail('bad_otp', 400, ch);
  if (row.expires_at < now()) return fail('bad_otp', 400, ch);
  if (row.attempts >= 5) return fail('too_many_attempts', 429, ch);

  if (await sha256(otp + env.SESSION_SECRET) !== row.otp_hash) {
    await env.DB.prepare('UPDATE otps SET attempts = attempts + 1 WHERE email = ? AND event_code = ?').bind(email, eventCode).run();
    return fail('bad_otp', 400, ch);
  }
  await env.DB.prepare('DELETE FROM otps WHERE email = ? AND event_code = ?').bind(email, eventCode).run();
  const session = await signSession(env, { e: email, ev: eventCode, iv: row.invitation_id, exp: now() + 7200 });
  await audit(env, 'otp_verified', 'email', email, eventCode, ipHash);
  return json({ ok: true, session }, 200, ch);
}

async function createRegistration(req, env, ch, ipHash) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const s = await readSession(env, token);
  if (!s) return fail('session_expired', 401, ch);
  if (!await allow(env, 'reg:' + ipHash, 10, 3600)) return fail('rate_limited', 429, ch);

  const b = await req.json().catch(() => ({}));
  const d = b.registration || {};
  if (b.event_code !== s.ev) return fail('event_mismatch', 400, ch);
  if ((b.fill_seconds || 0) < MIN_FILL_SECONDS) return fail('too_fast', 400, ch);

  const ev = await env.DB.prepare('SELECT * FROM events WHERE code = ?').bind(s.ev).first();
  if (!ev) return fail('invalid_event', 400, ch);
  if (ev.registration_closes_at && Date.parse(ev.registration_closes_at) < Date.now())
    return fail('registration_closed', 410, ch);

  /* Re-check the rules the browser checked. The browser is a convenience, not a control. */
  const missing = [];
  for (const k of ['first_name_passport','family_name_passport','date_of_birth','nationality','mobile',
                   'organization_name','country','job_title','protocol_level','role_in_delegation',
                   'liaison_officer_name','liaison_officer_email','attendance_mode',
                   'consent_processing','declaration_accuracy','signature_typed_name'])
    if (!d[k]) missing.push(k);
  if (d.attendance_mode === 'in_person') {
    for (const k of ['passport_number','passport_type','emergency_contact_name','emergency_contact_phone'])
      if (!d[k]) missing.push(k);
    if (d.visa_letter_needed === 'yes' && !d.consent_visa_sharing) missing.push('consent_visa_sharing');
  }
  if (missing.length) return json({ ok: false, error: 'validation_failed', fields: missing }, 400, ch);

  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE invitation_id = ?').bind(s.iv).first();
  const dup = await env.DB.prepare('SELECT reference FROM registrations WHERE event_code = ? AND email = ?')
    .bind(s.ev, s.e).first();
  if (dup) return json({ ok: false, error: 'duplicate_registration', reference: dup.reference }, 409, ch);

  const id = crypto.randomUUID();
  const ref = 'SUB-' + [...crypto.getRandomValues(new Uint8Array(4))]
    .map(x => 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'[x % 31]).join('');
  const fullName = [d.first_name_passport, d.middle_name_passport, d.family_name_passport].filter(Boolean).join(' ');
  const orgMismatch = inv && d.organization_name &&
    d.organization_name.trim().toLowerCase() !== String(inv.organization_name).trim().toLowerCase();

  await env.DB.prepare(
    `INSERT INTO registrations (registration_id, reference, event_code, invitation_id, email, full_name,
      organization_name, country, attendance_mode, role_in_delegation, visa_letter_needed, status,
      data_json, consents_json, flag_personal_email, flag_org_mismatch, source_ip_hash, fill_seconds, locale, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?, 'under_review', ?,?,?,?,?,?,?,?)`)
    .bind(id, ref, s.ev, s.iv, s.e, fullName, d.organization_name || null, d.country || null,
      d.attendance_mode || null, d.role_in_delegation || null, d.visa_letter_needed === 'yes' ? 1 : 0,
      JSON.stringify(d), JSON.stringify(b.consents || {}),
      b.personal_email ? 1 : 0, orgMismatch ? 1 : 0, ipHash, b.fill_seconds || null,
      b.locale || 'en', new Date().toISOString()).run();

  await env.DB.prepare('UPDATE invitations SET used_count = used_count + 1 WHERE invitation_id = ?').bind(s.iv).run();
  await audit(env, 'registration_submitted', 'registration', id, ref, ipHash);

  const body = `<h2 style="font-size:18px;margin:0 0 12px">Your registration has been received</h2>
    <p>Reference <b>${ref}</b>. Your submission for <b>${ev.title_en}</b> is now under review by the Technical Office for International Relations.</p>
    <p>No registration number or QR code is issued before approval.</p>
    <p style="direction:rtl;text-align:right">الرقم المرجعي <b>${ref}</b>. طلبك في <b>${ev.title_ar}</b> قيد المراجعة لدى المكتب الفني للعلاقات الدولية. ولا يصدر رقم التسجيل ولا رمز QR قبل الاعتماد.</p>`;
  await sendMail(env, s.e, `Registration received ${ref} — ${ev.title_en}`, shell(body));
  if (d.liaison_officer_email) await sendMail(env, d.liaison_officer_email, `Registration received ${ref} — ${fullName}`, shell(body));

  return json({ ok: true, status: 'under_review', reference: ref }, 201, ch);
}

async function adminRead(req, env, ch, csv) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT reference, created_at, status, event_code, full_name, email, organization_name, country,
            attendance_mode, role_in_delegation, visa_letter_needed, flag_personal_email, flag_org_mismatch
     FROM registrations ORDER BY created_at DESC LIMIT 500`).all();
  if (!csv) return json({ ok: true, count: results.length, registrations: results }, 200, ch);
  const cols = Object.keys(results[0] || { reference: '' });
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const out = [cols.join(','), ...results.map(r => cols.map(c => esc(r[c])).join(','))].join('\n');
  return new Response('\uFEFF' + out, { headers: { 'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': 'attachment; filename="registrations.csv"', ...ch } });
}

async function adminExportFull(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT registration_id, reference, created_at, status, event_code, invitation_id, email, full_name,
            organization_name, country, attendance_mode, role_in_delegation, visa_letter_needed,
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

function requireAdmin(req, env) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  return !!env.ADMIN_TOKEN && token === env.ADMIN_TOKEN;
}

async function adminListInvitations(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const { results } = await env.DB.prepare(
    `SELECT invitation_id, event_code, code, organization_name, country, org_type, liaison_email,
            max_uses, used_count, allow_free_email, expires_at, is_active
     FROM invitations ORDER BY rowid DESC LIMIT 500`).all();
  return json({ ok: true, count: results.length, invitations: results }, 200, ch);
}

async function adminCreateInvitation(req, env, ch, ipHash) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
  const b = await req.json().catch(() => ({}));
  const eventCode = String(b.event_code || '').trim();
  const orgName = String(b.organization_name || '').trim();
  if (!eventCode || !orgName) return fail('missing_fields', 400, ch);

  const ev = await env.DB.prepare('SELECT code FROM events WHERE code = ?').bind(eventCode).first();
  if (!ev) return fail('invalid_event', 400, ch);

  const maxUses = (b.max_uses === '' || b.max_uses === null || b.max_uses === undefined) ? null : parseInt(b.max_uses, 10);
  if (maxUses !== null && (!Number.isFinite(maxUses) || maxUses < 1)) return fail('invalid_max_uses', 400, ch);

  const prefix = (eventCode.replace(/[^A-Z0-9]/gi, '').slice(0, 6).toUpperCase() || 'EVT');
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
    .bind(id, eventCode, code, orgName, b.country || null, b.org_type || null, b.liaison_email || null,
      maxUses, b.allow_free_email ? 1 : 0, b.expires_at || null).run();

  await audit(env, 'invitation_created', 'invitation', id, code, ipHash);
  return json({ ok: true, invitation_id: id, code }, 201, ch);
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
      if (req.method === 'POST' && pathname === '/v1/otp/verify')         return await verifyOtp(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations')      return await createRegistration(req, env, ch, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/registrations')return await adminRead(req, env, ch, false);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.csv')   return await adminRead(req, env, ch, true);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.json')  return await adminExportFull(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/invitations')  return await adminListInvitations(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/admin/invitations')  return await adminCreateInvitation(req, env, ch, ipHash);
      if (pathname === '/v1/health') return json({ ok: true, time: new Date().toISOString() }, 200, ch);
      return fail('not_found', 404, ch);
    } catch (e) {
      return fail('server_error', 500, ch);
    }
  }
};
