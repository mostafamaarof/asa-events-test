/* =============================================================================
   ASA Events - registration API (Cloudflare Worker + D1)
   Endpoints:
     POST /v1/invitations/verify   check the invitation code, email the OTP
                                    (an invitation may cover more than one
                                    event; returns event_codes it currently
                                    unlocks, not tied to a single event)
     POST /v1/otp/verify           check the OTP, return a session token
                                    (keyed by invitation_id, not event_code)
     POST /v1/registrations        store the submission(s) as under_review,
                                    one per event_code in event_codes[]
     POST /v1/registrations/edit-link   email a 30-day self-service edit link
                                    for a (reference, email) pair, if it matches
     POST /v1/registrations/edit-fetch  return one registration's data (reference + token)
     POST /v1/registrations/edit        update it in place (reference + token)
     GET  /v1/admin/registrations  read the data back (Bearer ADMIN_TOKEN)
     GET  /v1/admin/export.csv     same data as CSV (summary columns only)
     GET  /v1/admin/export.json    full submissions incl. every form field (Bearer ADMIN_TOKEN)
     GET  /v1/admin/invitations    list invitation codes (Bearer ADMIN_TOKEN)
     POST /v1/admin/invitations    generate a new invitation code (Bearer ADMIN_TOKEN)
     POST /v1/uploads               store one attachment in R2 (Bearer session), returns its key
     GET  /v1/admin/files?key=...  download a stored attachment (Bearer ADMIN_TOKEN)
     GET  /v1/admin/attachments?reference=... list one registration's attachments (Bearer ADMIN_TOKEN)
     POST /v1/admin/registrations/status  set status to under_review/approved/rejected, emails the applicant (Bearer ADMIN_TOKEN)
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
const UPLOAD_MAX_MB = { any: 10, image: 5, doc: 50 };

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
   an edit token can never be replayed as a login session or vice versa. */
async function signEditToken(env, registrationId) {
  const body = b64u(JSON.stringify({ r: registrationId, exp: now() + 60 * 60 * 24 * 30 }));
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

  if (!await allow(env, 'inv:' + ipHash, 10, 3600)) return fail('rate_limited', 429, ch);
  if (!EMAIL_RE.test(email)) return fail('invalid_email', 400, ch);
  if (DISPOSABLE.includes(domainOf(email))) return fail('disposable_email', 403, ch);
  if (!CODE_RE.test(code)) return fail('invalid_code', 400, ch);

  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE code = ? AND is_active = 1').bind(code).first();
  /* One generic message for every failure: never confirm which half was wrong. */
  if (!inv) { await audit(env, 'invitation_verify_failed', 'invitation', code, null, ipHash); return fail('invalid_code', 400, ch); }
  if (inv.expires_at && Date.parse(inv.expires_at + 'T23:59:59Z') < Date.now()) return fail('invalid_code', 400, ch);
  if (inv.max_uses !== null && inv.used_count >= inv.max_uses) return fail('invalid_code', 400, ch);

  /* A code can cover more than one event; only offer the ones still open. */
  const { results: coveredEvents } = await env.DB.prepare(
    `SELECT e.code, e.title_en, e.title_ar, e.registration_closes_at
     FROM invitation_events ie JOIN events e ON e.code = ie.event_code
     WHERE ie.invitation_id = ? AND e.is_active = 1`).bind(inv.invitation_id).all();
  const openEvents = coveredEvents.filter(e => !e.registration_closes_at || Date.parse(e.registration_closes_at) >= Date.now());
  if (!openEvents.length) return fail('registration_closed', 410, ch);

  if (FREE_MAIL.includes(domainOf(email)) && !inv.allow_free_email)
    return fail('free_email_not_allowed', 403, ch);

  const otp = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const ttl = (parseInt(env.OTP_TTL_MINUTES || '10', 10)) * 60;
  await env.DB.prepare(
    `INSERT INTO otps (email,invitation_id,otp_hash,expires_at,attempts) VALUES (?,?,?,?,0)
     ON CONFLICT(email,invitation_id) DO UPDATE SET otp_hash=excluded.otp_hash, expires_at=excluded.expires_at, attempts=0`)
    .bind(email, inv.invitation_id, await sha256(otp + env.SESSION_SECRET), now() + ttl).run();

  const titleEn = openEvents.map(e => e.title_en).join(' & ');
  const titleAr = openEvents.map(e => e.title_ar).join(' و');
  await sendMail(env, email, `Verification code ${otp} — ${titleEn}`, shell(
    `<h2 style="font-size:18px;margin:0 0 12px">Your verification code</h2>
     <p style="font-size:32px;letter-spacing:.25em;margin:16px 0">${otp}</p>
     <p>Enter this code to continue your registration for <b>${titleEn}</b>. It expires in ${env.OTP_TTL_MINUTES || 10} minutes.</p>
     <p style="direction:rtl;text-align:right">أدخل هذا الرمز لمتابعة تسجيلك في <b>${titleAr}</b>. صلاحيته ${env.OTP_TTL_MINUTES || 10} دقائق.</p>`));

  await audit(env, 'otp_sent', 'invitation', inv.invitation_id, email, ipHash);
  return json({ ok: true, organization_name: inv.organization_name, country: inv.country,
                allow_free_email: !!inv.allow_free_email, otp_sent: true,
                invitation_id: inv.invitation_id, event_codes: openEvents.map(e => e.code) }, 200, ch);
}

async function verifyOtp(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const email = String(b.email || '').toLowerCase().trim();
  const invitationId = String(b.invitation_id || '').trim();
  const otp = String(b.otp || '').trim();

  if (!await allow(env, 'otp:' + ipHash, 20, 3600)) return fail('rate_limited', 429, ch);
  const row = await env.DB.prepare('SELECT * FROM otps WHERE email = ? AND invitation_id = ?').bind(email, invitationId).first();
  if (!row) return fail('bad_otp', 400, ch);
  if (row.expires_at < now()) return fail('bad_otp', 400, ch);
  if (row.attempts >= 5) return fail('too_many_attempts', 429, ch);

  if (await sha256(otp + env.SESSION_SECRET) !== row.otp_hash) {
    await env.DB.prepare('UPDATE otps SET attempts = attempts + 1 WHERE email = ? AND invitation_id = ?').bind(email, invitationId).run();
    return fail('bad_otp', 400, ch);
  }
  await env.DB.prepare('DELETE FROM otps WHERE email = ? AND invitation_id = ?').bind(email, invitationId).run();
  const session = await signSession(env, { e: email, iv: invitationId, exp: now() + 7200 });
  await audit(env, 'otp_verified', 'email', email, invitationId, ipHash);
  return json({ ok: true, session }, 200, ch);
}

/* Shared by create and edit: the rules the browser already checked, re-checked here. */
function requiredFieldErrors(d) {
  const missing = [];
  for (const k of ['first_name_passport','family_name_passport','date_of_birth','nationality','mobile',
                   'organization_name','country','job_title','protocol_level','role_in_delegation',
                   'attendance_mode',
                   'consent_processing','declaration_accuracy','signature_typed_name'])
    if (!d[k]) missing.push(k);
  if (d.attendance_mode === 'in_person') {
    for (const k of ['passport_number','passport_type','emergency_contact_name','emergency_contact_phone'])
      if (!d[k]) missing.push(k);
    if (d.visa_letter_needed === 'yes' && !d.consent_visa_sharing) missing.push('consent_visa_sharing');
  }
  return missing;
}

async function createRegistration(req, env, ch, ipHash) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const s = await readSession(env, token);
  if (!s) return fail('session_expired', 401, ch);
  if (!await allow(env, 'reg:' + ipHash, 10, 3600)) return fail('rate_limited', 429, ch);

  const b = await req.json().catch(() => ({}));
  const d = b.registration || {};
  const requested = Array.isArray(b.event_codes) ? [...new Set(b.event_codes.map(String))] : [];
  if (!requested.length) return fail('no_events_selected', 400, ch);
  if ((b.fill_seconds || 0) < MIN_FILL_SECONDS) return fail('too_fast', 400, ch);

  const inv = await env.DB.prepare('SELECT * FROM invitations WHERE invitation_id = ?').bind(s.iv).first();
  if (!inv) return fail('invalid_invitation', 400, ch);

  /* Never trust which events the client says it wants — only the ones this
     invitation actually covers are eligible, regardless of what was posted. */
  const { results: covered } = await env.DB.prepare(
    `SELECT e.* FROM invitation_events ie JOIN events e ON e.code = ie.event_code
     WHERE ie.invitation_id = ? AND e.is_active = 1`).bind(s.iv).all();
  const coveredMap = new Map(covered.map(e => [e.code, e]));
  const targets = requested.filter(c => coveredMap.has(c));
  if (!targets.length) return fail('invalid_event_selection', 400, ch);

  const missing = requiredFieldErrors(d);
  if (missing.length) return json({ ok: false, error: 'validation_failed', fields: missing }, 400, ch);

  const fullName = [d.first_name_passport, d.middle_name_passport, d.family_name_passport].filter(Boolean).join(' ');
  const orgMismatch = d.organization_name &&
    d.organization_name.trim().toLowerCase() !== String(inv.organization_name).trim().toLowerCase();

  const results = {};
  let createdCount = 0;
  for (const eventCode of targets) {
    const ev = coveredMap.get(eventCode);
    if (ev.registration_closes_at && Date.parse(ev.registration_closes_at) < Date.now()) {
      results[eventCode] = { ok: false, error: 'registration_closed' };
      continue;
    }
    const dup = await env.DB.prepare('SELECT reference FROM registrations WHERE event_code = ? AND email = ?')
      .bind(eventCode, s.e).first();
    if (dup) { results[eventCode] = { ok: true, reference: dup.reference, already_registered: true }; continue; }

    const id = crypto.randomUUID();
    const ref = 'SUB-' + [...crypto.getRandomValues(new Uint8Array(4))]
      .map(x => 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'[x % 31]).join('');

    await env.DB.prepare(
      `INSERT INTO registrations (registration_id, reference, event_code, invitation_id, email, full_name,
        organization_name, country, attendance_mode, role_in_delegation, visa_letter_needed, status,
        data_json, consents_json, flag_personal_email, flag_org_mismatch, source_ip_hash, fill_seconds, locale, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?, 'under_review', ?,?,?,?,?,?,?,?)`)
      .bind(id, ref, eventCode, s.iv, s.e, fullName, d.organization_name || null, d.country || null,
        d.attendance_mode || null, d.role_in_delegation || null, d.visa_letter_needed === 'yes' ? 1 : 0,
        JSON.stringify(d), JSON.stringify(b.consents || {}),
        b.personal_email ? 1 : 0, orgMismatch ? 1 : 0, ipHash, b.fill_seconds || null,
        b.locale || 'en', new Date().toISOString()).run();

    results[eventCode] = { ok: true, reference: ref, title_en: ev.title_en, title_ar: ev.title_ar };
    createdCount++;
    await audit(env, 'registration_submitted', 'registration', id, ref, ipHash);
  }

  if (createdCount > 0) {
    /* One code redemption per submission, however many events it covers. */
    await env.DB.prepare('UPDATE invitations SET used_count = used_count + 1 WHERE invitation_id = ?').bind(s.iv).run();
  }

  const anyOk = Object.values(results).some(r => r.ok);
  if (!anyOk) return json({ ok: false, error: 'registration_failed', results }, 409, ch);

  const newlyCreated = Object.entries(results).filter(([, r]) => r.ok && !r.already_registered);
  if (newlyCreated.length) {
    const listEn = newlyCreated.map(([, r]) => `${r.title_en} — reference <b>${r.reference}</b>`).join('<br>');
    const listAr = newlyCreated.map(([, r]) => `${r.title_ar} — الرقم المرجعي <b>${r.reference}</b>`).join('<br>');
    const body = `<h2 style="font-size:18px;margin:0 0 12px">Your registration has been received</h2>
      <p>${listEn}</p>
      <p>Under review by the Technical Office for International Relations. No registration number or QR code is issued before approval.</p>
      <p style="direction:rtl;text-align:right">${listAr}</p>
      <p style="direction:rtl;text-align:right">قيد المراجعة لدى المكتب الفني للعلاقات الدولية. ولا يصدر رقم التسجيل ولا رمز QR قبل الاعتماد.</p>`;
    await sendMail(env, s.e, `Registration received — ${newlyCreated.map(([, r]) => r.reference).join(', ')}`, shell(body));
  }

  return json({ ok: true, status: 'under_review', results }, 201, ch);
}

async function requestEditLink(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const email = String(b.email || '').toLowerCase().trim();
  if (!await allow(env, 'editlink:' + ipHash, 10, 3600)) return fail('rate_limited', 429, ch);
  if (!reference || !EMAIL_RE.test(email)) return fail('invalid_request', 400, ch);

  const reg = await env.DB.prepare('SELECT registration_id, reference, email, event_code FROM registrations WHERE reference = ? AND email = ?')
    .bind(reference, email).first();
  if (reg) {
    const ev = await env.DB.prepare('SELECT title_en, title_ar FROM events WHERE code = ?').bind(reg.event_code).first();
    const token = await signEditToken(env, reg.registration_id);
    const link = `${env.FRONTEND_BASE || ''}/register/?edit=${encodeURIComponent(reg.reference)}.${encodeURIComponent(token)}`;
    await sendMail(env, reg.email, `Edit link for registration ${reg.reference}`, shell(
      `<h2 style="font-size:18px;margin:0 0 12px">Edit your registration</h2>
       <p>Use this link to review or update your submission for <b>${ev ? ev.title_en : reg.event_code}</b> (reference <b>${reg.reference}</b>). It is valid for 30 days.</p>
       <p><a href="${link}">${link}</a></p>
       <p style="direction:rtl;text-align:right">استخدم هذا الرابط لمراجعة أو تعديل طلبك في <b>${ev ? ev.title_ar : reg.event_code}</b> (الرقم المرجعي <b>${reg.reference}</b>). صلاحيته 30 يوماً.</p>`));
    await audit(env, 'edit_link_sent', 'registration', reg.registration_id, reg.reference, ipHash);
  }
  /* Same response whether or not a match was found — never confirm which half was wrong. */
  return json({ ok: true }, 200, ch);
}

async function fetchForEdit(req, env, ch) {
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const t = await readEditToken(env, String(b.token || '').trim());
  if (!t) return fail('invalid_edit_link', 401, ch);
  const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ? AND registration_id = ?')
    .bind(reference, t.r).first();
  if (!reg) return fail('invalid_edit_link', 401, ch);
  return json({ ok: true, reference: reg.reference, event_code: reg.event_code, status: reg.status,
    registration: JSON.parse(reg.data_json || '{}'), consents: JSON.parse(reg.consents_json || '{}') }, 200, ch);
}

async function updateRegistration(req, env, ch, ipHash) {
  const b = await req.json().catch(() => ({}));
  const reference = String(b.reference || '').trim().toUpperCase();
  const t = await readEditToken(env, String(b.token || '').trim());
  if (!t) return fail('invalid_edit_link', 401, ch);
  if (!await allow(env, 'edit:' + ipHash, 10, 3600)) return fail('rate_limited', 429, ch);

  const reg = await env.DB.prepare('SELECT * FROM registrations WHERE reference = ? AND registration_id = ?')
    .bind(reference, t.r).first();
  if (!reg) return fail('invalid_edit_link', 401, ch);

  const d = b.registration || {};
  const missing = requiredFieldErrors(d);
  if (missing.length) return json({ ok: false, error: 'validation_failed', fields: missing }, 400, ch);

  const inv = reg.invitation_id ? await env.DB.prepare('SELECT organization_name FROM invitations WHERE invitation_id = ?').bind(reg.invitation_id).first() : null;
  const fullName = [d.first_name_passport, d.middle_name_passport, d.family_name_passport].filter(Boolean).join(' ');
  const orgMismatch = inv && d.organization_name &&
    d.organization_name.trim().toLowerCase() !== String(inv.organization_name).trim().toLowerCase();

  await env.DB.prepare(
    `UPDATE registrations SET full_name=?, organization_name=?, country=?, attendance_mode=?, role_in_delegation=?,
       visa_letter_needed=?, data_json=?, consents_json=?, flag_org_mismatch=?
     WHERE registration_id = ?`)
    .bind(fullName, d.organization_name || null, d.country || null, d.attendance_mode || null,
      d.role_in_delegation || null, d.visa_letter_needed === 'yes' ? 1 : 0,
      JSON.stringify(d), JSON.stringify(b.consents || {}), orgMismatch ? 1 : 0, reg.registration_id).run();

  await audit(env, 'registration_updated', 'registration', reg.registration_id, reg.reference, ipHash);

  const ev = await env.DB.prepare('SELECT title_en, title_ar FROM events WHERE code = ?').bind(reg.event_code).first();
  await sendMail(env, reg.email, `Registration updated — ${reg.reference}`, shell(
    `<h2 style="font-size:18px;margin:0 0 12px">Your registration has been updated</h2>
     <p>Reference <b>${reg.reference}</b> for <b>${ev ? ev.title_en : reg.event_code}</b> has been updated and remains under review.</p>
     <p style="direction:rtl;text-align:right">تم تحديث طلبك بالرقم المرجعي <b>${reg.reference}</b> في <b>${ev ? ev.title_ar : reg.event_code}</b> وهو لا يزال قيد المراجعة.</p>`));

  return json({ ok: true, status: 'under_review', reference: reg.reference }, 200, ch);
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
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
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

  await env.DB.prepare('UPDATE registrations SET status = ? WHERE reference = ?').bind(status, reference).run();
  await audit(env, 'registration_status_changed', 'registration', reg.registration_id, `${reference}:${status}`, ipHash);

  if (status === 'approved' || status === 'rejected') {
    const ev = await env.DB.prepare('SELECT title_en, title_ar FROM events WHERE code = ?').bind(reg.event_code).first();
    const body = status === 'approved'
      ? `<h2 style="font-size:18px;margin:0 0 12px">Your registration has been approved</h2>
         <p>Reference <b>${reference}</b> for <b>${ev ? ev.title_en : reg.event_code}</b> has been approved by the Technical Office for International Relations.</p>
         <p style="direction:rtl;text-align:right">تم اعتماد طلبك بالرقم المرجعي <b>${reference}</b> في <b>${ev ? ev.title_ar : reg.event_code}</b> من المكتب الفني للعلاقات الدولية.</p>`
      : `<h2 style="font-size:18px;margin:0 0 12px">Update on your registration</h2>
         <p>Reference <b>${reference}</b> for <b>${ev ? ev.title_en : reg.event_code}</b> was not approved. Contact the secretariat for details.</p>
         <p style="direction:rtl;text-align:right">لم يُعتمد طلبك بالرقم المرجعي <b>${reference}</b> في <b>${ev ? ev.title_ar : reg.event_code}</b>. تواصل مع الأمانة لمزيد من التفاصيل.</p>`;
    await sendMail(env, reg.email, `${status === 'approved' ? 'Registration approved' : 'Registration update'} — ${reference}`, shell(body));
  }

  return json({ ok: true, reference, status }, 200, ch);
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
  return json({ ok: true, invitation_id: id, code, event_codes: eventCodes }, 201, ch);
}

async function uploadFile(req, env, ch) {
  const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const s = await readSession(env, token);
  if (!s) return fail('session_expired', 401, ch);

  const form = await req.formData().catch(() => null);
  const file = form && form.get('file');
  const field = form ? String(form.get('field') || '').trim() : '';
  const accept = (form && form.get('accept')) || 'any';
  if (!file || typeof file === 'string' || !field) return fail('invalid_request', 400, ch);

  const allow = UPLOAD_ACCEPT[accept] || UPLOAD_ACCEPT.any;
  if (!allow.includes(file.type)) return fail('invalid_file_type', 400, ch);
  const maxMB = UPLOAD_MAX_MB[accept] || 10;
  if (file.size > maxMB * 1048576) return fail('file_too_large', 400, ch);

  const safeName = String(file.name || 'file').replace(/[^A-Za-z0-9._-]/g, '_').slice(-80);
  const key = `regs/${s.iv}/${await sha256(s.e)}/${field}-${crypto.randomUUID()}-${safeName}`;
  await env.FILES.put(key, file.stream(), { httpMetadata: { contentType: file.type } });

  await audit(env, 'file_uploaded', 'file', key, field, null);
  return json({ ok: true, key, filename: file.name, size: file.size, mime: file.type }, 201, ch);
}

async function adminGetFile(req, env, ch) {
  if (!requireAdmin(req, env)) return fail('unauthorized', 401, ch);
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
      if (req.method === 'POST' && pathname === '/v1/otp/verify')         return await verifyOtp(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations')      return await createRegistration(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit-link')  return await requestEditLink(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit-fetch') return await fetchForEdit(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/registrations/edit')       return await updateRegistration(req, env, ch, ipHash);
      if (req.method === 'GET'  && pathname === '/v1/admin/registrations')return await adminRead(req, env, ch, false);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.csv')   return await adminRead(req, env, ch, true);
      if (req.method === 'GET'  && pathname === '/v1/admin/export.json')  return await adminExportFull(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/invitations')  return await adminListInvitations(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/admin/invitations')  return await adminCreateInvitation(req, env, ch, ipHash);
      if (req.method === 'POST' && pathname === '/v1/uploads')            return await uploadFile(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/files')        return await adminGetFile(req, env, ch);
      if (req.method === 'GET'  && pathname === '/v1/admin/attachments')  return await adminAttachments(req, env, ch);
      if (req.method === 'POST' && pathname === '/v1/admin/registrations/status') return await adminSetStatus(req, env, ch, ipHash);
      if (pathname === '/v1/health') return json({ ok: true, time: new Date().toISOString() }, 200, ch);
      return fail('not_found', 404, ch);
    } catch (e) {
      return fail('server_error', 500, ch);
    }
  }
};
