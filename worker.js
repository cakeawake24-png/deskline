// Deskline API v2 · Cloudflare Worker + D1 + R2
const enc = new TextEncoder(), hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
const eq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0 };
const unhex = s => Uint8Array.from(s.match(/../g).map(x => parseInt(x, 16)));

/* ---------- contraseñas: PBKDF2-SHA256 + sal única + pepper secreto ---------- */
async function kdf(pw, salt, it, env) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw + env.PEPPER), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: it }, k, 256));
}
async function mkHash(pw, env) {
  const s = crypto.getRandomValues(new Uint8Array(16)), it = +env.ITER || 100000;
  return `v2$${it}$${hex(s)}$${await kdf(pw, s, it, env)}`;
}
async function check(pw, st, env) {
  if (st.startsWith('v2$')) { const [, it, s, h] = st.split('$'); return eq(h, await kdf(pw, unhex(s), +it, env)); }
  return eq(st, await sha(pw)); // formato antiguo; se actualiza al iniciar sesión
}

/* ---------- límites de intentos ---------- */
async function cnt(db, k, win) { const r = await db.prepare('SELECT n,ts FROM att WHERE k=?').bind(k).first(); return r && Date.now() - r.ts < win ? r.n : 0 }
async function hit(db, k, win) {
  const r = await db.prepare('SELECT n,ts FROM att WHERE k=?').bind(k).first(), live = r && Date.now() - r.ts < win, n = live ? r.n + 1 : 1;
  await db.prepare('INSERT INTO att VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET n=excluded.n,ts=excluded.ts').bind(k, n, live ? r.ts : Date.now()).run();
  return n;
}

/* ---------- limpieza de datos ---------- */
const URLOK = /^(data:(image|video)\/[a-z0-9.+-]+;base64,[A-Za-z0-9+\/=]+|https:\/\/[\w.-]+(:\d+)?\/api\/media\/[\w-]{36})$/i;
function san(v) { // evita inyectar código mediante enlaces de imagen/video
  if (Array.isArray(v)) return v.map(san);
  if (v && typeof v === 'object') {
    const o = {};
    for (const k in v) { if (k === '__proto__') continue; o[k] = ['src', 'photo', 'video', 'img'].includes(k) && typeof v[k] === 'string' && v[k] && !URLOK.test(v[k]) ? '' : san(v[k]); }
    return o;
  }
  return v;
}
const keyOf = x => x && typeof x === 'object' ? (x.id ?? x.email) : undefined;
function merge(a, b) {
  if (Array.isArray(a) && Array.isArray(b)) {
    const m = new Map(), id = x => keyOf(x) ?? JSON.stringify(x);
    a.forEach(x => m.set(id(x), x));
    b.forEach(x => m.set(id(x), m.has(id(x)) && typeof x === 'object' ? merge(m.get(id(x)), x) : x));
    return [...m.values()];
  }
  if (a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b)) {
    const o = {};
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) o[k] = k in b ? (k in a ? merge(a[k], b[k]) : b[k]) : a[k];
    return o;
  }
  return b;
}

/* ---------- propiedad de los datos: nadie edita lo de otro usuario ---------- */
const own = (o, n, me) => [...(o || []).filter(u => u !== me), ...((n || []).includes(me) ? [me] : [])];
const mine = (old, inc, me, f, fx) => {
  const r = [];
  for (const x of old || []) if (x[f] !== me) { const n = (inc || []).find(y => y.id === x.id); r.push(n ? fx(x, n) : x); }
  for (const x of inc || []) if (x[f] === me) r.push(x);
  return r;
};
const SELF = ['dx_creator', 'dx_acct', 'dx_set', 'dx_fol', 'dx_int', 'dx_viol'];
const KEYS = [...SELF, 'dx_plan', 'dx_not', 'dx_dm', 'dx_posts', 'dx_ch', 'dx_pages', 'dx_ads', 'desklineUsers', 'desklineStories'];
function rule(k, old, inc, me) {
  if (SELF.includes(k)) { const o = { ...(old || {}) }; if (inc && inc[me] !== undefined) o[me] = inc[me]; else delete o[me]; return o; }
  switch (k) {
    case 'dx_plan': return old || {}; // el plan solo cambia al verificar un pago
    case 'dx_not': { const o = { ...(old || {}) }; for (const e in inc || {}) o[e] = e === me ? inc[e] : merge(o[e] || [], (inc[e] || []).slice(0, 50)); return o; }
    case 'dx_dm': { const o = { ...(old || {}) }; for (const p in inc || {}) { if (!p.split('|').includes(me)) continue; const od = o[p] || []; o[p] = merge(od, (inc[p] || []).filter(m => m.f === me || od.some(x => x.at === m.at && x.f === m.f))); } return o; }
    case 'dx_posts': return mine(old, inc, me, 'by', (x, n) => ({ ...x,
      react: Object.fromEntries([...new Set([...Object.keys(x.react || {}), ...Object.keys(n.react || {})])].map(e => [e, own((x.react || {})[e], (n.react || {})[e], me)])),
      rp: own(x.rp, n.rp, me), reports: own(x.reports, n.reports, me),
      cm: merge(x.cm || [], (n.cm || []).filter(c => c.by === me || (x.cm || []).some(y => y.at === c.at && y.by === c.by))) })).sort((a, b) => b.at - a.at);
    case 'dx_ch': return mine(old, inc, me, 'owner', (x, n) => ({ ...x, members: own(x.members, n.members, me), msgs: merge(x.msgs || [], (n.msgs || []).filter(m => m.f === me || (x.msgs || []).some(y => JSON.stringify(y) === JSON.stringify(m)))) }));
    case 'dx_pages': return mine(old, inc, me, 'owner', (x, n) => ({ ...x, fans: own(x.fans, n.fans, me) }));
    case 'dx_ads': return mine(old, inc, me, 'by', (x, n) => ({ ...x, imp: Math.max(x.imp, n.imp || 0), clk: Math.max(x.clk, n.clk || 0) }));
    case 'desklineUsers': return (old || []).filter(u => u.email !== me).concat((inc || []).filter(u => u.email === me).map(({ passwordHash, ...u }) => u));
    case 'desklineStories': return mine(old, inc, me, 'authorEmail', (x, n) => ({ ...x, likes: own(x.likes, n.likes, me) }));
  }
}
function view(k, v, me) { // cada usuario solo recibe lo que le corresponde
  if (k === 'dx_plan') return Object.fromEntries(Object.entries(v || {}).filter(([, x]) => x && typeof x === 'object' && x.u > Date.now()));
  if (k === 'dx_dm') return Object.fromEntries(Object.entries(v || {}).filter(([p]) => p.split('|').includes(me)));
  if (k === 'dx_not') return { [me]: (v || {})[me] || [] };
  if (k === 'dx_int' || k === 'dx_viol') return { [me]: (v || {})[me] };
  return v;
}

async function upState(db, k, fn) {
  const c = await db.prepare('SELECT v,ver FROM state WHERE k=?').bind(k).first(), nv = fn(c ? JSON.parse(c.v) : null);
  await db.prepare('INSERT INTO state VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v,ver=excluded.ver').bind(k, JSON.stringify(nv), (c ? c.ver : 0) + 1).run();
}
const MEDIAURL = /^https:\/\/[\w.-]+(:\d+)?\/api\/media\/[\w-]{36}$/;
const MIME = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm'];
const SIG = { 'image/jpeg': /^ffd8ff/, 'image/png': /^89504e47/, 'image/gif': /^47494638/, 'image/webp': /^52494646/, 'video/mp4': /^.{8}66747970/, 'video/webm': /^1a45dfa3/ };

/* ---------- códigos de verificación: correo (SendGrid) y SMS (Twilio Verify) ---------- */
const OTP_TTL = 6e5, OTP_TRIES = 5;
let otpReady;
const ensureOtp = db => otpReady || (otpReady = db.prepare('CREATE TABLE IF NOT EXISTS otp(k TEXT PRIMARY KEY, h TEXT, exp INTEGER, tries INTEGER, ts INTEGER)').run().catch(e => { otpReady = null; throw e; }));
const code6 = () => { const a = new Uint32Array(1); do crypto.getRandomValues(a); while (a[0] >= 4294000000); return String(a[0] % 1e6).padStart(6, '0'); }; // sin sesgo
const MAIL = {
  es: ['Tu código de verificación de Deskline', 'Tu código de verificación es', 'Vence en 10 minutos. Si no fuiste tú, ignora este mensaje.'],
  en: ['Your Deskline verification code', 'Your verification code is', 'It expires in 10 minutes. If this wasn\'t you, ignore this message.'],
  pt: ['Seu código de verificação do Deskline', 'Seu código de verificação é', 'Expira em 10 minutos. Se não foi você, ignore esta mensagem.'],
  fr: ['Votre code de vérification Deskline', 'Votre code de vérification est', 'Il expire dans 10 minutes. Si ce n\'était pas vous, ignorez ce message.']
};
async function sendMail(env, to, code, lang) {
  const [s, a, b] = MAIL[lang] || MAIL.es;
  const r = await fetch('https://api.sendgrid.com/v3/mail/send', { method: 'POST', headers: { authorization: 'Bearer ' + env.SENDGRID_API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({ personalizations: [{ to: [{ email: to }] }], from: { email: env.MAIL_FROM, name: 'Deskline' }, subject: s,
      content: [{ type: 'text/plain', value: `${a}: ${code}\n\n${b}` },
        { type: 'text/html', value: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px"><h2 style="color:#6d28d9;margin:0 0 12px">Deskline</h2><p>${a}</p><p style="font-size:34px;letter-spacing:8px;font-weight:700;margin:12px 0">${code}</p><p style="color:#666;font-size:13px">${b}</p></div>` }] }) });
  if (r.status !== 202) console.error('sendgrid', r.status, (await r.text()).slice(0, 300));
  return r.status === 202;
}
const twilio = (env, path, params) => fetch(`https://verify.twilio.com/v2/Services/${env.TWILIO_VERIFY_SID}/${path}`, { method: 'POST',
  headers: { authorization: 'Basic ' + btoa(env.TWILIO_ACCOUNT_SID + ':' + env.TWILIO_AUTH_TOKEN), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(params) });

export default {
  async fetch(req, env) {
    const H = { 'access-control-allow-origin': env.ORIGIN || '*', 'access-control-allow-headers': 'content-type,authorization,range', 'access-control-allow-methods': 'GET,PUT,POST,OPTIONS', 'content-type': 'application/json',
      'x-content-type-options': 'nosniff', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'strict-transport-security': 'max-age=31536000' };
    const out = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: H });
    if (req.method === 'OPTIONS') return new Response(null, { headers: H });
    const p = new URL(req.url).pathname, db = env.DB, ip = req.headers.get('cf-connecting-ip') || 'x';
    try {
      if (!env.PEPPER) return out({ error: 'config' }, 500);
      /* medios: la URL contiene un identificador aleatorio imposible de adivinar */
      const mm = p.match(/^\/api\/media\/([\w-]{36})$/);
      if (req.method === 'GET' && mm) {
        const o = await env.MEDIA.get('m/' + mm[1], { range: req.headers });
        if (!o) return new Response('no', { status: 404, headers: H });
        const h = { ...H, 'content-type': o.httpMetadata.contentType, 'cache-control': 'public,max-age=86400,immutable', 'content-security-policy': "default-src 'none'", 'accept-ranges': 'bytes' };
        if (o.range) { h['content-range'] = `bytes ${o.range.offset}-${o.range.offset + o.range.length - 1}/${o.size}`; return new Response(o.body, { status: 206, headers: h }); }
        return new Response(o.body, { headers: h });
      }
      if (req.method === 'POST' && (p === '/api/otp/send' || p === '/api/otp/check')) {
        const raw = await req.text(); let b = {}; try { b = raw.length > 2000 ? {} : JSON.parse(raw); } catch { } if (!b || typeof b !== 'object') b = {}; const ch = b.channel, now = Date.now();
        let to = String(b.to || '').trim();
        if (ch === 'email') { to = to.toLowerCase(); if (!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(to)) return out({ error: 'datos' }, 400); }
        else if (ch === 'sms') {
          to = to.replace(/[\s()-]/g, ''); if (!/^\+[1-9]\d{6,14}$/.test(to)) return out({ error: 'datos' }, 400);
          const allow = (env.SMS_ALLOW || '').split(',').map(x => x.trim()).filter(Boolean); // países permitidos (anti-fraude de SMS)
          if (allow.length && !allow.some(c => to.startsWith('+' + c))) return out({ error: 'pais' }, 400);
        } else return out({ error: 'datos' }, 400);
        await ensureOtp(db);
        const k = ch + ':' + to, lang = ['es', 'en', 'pt', 'fr'].includes(b.lang) ? b.lang : 'es';
        if (p === '/api/otp/send') {
          if (ch === 'email' ? !env.SENDGRID_API_KEY || !env.MAIL_FROM : !env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_VERIFY_SID) return out({ error: 'config' }, 500);
          await db.prepare('DELETE FROM otp WHERE exp<?').bind(now - 36e5).run();
          const prev = await db.prepare('SELECT ts FROM otp WHERE k=?').bind(k).first();
          if (prev && now - prev.ts < 6e4) return out({ error: 'wait' }, 429); // 1 envío por minuto a cada destino
          if (await hit(db, 'os:' + ip, 36e5) > 20 || await hit(db, 'od:' + k, 36e5) > 5) return out({ error: 'limit' }, 429);
          if (ch === 'email' && await hit(db, 'mail:day', 864e5) > (+env.MAIL_DAILY || 300)) return out({ error: 'limit' }, 429);
          const code = ch === 'email' ? code6() : '';
          if (ch === 'sms' && await hit(db, 'sms:day', 864e5) > (+env.SMS_DAILY || 200)) return out({ error: 'limit' }, 429); // tope diario de gasto
          await db.prepare('INSERT INTO otp VALUES(?,?,?,0,?) ON CONFLICT(k) DO UPDATE SET h=excluded.h,exp=excluded.exp,tries=0,ts=excluded.ts').bind(k, code ? await sha(code + ':' + k + ':' + env.PEPPER) : '', now + OTP_TTL, now).run();
          let ok;
          if (ch === 'email') ok = await sendMail(env, to, code, lang);
          else { const r = await twilio(env, 'Verifications', { To: to, Channel: 'sms', Locale: lang }); if (r.status === 429) { return out({ error: 'limit' }, 429); } ok = r.ok; if (!ok) console.error('twilio', r.status, (await r.text()).slice(0, 300)); }
          if (!ok) { await db.prepare('DELETE FROM otp WHERE k=?').bind(k).run(); return out({ error: 'send' }, 502); }
          return out({ ok: 1 });
        }
        if (await hit(db, 'oc:' + ip, 9e5) > 40) return out({ error: 'limit' }, 429);
        const code = String(b.code || '');
        if (!/^\d{6}$/.test(code)) return out({ error: 'bad' }, 400);
        const row = await db.prepare('UPDATE otp SET tries=tries+1 WHERE k=? AND exp>? AND tries<? RETURNING h').bind(k, now, OTP_TRIES).first(); // atómico: ráfagas en paralelo no suman más de 5 intentos
        if (!row) return out({ error: 'expired' }, 400);
        let ok;
        if (ch === 'email') ok = eq(row.h, await sha(code + ':' + k + ':' + env.PEPPER));
        else { const r = await twilio(env, 'VerificationCheck', { To: to, Code: code }), j = await r.json().catch(() => ({})); ok = r.ok && j.status === 'approved'; }
        if (!ok) return out({ error: 'bad' }, 401);
        if (!await db.prepare('DELETE FROM otp WHERE k=? RETURNING k').bind(k).first()) return out({ error: 'expired' }, 400); // un solo uso
        return out({ ok: 1 });
      }
      if (req.method === 'POST' && (p === '/api/register' || p === '/api/login')) {
        const { email, password } = await req.json(), e = String(email || '').toLowerCase().trim(), pw = String(password || '');
        if (!/^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/.test(e) || pw.length > 128) return out({ error: 'datos' }, 400);
        await db.prepare('DELETE FROM tok WHERE exp<?').bind(Date.now()).run();
        const r = await db.prepare('SELECT hash FROM auth WHERE email=?').bind(e).first();
        if (p === '/api/register') {
          if (pw.length < 8 || !/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return out({ error: 'weak' }, 400);
          if (await hit(db, 'r:' + ip, 36e5) > 10) return out({ error: 'limit' }, 429);
          if (r) return out({ error: 'exists' }, 409);
          await db.prepare('INSERT INTO auth VALUES(?,?)').bind(e, await mkHash(pw, env)).run();
        } else {
          if (await cnt(db, 'l:' + e, 9e5) >= 5 || await cnt(db, 'i:' + ip, 9e5) >= 30) return out({ error: 'limit' }, 429);
          const ok = r ? await check(pw, r.hash, env) : (await kdf(pw, new Uint8Array(16), 1000, env), false); // tiempo similar si el correo no existe
          if (!ok) { await hit(db, 'l:' + e, 9e5); await hit(db, 'i:' + ip, 9e5); return out({ error: 'bad' }, 401); }
          await db.prepare('DELETE FROM att WHERE k=?').bind('l:' + e).run();
          if (!r.hash.startsWith('v2$')) await db.prepare('UPDATE auth SET hash=? WHERE email=?').bind(await mkHash(pw, env), e).run();
        }
        const t = crypto.randomUUID() + crypto.randomUUID();
        await db.prepare('INSERT INTO tok VALUES(?,?,?)').bind(await sha(t), e, Date.now() + 6048e5).run(); // 7 días, guardado como hash
        return out({ token: t });
      }
      const tk = (req.headers.get('authorization') || '').slice(7), th = await sha(tk);
      const row = await db.prepare('SELECT email FROM tok WHERE t=? AND exp>?').bind(th, Date.now()).first();
      if (!row) return out({ error: 'auth' }, 401);
      const me = row.email;
      if (req.method === 'POST' && p === '/api/logout') { await db.prepare('DELETE FROM tok WHERE t=?').bind(th).run(); return out({ ok: 1 }); }
      if (req.method === 'POST' && p === '/api/media') {
        const ct = (req.headers.get('content-type') || '').split(';')[0], max = ct.startsWith('video/') ? 25e6 : 10e6;
        if (!MIME.includes(ct)) return out({ error: 'tipo' }, 415);
        if (+req.headers.get('content-length') > max) return out({ error: 'grande' }, 413);
        if (await hit(db, 'u:' + me, 864e5) > 100) return out({ error: 'limit' }, 429);
        const buf = await req.arrayBuffer();
        if (buf.byteLength > max || !SIG[ct].test(hex(buf.slice(0, 12)))) return out({ error: 'archivo' }, 415);
        const id = crypto.randomUUID();
        await env.MEDIA.put('m/' + id, buf, { httpMetadata: { contentType: ct } });
        return out({ url: '/api/media/' + id });
      }
      /* ---------- pagos con Yape / Plin (verificación manual) ---------- */
      const ADMIN = (env.ADMIN_EMAIL || '').toLowerCase().trim(), PRICE = { plus: +env.PRICE_PLUS || 18, pro: +env.PRICE_PRO || 36 };
      const note = (to, text) => upState(db, 'dx_not', o => { o = o || {}; o[to] = [{ id: Date.now() + Math.random(), at: Date.now(), type: 'sys', text }, ...(o[to] || [])].slice(0, 50); return o; });
      if (req.method === 'GET' && p === '/api/me') return out({ admin: !!ADMIN && me === ADMIN, prices: PRICE });
      if (p === '/api/pay' && req.method === 'GET') {
        const { results } = await db.prepare('SELECT id,plan,amount,method,op,status,reason,ts FROM payments WHERE email=? ORDER BY ts DESC LIMIT 10').bind(me).all();
        return out({ rows: results });
      }
      if (p === '/api/pay' && req.method === 'POST') {
        const b = await req.json(), op = String(b.op || '').replace(/\s/g, ''), holder = String(b.holder || '').slice(0, 80), rc = String(b.receipt || '');
        if (!PRICE[b.plan] || !['yape', 'plin'].includes(b.method) || !/^[A-Za-z0-9]{6,20}$/.test(op) || !holder || !MEDIAURL.test(rc) || !(await env.MEDIA.head('m/' + rc.slice(-36)))) return out({ error: 'datos' }, 400);
        if (await hit(db, 'p:' + me, 864e5) > 10) return out({ error: 'limit' }, 429);
        const pend = await db.prepare("SELECT COUNT(*) c FROM payments WHERE email=? AND status='pending'").bind(me).first();
        if (pend.c >= 3) return out({ error: 'limit' }, 429);
        if (await db.prepare("SELECT 1 x FROM payments WHERE op=? AND status!='rejected'").bind(op).first()) return out({ error: 'dup' }, 409);
        await db.prepare("INSERT INTO payments VALUES(?,?,?,?,?,?,?,?,'pending','',?,0)").bind(crypto.randomUUID(), me, b.plan, PRICE[b.plan], b.method, op, holder, rc, Date.now()).run();
        if (ADMIN) await note(ADMIN, '💳 Nuevo pago por verificar de ' + me);
        return out({ ok: 1 });
      }
      if (p === '/api/admin/pay' && ADMIN && me === ADMIN) {
        if (req.method === 'GET') {
          const { results } = await db.prepare("SELECT id,email,plan,amount,method,op,holder,receipt,ts FROM payments WHERE status='pending' ORDER BY ts").all();
          return out({ rows: results });
        }
        if (req.method === 'POST') {
          const { id, ok, reason } = await req.json(), pay = await db.prepare("SELECT * FROM payments WHERE id=? AND status='pending'").bind(id).first();
          if (!pay) return out({ error: 'no' }, 404);
          await db.prepare('UPDATE payments SET status=?,reason=?,decided=? WHERE id=?').bind(ok ? 'approved' : 'rejected', String(reason || '').slice(0, 200), Date.now(), id).run();
          if (ok) {
            let until;
            await upState(db, 'dx_plan', o => { o = o || {}; const c = o[pay.email]; until = Math.max(Date.now(), c && c.p === pay.plan && c.u > Date.now() ? c.u : 0) + 30 * 864e5; o[pay.email] = { p: pay.plan, u: until }; return o; });
            await note(pay.email, `✅ Pago verificado: tu plan ${pay.plan === 'pro' ? 'Creator Pro' : 'Plus'} está activo hasta ${new Date(until).toLocaleDateString('es-PE')}.`);
          } else await note(pay.email, '❌ No pudimos verificar tu pago: ' + (reason || 'revisa los datos') + '. Puedes volver a enviarlo.');
          return out({ ok: 1 });
        }
      }
      if (req.method === 'GET' && p === '/api/state') {
        const { results } = await db.prepare('SELECT k,v,ver FROM state').all(), s = {};
        for (const r of results) s[r.k] = { ver: r.ver, value: view(r.k, JSON.parse(r.v), me) };
        return out(s);
      }
      const m = p.match(/^\/api\/state\/(\w+)$/);
      if (req.method === 'PUT' && m && KEYS.includes(m[1])) {
        const k = m[1], txt = await req.text();
        if (txt.length > 1.5e6) return out({ error: 'grande' }, 413);
        const { value } = JSON.parse(txt);
        const cur = await db.prepare('SELECT v,ver FROM state WHERE k=?').bind(k).first();
        const nv = rule(k, cur && JSON.parse(cur.v), san(value), me), ver = (cur ? cur.ver : 0) + 1;
        await db.prepare('INSERT INTO state VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v,ver=excluded.ver').bind(k, JSON.stringify(nv), ver).run();
        return out({ ver, value: view(k, nv, me) });
      }
      return out({ error: 'not found' }, 404);
    } catch (e) { console.error('worker', e && e.message); return out({ error: 'server' }, 500); }
  }
};
