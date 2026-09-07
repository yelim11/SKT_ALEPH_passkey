'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'db.json');
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = process.env.RP_NAME || 'Yerim Passkey Portfolio';
const ORIGIN = (process.env.ORIGIN || `http://localhost:${PORT}`).replace(/\/$/, '');
const CHALLENGE_TTL = 5 * 60 * 1000;
const SESSION_TTL = 2 * 60 * 60 * 1000;

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }
function fromB64url(s) { return Buffer.from(String(s || ''), 'base64url'); }
function randomId(n = 24) { return b64url(crypto.randomBytes(n)); }
function nowISO() { return new Date().toISOString(); }
function sha256(data) { return crypto.createHash('sha256').update(data).digest(); }
function safePreview(s) { s = String(s || ''); return s.length < 18 ? s : `${s.slice(0, 8)}…${s.slice(-6)}`; }

function defaultDB() {
  return {
    users: [
      {
        id: 'owner', username: 'yerim-owner', label: '예림 소유자 계정', isOwner: true,
        webAuthnUserID: randomId(32), createdAt: nowISO(),
        privateItems: [
          { id: 'owner-1', title: '준비 중인 프로젝트 메모', body: '작은 보안 실습을 포트폴리오 형태로 정리하고 다음 개선점을 기록한다.' },
          { id: 'owner-2', title: '지원 예정 목록', body: '가상의 A팀, B팀, C팀을 비교하고 필요한 기술을 정리한다.' },
          { id: 'owner-3', title: '이번 주 회고', body: '기능 구현 뒤 실패 요청까지 직접 재현해 기록하는 습관을 유지한다.' },
        ],
      },
      {
        id: 'tester', username: 'yerim-tester', label: '과제용 테스트 계정', isOwner: false,
        webAuthnUserID: randomId(32), createdAt: nowISO(),
        privateItems: [
          { id: 'tester-1', title: '테스트 프로젝트 메모', body: '테스트 계정에만 보이는 가상 프로젝트 메모입니다.' },
          { id: 'tester-2', title: '테스트 지원 목록', body: 'Alpha, Beta, Gamma는 과제 검증을 위한 가상의 항목입니다.' },
          { id: 'tester-3', title: '테스트 회고', body: '다른 계정에서 이 내용이 보이지 않는지 확인하기 위한 데이터입니다.' },
        ],
      },
    ],
    passkeys: [], challenges: [], sessions: [], audit: [],
  };
}

function loadDB() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) {
    const db = defaultDB();
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
    return db;
  }
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { const db = defaultDB(); fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); return db; }
}
function saveDB(db) { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
function cleanup(db) {
  const t = Date.now();
  db.challenges = db.challenges.filter(x => x.expiresAt > t);
  db.sessions = db.sessions.filter(x => x.expiresAt > t);
  if (db.audit.length > 300) db.audit = db.audit.slice(-300);
}
function audit(db, event, details = {}) {
  db.audit.push({ at: nowISO(), event, ...details });
  if (db.audit.length > 300) db.audit = db.audit.slice(-300);
}
function getUser(db, id) { return db.users.find(u => u.id === id); }
function getPasskeys(db, userId) { return db.passkeys.filter(p => p.userId === userId); }

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('='); if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function sessionFor(req, db) {
  cleanup(db);
  const token = parseCookies(req).yerim_session;
  if (!token) return null;
  const hash = sha256(token).toString('hex');
  const s = db.sessions.find(x => x.tokenHash === hash && x.expiresAt > Date.now());
  if (!s) return null;
  const user = getUser(db, s.userId);
  return user ? { session: s, user } : null;
}
function setSession(res, db, user) {
  const token = randomId(32);
  const tokenHash = sha256(token).toString('hex');
  db.sessions = db.sessions.filter(s => s.userId !== user.id);
  db.sessions.push({ tokenHash, userId: user.id, createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL });
  const secure = ORIGIN.startsWith('https://') ? '; Secure' : '';
  res.setHeader('Set-Cookie', `yerim_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(SESSION_TTL/1000)}${secure}`);
}
function clearSession(req, res, db) {
  const token = parseCookies(req).yerim_session;
  if (token) {
    const hash = sha256(token).toString('hex');
    db.sessions = db.sessions.filter(s => s.tokenHash !== hash);
  }
  res.setHeader('Set-Cookie', 'yerim_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}

function json(res, status, body, extra = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(body));
}
function text(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff' }); res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = ''; req.on('data', c => { data += c; if (data.length > 2_000_000) req.destroy(); });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(e); } }); req.on('error', reject);
  });
}

function createChallenge(db, type, account) {
  const item = { id: randomId(18), challenge: randomId(32), type, account, createdAt: Date.now(), expiresAt: Date.now() + CHALLENGE_TTL };
  db.challenges.push(item); return item;
}
function consumeChallenge(db, id, type, account) {
  cleanup(db);
  const i = db.challenges.findIndex(c => c.id === id && c.type === type && c.account === account && c.expiresAt > Date.now());
  if (i < 0) return null;
  const [c] = db.challenges.splice(i, 1); return c;
}

// Minimal CBOR decoder sufficient for WebAuthn attestationObject/COSE keys.
function decodeCBOR(buffer, start = 0) {
  let o = start;
  function uint(add) {
    if (add < 24) return add;
    if (add === 24) return buffer[o++];
    if (add === 25) { const v = buffer.readUInt16BE(o); o += 2; return v; }
    if (add === 26) { const v = buffer.readUInt32BE(o); o += 4; return v; }
    if (add === 27) { const v = Number(buffer.readBigUInt64BE(o)); o += 8; return v; }
    throw new Error('unsupported CBOR length');
  }
  function item() {
    const b = buffer[o++]; if (b === undefined) throw new Error('truncated CBOR');
    const major = b >> 5, add = b & 31;
    if (major === 0) return uint(add);
    if (major === 1) return -1 - uint(add);
    if (major === 2) { const n = uint(add), v = buffer.subarray(o, o+n); o += n; return Buffer.from(v); }
    if (major === 3) { const n = uint(add), v = buffer.subarray(o, o+n).toString('utf8'); o += n; return v; }
    if (major === 4) { const n = uint(add), a = []; for (let i=0;i<n;i++) a.push(item()); return a; }
    if (major === 5) { const n = uint(add), m = new Map(); for (let i=0;i<n;i++) m.set(item(), item()); return m; }
    if (major === 6) { uint(add); return item(); }
    if (major === 7) {
      if (add === 20) return false; if (add === 21) return true; if (add === 22) return null; if (add === 23) return undefined;
      throw new Error('unsupported CBOR simple value');
    }
    throw new Error('unsupported CBOR type');
  }
  const value = item(); return { value, offset: o };
}

function parseAuthData(buf) {
  if (buf.length < 37) throw new Error('authenticatorData too short');
  const rpIdHash = buf.subarray(0,32); const flags = buf[32]; const signCount = buf.readUInt32BE(33);
  let credentialId = null, cose = null;
  if (flags & 0x40) {
    let o = 37 + 16; if (buf.length < o + 2) throw new Error('attested data missing');
    const len = buf.readUInt16BE(o); o += 2; credentialId = buf.subarray(o,o+len); o += len;
    cose = decodeCBOR(buf, o).value;
  }
  return { rpIdHash, flags, signCount, credentialId, cose };
}
function publicKeyFromCOSE(cose) {
  if (!(cose instanceof Map)) throw new Error('COSE key missing');
  const kty = cose.get(1), alg = cose.get(3);
  if (kty === 2 && alg === -7) {
    const crv = cose.get(-1), x = cose.get(-2), y = cose.get(-3);
    if (crv !== 1 || !Buffer.isBuffer(x) || !Buffer.isBuffer(y)) throw new Error('unsupported EC key');
    const jwk = { kty:'EC', crv:'P-256', x:b64url(x), y:b64url(y), ext:true };
    return { key: crypto.createPublicKey({ key:jwk, format:'jwk' }), jwk, alg };
  }
  if (kty === 3 && alg === -257) {
    const n = cose.get(-1), e = cose.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) throw new Error('unsupported RSA key');
    const jwk = { kty:'RSA', n:b64url(n), e:b64url(e), ext:true };
    return { key: crypto.createPublicKey({ key:jwk, format:'jwk' }), jwk, alg };
  }
  if (kty === 1 && alg === -8) {
    const crv = cose.get(-1), x = cose.get(-2);
    if (crv !== 6 || !Buffer.isBuffer(x)) throw new Error('unsupported OKP key');
    const jwk = { kty:'OKP', crv:'Ed25519', x:b64url(x), ext:true };
    return { key: crypto.createPublicKey({ key:jwk, format:'jwk' }), jwk, alg };
  }
  throw new Error(`unsupported credential algorithm: kty=${kty}, alg=${alg}`);
}
function parseClientData(encoded, expectedType, expectedChallenge) {
  const raw = fromB64url(encoded); const client = JSON.parse(raw.toString('utf8'));
  if (client.type !== expectedType) throw new Error('clientData type mismatch');
  if (client.challenge !== expectedChallenge) throw new Error('challenge mismatch');
  if (client.origin !== ORIGIN) throw new Error(`origin mismatch: ${client.origin}`);
  return { raw, client };
}
function verifyRpAndFlags(authData) {
  const parsed = parseAuthData(authData);
  const expected = sha256(RP_ID);
  if (!crypto.timingSafeEqual(parsed.rpIdHash, expected)) throw new Error('RP ID hash mismatch');
  if (!(parsed.flags & 0x01)) throw new Error('user presence missing');
  if (!(parsed.flags & 0x04)) throw new Error('user verification missing');
  return parsed;
}
function verifyAuthSignature(passkey, authData, clientDataRaw, signature) {
  const key = crypto.createPublicKey({ key: passkey.publicJwk, format: 'jwk' });
  const signed = Buffer.concat([authData, sha256(clientDataRaw)]);
  if (passkey.alg === -8) return crypto.verify(null, signed, key, signature);
  return crypto.verify('sha256', signed, key, signature);
}

function canRegister(db, req, account) {
  const auth = sessionFor(req, db); const ownerCount = getPasskeys(db, 'owner').length;
  if (account === 'owner' && ownerCount === 0) return true;
  if (!auth) return false;
  if (auth.user.id === account) return true;
  return auth.user.isOwner && account === 'tester';
}

async function handleApi(req, res, url, db) {
  const auth = sessionFor(req, db);
  if (req.method === 'GET' && url.pathname === '/api/status') {
    cleanup(db); saveDB(db);
    return json(res, 200, {
      ok: true,
      webauthn: { rpID: RP_ID, origin: ORIGIN, rpName: RP_NAME },
      ownerReady: getPasskeys(db,'owner').length > 0,
      accounts: db.users.map(u => ({ id:u.id, label:u.label, passkeyCount:getPasskeys(db,u.id).length })),
      session: auth ? { userId:auth.user.id, label:auth.user.label, isOwner:auth.user.isOwner } : null,
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/register/options') {
    const body = await readBody(req); const account = body.account || 'owner'; const user = getUser(db, account);
    if (!user) return json(res,404,{error:'USER_NOT_FOUND'});
    if (!canRegister(db, req, account)) return json(res,403,{error:'REGISTER_FORBIDDEN',message:'첫 패스키 이후 추가 등록은 로그인 상태에서만 가능합니다.'});
    const c = createChallenge(db,'register',account);
    const options = {
      challenge: c.challenge,
      rp: { id: RP_ID, name: RP_NAME },
      user: { id: user.webAuthnUserID, name:user.username, displayName:user.label },
      pubKeyCredParams: [{type:'public-key',alg:-7},{type:'public-key',alg:-257},{type:'public-key',alg:-8}],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: { residentKey:'preferred', userVerification:'required' },
      excludeCredentials: getPasskeys(db,account).map(p => ({ type:'public-key', id:p.id, transports:p.transports || [] })),
    };
    audit(db,'registration_options',{account,challengePreview:safePreview(c.challenge)}); saveDB(db);
    return json(res,200,{challengeId:c.id,challengePreview:safePreview(c.challenge),options});
  }

  if (req.method === 'POST' && url.pathname === '/api/register/cancel') {
    const body = await readBody(req); const i = db.challenges.findIndex(c => c.id === body.challengeId && c.account === body.account && c.type==='register');
    if (i >= 0) db.challenges.splice(i,1); audit(db,'registration_cancel',{account:body.account}); saveDB(db);
    return json(res,200,{ok:true});
  }

  if (req.method === 'POST' && url.pathname === '/api/register/verify') {
    const body = await readBody(req); const account = body.account || 'owner';
    if (!canRegister(db, req, account)) return json(res,403,{error:'REGISTER_FORBIDDEN'});
    const c = consumeChallenge(db,body.challengeId,'register',account);
    if (!c) { saveDB(db); return json(res,401,{error:'CHALLENGE_MISSING_OR_USED'}); }
    try {
      const r = body.response || {}; const cr = r.response || {};
      const { raw: clientRaw } = parseClientData(cr.clientDataJSON,'webauthn.create',c.challenge);
      void clientRaw;
      const att = decodeCBOR(fromB64url(cr.attestationObject)).value;
      if (!(att instanceof Map)) throw new Error('invalid attestationObject');
      const authData = att.get('authData'); if (!Buffer.isBuffer(authData)) throw new Error('authData missing');
      const parsed = verifyRpAndFlags(authData);
      if (!parsed.credentialId || !parsed.cose) throw new Error('credential public key missing');
      const credentialId = b64url(parsed.credentialId);
      if (credentialId !== r.id && credentialId !== r.rawId) throw new Error('credential id mismatch');
      if (db.passkeys.some(p => p.id === credentialId)) throw new Error('credential already registered');
      const pk = publicKeyFromCOSE(parsed.cose);
      const entry = {
        id: credentialId, userId:account,
        name: String(body.passkeyName || '내 패스키').slice(0,40),
        storageType: String(body.storageType || '기기/비밀번호 관리자').slice(0,80),
        transports: Array.isArray(cr.transports) ? cr.transports.slice(0,10) : [],
        publicJwk: pk.jwk, publicKey: b64url(Buffer.from(JSON.stringify(pk.jwk))), alg:pk.alg,
        signCount: parsed.signCount || 0, deviceType:r.authenticatorAttachment || 'unknown', createdAt:nowISO(),
      };
      db.passkeys.push(entry); audit(db,'registration_success',{account,credential:safePreview(credentialId),publicKeyPreview:safePreview(entry.publicKey)}); saveDB(db);
      return json(res,200,{ok:true,passkey:{id:entry.id,name:entry.name,publicKey:entry.publicKey,createdAt:entry.createdAt}});
    } catch (e) {
      audit(db,'registration_failure',{account,reason:e.message}); saveDB(db); return json(res,401,{error:'REGISTRATION_VERIFY_FAILED',message:e.message});
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/login/options') {
    const body = await readBody(req); const account = body.account || 'owner'; const user = getUser(db, account); const keys = getPasskeys(db,account);
    if (!user) return json(res,404,{error:'USER_NOT_FOUND'}); if (!keys.length) return json(res,400,{error:'NO_PASSKEY',message:'등록된 패스키가 없습니다.'});
    const c = createChallenge(db,'login',account);
    const options = { challenge:c.challenge, timeout:60000, rpId:RP_ID, userVerification:'required', allowCredentials:keys.map(p => ({type:'public-key',id:p.id,transports:p.transports || []})) };
    audit(db,'login_options',{account,challengePreview:safePreview(c.challenge)}); saveDB(db);
    return json(res,200,{challengeId:c.id,challengePreview:safePreview(c.challenge),options});
  }

  if (req.method === 'POST' && url.pathname === '/api/login/verify') {
    const body = await readBody(req); const account = body.account || 'owner';
    const c = consumeChallenge(db,body.challengeId,'login',account);
    if (!c) { saveDB(db); return json(res,401,{error:'CHALLENGE_MISSING_OR_USED'}); }
    try {
      const r = body.response || {}; const cr = r.response || {}; const credentialId = String(r.id || r.rawId || '');
      const passkey = db.passkeys.find(p => p.id === credentialId && p.userId === account);
      if (!passkey) throw new Error('credential not registered for this account');
      const { raw: clientRaw } = parseClientData(cr.clientDataJSON,'webauthn.get',c.challenge);
      const authData = fromB64url(cr.authenticatorData); const parsed = verifyRpAndFlags(authData); const sig = fromB64url(cr.signature);
      if (!verifyAuthSignature(passkey,authData,clientRaw,sig)) throw new Error('signature verification failed');
      if (parsed.signCount > passkey.signCount) passkey.signCount = parsed.signCount;
      const user = getUser(db,account); setSession(res,db,user); audit(db,'login_success',{account,credential:safePreview(credentialId)}); saveDB(db);
      return json(res,200,{ok:true,user:{id:user.id,label:user.label}});
    } catch (e) {
      audit(db,'login_failure',{account,reason:e.message}); saveDB(db); return json(res,401,{error:'LOGIN_VERIFY_FAILED',message:e.message});
    }
  }

  if (req.method === 'POST' && url.pathname === '/api/logout') {
    clearSession(req,res,db); audit(db,'logout',{}); saveDB(db); return json(res,200,{ok:true});
  }

  if (req.method === 'GET' && url.pathname === '/api/private') {
    if (!auth) return json(res,401,{error:'AUTH_REQUIRED'});
    return json(res,200,{user:{id:auth.user.id,label:auth.user.label},items:auth.user.privateItems,note:'이 자료는 패스키 인증 뒤 서버가 내려준 가상 데이터입니다.'});
  }

  const cross = url.pathname.match(/^\/api\/private\/users\/([^/]+)$/);
  if (req.method === 'GET' && cross) {
    if (!auth) return json(res,401,{error:'AUTH_REQUIRED'});
    const requested = decodeURIComponent(cross[1]); const other = getUser(db,requested);
    const count = other ? other.privateItems.length : 0;
    if (requested !== auth.user.id) { audit(db,'cross_account_block',{from:auth.user.id,to:requested,countBefore:count,countAfter:count}); saveDB(db); return json(res,403,{error:'CROSS_ACCOUNT_FORBIDDEN',countBefore:count,countAfter:count}); }
    return json(res,200,{user:{id:auth.user.id,label:auth.user.label},items:auth.user.privateItems});
  }

  if (req.method === 'GET' && url.pathname === '/api/passkeys') {
    if (!auth) return json(res,401,{error:'AUTH_REQUIRED'});
    return json(res,200,{passkeys:getPasskeys(db,auth.user.id).map(p => ({id:p.id,name:p.name,storageType:p.storageType,transports:p.transports,publicKey:p.publicKey,deviceType:p.deviceType,createdAt:p.createdAt}))});
  }

  const del = url.pathname.match(/^\/api\/passkeys\/([^/]+)$/);
  if (req.method === 'DELETE' && del) {
    if (!auth) return json(res,401,{error:'AUTH_REQUIRED'});
    const id = decodeURIComponent(del[1]); const mine = getPasskeys(db,auth.user.id); const p = mine.find(x => x.id === id);
    if (!p) return json(res,404,{error:'PASSKEY_NOT_FOUND'});
    if (mine.length <= 1) return json(res,409,{error:'LAST_PASSKEY_BLOCKED',message:'마지막 패스키는 삭제할 수 없습니다. 다른 패스키를 먼저 등록하세요.'});
    db.passkeys = db.passkeys.filter(x => x.id !== id); audit(db,'passkey_deleted',{account:auth.user.id,credential:safePreview(id)}); saveDB(db);
    return json(res,200,{ok:true,remaining:getPasskeys(db,auth.user.id).length});
  }

  if (req.method === 'GET' && url.pathname === '/api/evidence/audit') {
    if (!auth) return json(res,401,{error:'AUTH_REQUIRED'});
    const entries = db.audit.slice(-80).map(x => ({...x}));
    return json(res,200,{entries,note:'세션 토큰과 challenge 원문은 이 기록에 포함하지 않습니다.'});
  }

  if (req.method === 'GET' && url.pathname === '/api/evidence/public-source-check') {
    const html = fs.readFileSync(path.join(PUBLIC_DIR,'index.html'),'utf8');
    const leaks = db.users.flatMap(u => u.privateItems).filter(i => html.includes(i.title) || html.includes(i.body));
    return json(res,200,{ok:leaks.length===0,leakCount:leaks.length});
  }

  return json(res,404,{error:'API_NOT_FOUND'});
}

const MIME = { '.html':'text/html; charset=utf-8', '.js':'application/javascript; charset=utf-8', '.css':'text/css; charset=utf-8', '.json':'application/json; charset=utf-8', '.png':'image/png', '.jpg':'image/jpeg', '.jpeg':'image/jpeg', '.svg':'image/svg+xml', '.ico':'image/x-icon' };
function serveStatic(res, pathname) {
  let rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.replace(/^\//,''));
  if (rel.includes('..')) return text(res,403,'Forbidden');
  const file = path.join(PUBLIC_DIR,rel);
  if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return false;
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Cache-Control':'no-cache', 'X-Content-Type-Options':'nosniff', 'Referrer-Policy':'same-origin', 'Permissions-Policy':'publickey-credentials-create=(self), publickey-credentials-get=(self)' });
  fs.createReadStream(file).pipe(res); return true;
}

const server = http.createServer(async (req,res) => {
  const url = new URL(req.url, ORIGIN);
  try {
    const db = loadDB(); cleanup(db);
    if (url.pathname.startsWith('/api/')) return await handleApi(req,res,url,db);
    if (req.method !== 'GET' && req.method !== 'HEAD') return text(res,405,'Method Not Allowed');
    if (serveStatic(res,url.pathname) !== false) return;
    return text(res,404,'Not Found');
  } catch (e) {
    console.error(e); if (!res.headersSent) return json(res,500,{error:'SERVER_ERROR',message:e.message}); res.end();
  }
});

server.listen(PORT,HOST,() => {
  console.log(`Yerim Passkey Portfolio running on ${HOST}:${PORT}`);
  console.log(`RP_ID=${RP_ID} ORIGIN=${ORIGIN}`);
});
