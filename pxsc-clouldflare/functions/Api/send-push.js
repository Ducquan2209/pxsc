const enc = new TextEncoder();

function b64uToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

function bytesToB64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8);
  return new Uint8Array(bits);
}

// Header Authorization kiểu VAPID (ES256)
async function vapidAuth(endpoint, env) {
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const aud = new URL(endpoint).origin;
  const header = bytesToB64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = bytesToB64u(enc.encode(JSON.stringify({
    aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT
  })));
  const data = header + '.' + payload;
  const key = await crypto.subtle.importKey('jwk',
    { kty: 'EC', crv: 'P-256', d: jwk.d, x: jwk.x, y: jwk.y },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(data)));
  const pub = bytesToB64u(concat(new Uint8Array([4]), b64uToBytes(jwk.x), b64uToBytes(jwk.y)));
  return 'vapid t=' + data + '.' + bytesToB64u(sig) + ', k=' + pub;
}

// Mã hóa nội dung theo chuẩn aes128gcm (RFC 8291)
async function mahoaNoiDung(sub, text) {
  const uaPublic = b64uToBytes(sub.keys.p256dh);
  const auth = b64uToBytes(sub.keys.auth);
  const asKP = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', asKP.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asKP.privateKey, 256));
  const prk = await hkdf(auth, secret, concat(enc.encode('WebPush: info\0'), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, prk, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, prk, enc.encode('Content-Encoding: nonce\0'), 12);
  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const padded = concat(enc.encode(text), new Uint8Array([2]));
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, padded));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}

export async function onRequestPost({ request, env }) {
  if (request.headers.get('x-push-secret') !== env.PUSH_SECRET) {
    return new Response('Unauthorized', { status: 401 });
  }
  let data;
  try { data = await request.json(); }
  catch (e) { return new Response('Bad JSON', { status: 400 }); }
  if (!data.subscription || !data.subscription.endpoint || !data.subscription.keys) {
    return new Response('Thiếu subscription', { status: 400 });
  }
  try {
    const sub = data.subscription;
    const noiDung = JSON.stringify({ title: data.title, body: data.body, url: data.url || '/' });
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: {
        'TTL': '86400',
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        'Authorization': await vapidAuth(sub.endpoint, env)
      },
      body: await mahoaNoiDung(sub, noiDung)
    });
    const thongTin = res.status < 300 ? '' : (await res.text()).slice(0, 200);
    return Response.json({
      ok: res.status < 300,
      pushStatus: res.status,
      expired: res.status === 404 || res.status === 410,
      detail: thongTin
    });
  } catch (e) {
    return new Response(String((e && e.message) || e), { status: 500 });
  }
}