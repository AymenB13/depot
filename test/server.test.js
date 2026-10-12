'use strict';

// Parcours complet en local : envoi public avec nom et preuve de travail, antivirus (faux clamd),
// administration, téléchargement, refus et attaques simples.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const { createApp } = require('../server');
const { loadConfig } = require('../lib/config');
const { hashPassword } = require('../lib/password');
const { CHUNK_SIZE } = require('../lib/crypto');
const { leadingZeroBits } = require('../lib/antispam');

const PASSWORD = 'correct horse battery staple';
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

// Faux clamd : protocole INSTREAM, « FOUND » si le contenu contient la chaîne de test EICAR.
function fakeClamd() {
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let content = Buffer.alloc(0);
    let started = false;
    socket.on('data', (data) => {
      buffer = Buffer.concat([buffer, data]);
      if (!started) {
        const end = buffer.indexOf(0);
        if (end < 0) return;
        buffer = buffer.subarray(end + 1);
        started = true;
      }
      while (buffer.length >= 4) {
        const length = buffer.readUInt32BE(0);
        if (length === 0) {
          const infected = content.includes(Buffer.from('EICAR-STANDARD-ANTIVIRUS-TEST-FILE'));
          socket.end(infected ? 'stream: Eicar-Test-Signature FOUND\0' : 'stream: OK\0');
          return;
        }
        if (buffer.length < 4 + length) return;
        content = Buffer.concat([content, buffer.subarray(4, 4 + length)]);
        buffer = buffer.subarray(4 + length);
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function startApp(dataDir, port, extra = {}) {
  const config = loadConfig({
    MASTER_KEY: extra.masterKey || crypto.randomBytes(32).toString('base64url'),
    ADMIN_PASSWORD_HASH: extra.passwordHash || hashPassword(PASSWORD),
    PUBLIC_URL: `http://127.0.0.1:${port}`,
    DATA_DIR: dataDir,
    INSECURE_COOKIES: '1',
    MIN_FREE_BYTES: '0',
    POW_BITS: '8',
    CLAMAV_HOST: '127.0.0.1',
    CLAMAV_PORT: String(extra.clamavPort || 1),
    ...extra.env,
  });
  const app = createApp(config, { logger: () => {} });
  await app.init();
  await new Promise((resolve) => app.server.listen(port, '127.0.0.1', resolve));
  return app;
}

function stop(app) {
  return new Promise((resolve) => {
    app.server.closeAllConnections();
    app.server.close(resolve);
  });
}

function solve(challenge, bits) {
  for (let nonce = 0; ; nonce += 1) {
    const digest = crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest();
    if (leadingZeroBits(digest) >= bits) return String(nonce);
  }
}

async function waitFor(check, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await check()) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}

function client(base) {
  const json = (method, url, body, headers = {}) =>
    fetch(base + url, {
      method,
      body: body === undefined ? undefined : JSON.stringify(body),
      headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
    });
  async function start(fields) {
    const { challenge, bits } = await (await fetch(`${base}/api/challenge`)).json();
    return json('POST', '/api/uploads', { challenge, nonce: solve(challenge, bits), uploader: 'Zakariae Mokssit', ...fields });
  }
  async function upload(name, content, fields = {}) {
    const res = await start({ name, size: content.length, ...fields });
    assert.equal(res.status, 201, await res.clone().text());
    const session = await res.json();
    for (let index = 0; index < session.chunks; index += 1) {
      const body = content.subarray(index * session.chunkSize, (index + 1) * session.chunkSize);
      const put = await fetch(`${base}/api/uploads/${session.uploadId}/${index}`, { method: 'PUT', body });
      assert.equal(put.status, 200);
    }
    const done = await json('POST', `/api/uploads/${session.uploadId}/complete`);
    assert.equal(done.status, 200);
    return { session, receipt: await done.json() };
  }
  return { json, start, upload };
}

test('parcours complet du portail', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const clamd = await fakeClamd();
  const port = await freePort();
  const masterKey = crypto.randomBytes(32).toString('base64url');
  const passwordHash = hashPassword(PASSWORD);
  let app = await startApp(dataDir, port, { masterKey, passwordHash, clamavPort: clamd.address().port });
  const base = `http://127.0.0.1:${port}`;
  t.after(async () => {
    await stop(app);
    clamd.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const { json, start, upload } = client(base);
  const get = (url, headers = {}) => fetch(base + url, { headers, redirect: 'manual' });
  const post = (url, body, headers = {}) =>
    fetch(base + url, {
      method: 'POST',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      redirect: 'manual',
    });

  // Page d'envoi publique et en-têtes de sécurité.
  let res = await get('/');
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Prénom et nom/);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
  assert.equal(res.headers.get('referrer-policy'), 'same-origin');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  for (const page of ['/securite', '/confidentialite', '/mentions-legales']) assert.equal((await get(page)).status, 200, page);
  const legal = await (await get('/mentions-legales')).text();
  assert.match(legal, /Z3071357B/);
  assert.match(legal, /Av\. del Regne de València, 87, #70, 46006 València/);
  assert.equal((await get('/assets/../server.js')).status, 404);
  assert.equal((await get('/assets/%2e%2e/server.js')).status, 404);

  // Refus : sans nom, champ piège rempli, défi absent ou rejoué, format, taille, autre site.
  const { challenge, bits } = await (await fetch(`${base}/api/challenge`)).json();
  const nonce = solve(challenge, bits);
  res = await json('POST', '/api/uploads', { challenge, nonce, name: 'a.pdf', size: 3, uploader: '' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /prénom et votre nom/);
  res = await json('POST', '/api/uploads', { challenge, nonce, name: 'a.pdf', size: 3, uploader: 'Robot Robot', website: 'http://spam' });
  assert.equal(res.status, 400);
  res = await json('POST', '/api/uploads', { name: 'a.pdf', size: 3, uploader: 'Sans Défi' });
  assert.equal(res.status, 403);
  res = await json('POST', '/api/uploads', { challenge, nonce, name: 'a.pdf', size: 3, uploader: 'Zakariae Mokssit' });
  assert.equal(res.status, 201, 'premier usage du défi');
  await json('DELETE', `/api/uploads/${(await res.json()).uploadId}`);
  res = await json('POST', '/api/uploads', { challenge, nonce, name: 'b.pdf', size: 3, uploader: 'Zakariae Mokssit' });
  assert.equal(res.status, 403, 'défi rejoué');
  assert.equal((await start({ name: 'outil.exe', size: 10 })).status, 415);
  assert.equal((await start({ name: 'vide.pdf', size: 0 })).status, 400);
  assert.equal((await start({ name: 'enorme.zip', size: 3 * 1024 ** 3 })).status, 413);
  assert.equal((await json('POST', '/api/uploads', { name: 'x.pdf' }, { origin: 'https://evil.example' })).status, 403);

  // Envoi d'un fichier de trois blocs ; bloc hors ordre ou tronqué refusé ; « complete » rejouable.
  const content = crypto.randomBytes(2 * CHUNK_SIZE + 12345);
  res = await start({ name: 'C:\\Users\\zak\\CA lessive 2025.xlsx', size: content.length });
  const session = await res.json();
  assert.equal(session.chunks, 3);
  const putChunk = (index, body) => fetch(`${base}/api/uploads/${session.uploadId}/${index}`, { method: 'PUT', body });
  res = await putChunk(1, content.subarray(CHUNK_SIZE, 2 * CHUNK_SIZE));
  assert.equal(res.status, 409);
  assert.equal((await res.json()).next, 0);
  assert.equal((await putChunk(0, content.subarray(0, 100))).status, 400);
  for (let index = 0; index < 3; index += 1) {
    assert.equal((await putChunk(index, content.subarray(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE))).status, 200);
  }
  res = await json('POST', `/api/uploads/${session.uploadId}/complete`);
  const receipt = await res.json();
  assert.equal(receipt.name, 'CA lessive 2025.xlsx');
  res = await json('POST', `/api/uploads/${session.uploadId}/complete`);
  assert.deepEqual(await res.json(), receipt, 'même réponse, pas de doublon');

  // Fichier de test antivirus (EICAR) : bloqué.
  await upload('facture.pdf', Buffer.from(EICAR));
  const scanned = () => app.scansIdle() && [...app.store.files.values()].every((f) => f.scan && f.scan.status !== 'pending');
  assert.ok(await waitFor(scanned));

  // Rien en clair sur le disque.
  const filesDir = path.join(dataDir, 'files');
  const everything = Buffer.concat(fs.readdirSync(filesDir).map((name) => fs.readFileSync(path.join(filesDir, name))));
  assert.equal(everything.indexOf(content.subarray(0, 64)), -1);
  assert.equal(everything.indexOf('lessive'), -1, 'nom de fichier chiffré');
  assert.equal(everything.indexOf('Mokssit'), -1, 'nom du déposant chiffré');
  assert.equal(everything.indexOf('EICAR'), -1);

  // Administration.
  assert.equal((await get('/admin')).status, 303);
  assert.equal((await post('/admin/login', 'password=mauvais')).status, 401);
  res = await post('/admin/login', `password=${encodeURIComponent(PASSWORD)}`);
  assert.equal(res.status, 303);
  assert.match(res.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  const cookie = res.headers.get('set-cookie').split(';')[0];
  let page = await (await get('/admin', { cookie })).text();
  assert.match(page, /Zakariae Mokssit/);
  assert.match(page, /Virus : Eicar-Test-Signature/);
  assert.match(page, /Sain/);
  const files = [...app.store.files.values()];
  const good = files.find((f) => f.name === 'CA lessive 2025.xlsx');
  const bad = files.find((f) => f.name === 'facture.pdf');
  assert.equal(good.scan.status, 'clean');
  assert.equal(bad.scan.status, 'infected');

  res = await get(`/admin/files/${good.id}`, { cookie });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition'), /^attachment; filename="CA lessive 2025.xlsx"/);
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), content);
  assert.equal((await get(`/admin/files/${bad.id}`, { cookie })).status, 409, 'fichier infecté jamais servi');
  assert.equal((await get(`/admin/files/${good.id}`)).status, 303, 'sans session : connexion demandée');
  assert.equal((await post(`/admin/files/${bad.id}/delete`, 'csrf=faux', { cookie })).status, 403);

  // Contenu altéré sur le disque : le téléchargement s'interrompt.
  const binPath = path.join(filesDir, `${good.id}.bin`);
  const original = fs.readFileSync(binPath);
  const altered = Buffer.from(original);
  altered[CHUNK_SIZE + 500] ^= 0xff;
  fs.writeFileSync(binPath, altered);
  res = await get(`/admin/files/${good.id}`, { cookie });
  await assert.rejects(res.arrayBuffer());
  fs.writeFileSync(binPath, original);

  // Redémarrage : fichiers et verdicts retrouvés ; suppression ; déconnexion.
  await stop(app);
  app = await startApp(dataDir, port, { masterKey, passwordHash, clamavPort: clamd.address().port });
  assert.equal(app.store.files.get(good.id).scan.status, 'clean');
  res = await post('/admin/login', `password=${encodeURIComponent(PASSWORD)}`);
  const cookie2 = res.headers.get('set-cookie').split(';')[0];
  page = await (await get('/admin', { cookie: cookie2 })).text();
  const csrf2 = /name="csrf" value="([^"]+)"/.exec(page)[1];
  assert.equal((await post(`/admin/files/${bad.id}/delete`, `csrf=${csrf2}`, { cookie: cookie2 })).status, 303);
  assert.equal(app.store.files.has(bad.id), false);
  assert.equal((await post('/admin/logout', `csrf=${csrf2}`, { cookie: cookie2 })).status, 303);
  assert.equal((await get('/admin', { cookie: cookie2 })).status, 303);

  let last;
  for (let i = 0; i < 9; i += 1) last = await post('/admin/login', 'password=nope');
  assert.equal(last.status, 429);
});

test('antivirus indisponible : le fichier attend, rien ne sort', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const port = await freePort();
  const app = await startApp(dataDir, port, { clamavPort: await freePort() });
  t.after(async () => {
    await stop(app);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const { upload } = client(`http://127.0.0.1:${port}`);
  await upload('notes.txt', Buffer.from('bonjour'));
  assert.ok(await waitFor(() => app.scansIdle()));
  assert.equal([...app.store.files.values()][0].scan.status, 'pending');
});

test('limites tenues sous requêtes parallèles, volume quotidien, noms mal formés', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const port = await freePort();
  const app = await startApp(dataDir, port, { env: { DAILY_BYTES_PER_IP: '1000' } });
  const base = `http://127.0.0.1:${port}`;
  t.after(async () => {
    await stop(app);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const { json, start } = client(base);

  const responses = await Promise.all(Array.from({ length: 20 }, (_, i) => start({ name: `f${i}.csv`, size: 10 })));
  const accepted = responses.filter((r) => r.status === 201);
  assert.equal(accepted.length, 6, 'six envois simultanés au plus par adresse');
  assert.equal(app.uploads.sessions.size, 6);
  for (const r of accepted) {
    const { uploadId } = await r.json();
    assert.equal((await fetch(`${base}/api/uploads/${uploadId}`, { method: 'DELETE' })).status, 204);
  }
  assert.equal(app.uploads.sessions.size, 0);

  // 60 octets déjà comptés aujourd'hui pour cette adresse : 1000 de plus dépassent le plafond.
  assert.equal((await start({ name: 'gros.csv', size: 1000 })).status, 429);

  const ok = await start({ name: 'rapport \ud83d.pdf', size: 3 });
  assert.equal(ok.status, 201);
  const session = await ok.json();
  assert.equal((await fetch(`${base}/api/uploads/${session.uploadId}/0`, { method: 'PUT', body: Buffer.from('abc') })).status, 200);
  const receipt = await (await json('POST', `/api/uploads/${session.uploadId}/complete`)).json();
  assert.equal(receipt.name, 'rapport \ufffd.pdf');
});

test('adresse du client : dernière entrée de X-Forwarded-For, en-têtes anormaux ignorés', () => {
  const { clientIp } = require('../lib/http');
  const req = (xff, remote = '10.0.0.5') => ({ headers: xff === undefined ? {} : { 'x-forwarded-for': xff }, socket: { remoteAddress: remote } });
  assert.equal(clientIp(req('1.1.1.1, 203.0.113.9')), '203.0.113.9');
  assert.equal(clientIp(req('pas-une-ip')), '10.0.0.5');
  assert.equal(clientIp(req(`${'1.2.3.4,'.repeat(200)}5.6.7.8`)), '10.0.0.5');
  assert.equal(clientIp(req('2001:db8:aaaa:bbbb:1:2:3:4')), '2001:db8:aaaa:bbbb::/64');
  assert.equal(clientIp(req(undefined, '::ffff:192.0.2.1')), '192.0.2.1');
});

test('suppression automatique après la durée de conservation', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const port = await freePort();
  const app = await startApp(dataDir, port);
  t.after(async () => {
    await stop(app);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const { upload } = client(`http://127.0.0.1:${port}`);
  await upload('a.csv', Buffer.from('a;b;c'));
  assert.equal(app.store.files.size, 1);
  assert.equal(await app.store.purgeOlderThan(new Date(Date.now() - 86400e3)), 0);
  assert.equal(await app.store.purgeOlderThan(new Date(Date.now() + 1000)), 1);
  assert.equal(app.store.files.size, 0);
});
