'use strict';

// Parcours complet en local : administration, dépôt par blocs, téléchargement, refus et attaques simples.

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

const PASSWORD = 'correct horse battery staple';

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function startApp(dataDir, port, masterKey, passwordHash) {
  const config = loadConfig({
    MASTER_KEY: masterKey,
    ADMIN_PASSWORD_HASH: passwordHash,
    PUBLIC_URL: `http://127.0.0.1:${port}`,
    DATA_DIR: dataDir,
    INSECURE_COOKIES: '1',
    MIN_FREE_BYTES: '0',
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

test('parcours complet du portail', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const port = await freePort();
  const masterKey = crypto.randomBytes(32).toString('base64url');
  const passwordHash = hashPassword(PASSWORD);
  let app = await startApp(dataDir, port, masterKey, passwordHash);
  const base = `http://127.0.0.1:${port}`;
  t.after(async () => {
    await stop(app);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  const get = (url, headers = {}) => fetch(base + url, { headers, redirect: 'manual' });
  const post = (url, body, headers = {}) =>
    fetch(base + url, {
      method: 'POST',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      redirect: 'manual',
    });

  // Pages publiques et en-têtes de sécurité.
  let res = await get('/');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-security-policy'), /default-src 'none'/);
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(res.headers.get('referrer-policy'), 'same-origin');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.match(res.headers.get('strict-transport-security'), /max-age=31536000/);
  for (const page of ['/securite', '/confidentialite', '/mentions-legales']) {
    assert.equal((await get(page)).status, 200, page);
  }
  assert.match(await (await get('/mentions-legales')).text(), /Z3071357B/);

  // Fichiers statiques : seulement ceux chargés au démarrage.
  assert.equal((await get('/assets/app.css')).status, 200);
  assert.equal((await get('/assets/../server.js')).status, 404);
  assert.equal((await get('/assets/%2e%2e/server.js')).status, 404);
  assert.equal((await get('/assets/..%2fserver.js')).status, 404);
  assert.equal((await get('/assets/fonts/OFL-figtree.txt')).status, 404);

  // Administration : connexion.
  res = await get('/admin');
  assert.equal(res.status, 303);
  assert.equal(res.headers.get('location'), '/admin/login');
  res = await post('/admin/login', 'password=mauvais');
  assert.equal(res.status, 401);
  res = await post('/admin/login', `password=${encodeURIComponent(PASSWORD)}`);
  assert.equal(res.status, 303);
  const setCookie = res.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  const cookie = setCookie.split(';')[0];

  res = await get('/admin', { cookie });
  assert.equal(res.status, 200);
  let page = await res.text();
  const csrf = /name="csrf" value="([^"]+)"/.exec(page)[1];

  // Formulaire sans jeton CSRF ou venant d'un autre site : refusé.
  assert.equal((await post('/admin/boxes', 'name=Pirate', { cookie })).status, 403);
  assert.equal((await post('/admin/boxes', `name=Pirate&csrf=${csrf}`, { cookie, origin: 'https://evil.example' })).status, 403);

  res = await post('/admin/boxes', `name=${encodeURIComponent('LabelVie <script>')}&csrf=${csrf}`, { cookie });
  assert.equal(res.status, 303);
  page = await (await get('/admin', { cookie })).text();
  assert.ok(page.includes('LabelVie &lt;script&gt;'), 'nom échappé');
  assert.ok(!page.includes('LabelVie <script>'));
  const token = new RegExp(`${base}/d/([A-Za-z0-9_-]{43})`).exec(page)[1];

  // Page de dépôt.
  res = await get(`/d/${token}`);
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Espace réservé à <strong>LabelVie &lt;script&gt;<\/strong>/);
  assert.equal((await get('/d/inexistant')).status, 404);
  assert.equal((await get(`/d/${'A'.repeat(43)}`)).status, 404);

  // Dépôt d'un fichier de trois blocs.
  const api = `${base}/api/d/${token}/uploads`;
  const content = crypto.randomBytes(2 * CHUNK_SIZE + 12345);
  const json = (method, url, body) =>
    fetch(url, { method, body: body && JSON.stringify(body), headers: body ? { 'content-type': 'application/json' } : {} });

  res = await json('POST', api, { name: 'C:\\Users\\zak\\CA lessive 2025.xlsx', size: content.length, uploaderName: 'Zakariae', message: 'Voici les ventes.' });
  assert.equal(res.status, 201);
  const start = await res.json();
  assert.equal(start.chunks, 3);
  assert.equal(start.chunkSize, CHUNK_SIZE);

  const putChunk = (index, body) => fetch(`${api}/${start.uploadId}/${index}`, { method: 'PUT', body });
  res = await putChunk(1, content.subarray(CHUNK_SIZE, 2 * CHUNK_SIZE));
  assert.equal(res.status, 409);
  assert.equal((await res.json()).next, 0);
  res = await putChunk(0, content.subarray(0, 100));
  assert.equal(res.status, 400);
  for (let index = 0; index < 3; index += 1) {
    res = await putChunk(index, content.subarray(index * CHUNK_SIZE, Math.min((index + 1) * CHUNK_SIZE, content.length)));
    assert.equal(res.status, 200);
    assert.equal((await res.json()).next, index + 1);
  }
  res = await putChunk(1, content.subarray(CHUNK_SIZE, 2 * CHUNK_SIZE));
  assert.equal(res.status, 409, 'bloc renvoyé deux fois');
  res = await json('POST', `${api}/${start.uploadId}/complete`);
  assert.equal(res.status, 200);
  const receipt = await res.json();
  assert.equal(receipt.name, 'CA lessive 2025.xlsx');
  assert.equal(receipt.size, content.length);
  assert.equal(receipt.sha256, crypto.createHash('sha256').update(content).digest('hex'));

  // Rien en clair sur le disque.
  const filesDir = path.join(dataDir, 'files');
  const stored = fs.readdirSync(filesDir);
  assert.equal(stored.filter((name) => name.endsWith('.bin')).length, 1);
  const bin = fs.readFileSync(path.join(filesDir, stored.find((name) => name.endsWith('.bin'))));
  assert.equal(bin.indexOf(content.subarray(0, 64)), -1);
  const everything = Buffer.concat(stored.map((name) => fs.readFileSync(path.join(filesDir, name))));
  assert.equal(everything.indexOf('lessive'), -1, 'nom de fichier chiffré');
  assert.equal(everything.indexOf('Zakariae'), -1, 'déposant chiffré');
  assert.equal(fs.readFileSync(path.join(dataDir, 'boxes.json'), 'utf8').includes('LabelVie'), false, 'nom du client chiffré');
  assert.equal(fs.readFileSync(path.join(dataDir, 'boxes.json'), 'utf8').includes(token), false, 'lien chiffré');

  // Refus.
  res = await json('POST', api, { name: 'outil.exe', size: 10 });
  assert.equal(res.status, 415);
  res = await json('POST', api, { name: 'vide.pdf', size: 0 });
  assert.equal(res.status, 400);
  res = await json('POST', api, { name: 'enorme.zip', size: 5 * 1024 ** 3 });
  assert.equal(res.status, 413);
  res = await fetch(api, { method: 'POST', body: '{', headers: { 'content-type': 'application/json' } });
  assert.equal(res.status, 400);
  res = await fetch(api, { method: 'POST', body: '{}', headers: { 'content-type': 'application/json', origin: 'https://evil.example' } });
  assert.equal(res.status, 403);

  // Téléchargement par l'administrateur, à l'identique.
  page = await (await get('/admin', { cookie })).text();
  const fileId = /\/admin\/files\/([a-f0-9]{32})"/.exec(page)[1];
  assert.ok(page.includes('Déposé par Zakariae'));
  res = await get(`/admin/files/${fileId}`, { cookie });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition'), /^attachment; filename="CA lessive 2025.xlsx"/);
  assert.equal(res.headers.get('content-type'), 'application/octet-stream');
  assert.deepEqual(Buffer.from(await res.arrayBuffer()), content);
  assert.equal((await get(`/admin/files/${fileId}`)).status, 303, 'téléchargement sans session : connexion demandée');

  // Le lien de dépôt ne donne jamais accès aux fichiers.
  assert.equal((await fetch(`${api}/${fileId}`)).status, 405);
  assert.equal((await get(`/d/${token}/${fileId}`)).status, 404);

  // Contenu altéré sur le disque : le téléchargement s'interrompt au lieu de livrer un faux fichier.
  const binPath = path.join(filesDir, `${fileId}.bin`);
  const original = fs.readFileSync(binPath);
  const altered = Buffer.from(original);
  altered[CHUNK_SIZE + 500] ^= 0xff;
  fs.writeFileSync(binPath, altered);
  res = await get(`/admin/files/${fileId}`, { cookie });
  await assert.rejects(res.arrayBuffer());
  fs.writeFileSync(binPath, original);

  // Redémarrage : espaces et fichiers retrouvés.
  await stop(app);
  app = await startApp(dataDir, port, masterKey, passwordHash);
  assert.equal(app.store.boxes[0].name, 'LabelVie <script>');
  assert.equal(app.store.files.size, 1);
  res = await post('/admin/login', `password=${encodeURIComponent(PASSWORD)}`);
  const cookie2 = res.headers.get('set-cookie').split(';')[0];
  page = await (await get('/admin', { cookie: cookie2 })).text();
  const csrf2 = /name="csrf" value="([^"]+)"/.exec(page)[1];
  const boxId = /\/admin\/boxes\/([a-f0-9]{16})\/toggle/.exec(page)[1];

  // Lien désactivé, puis remplacé.
  res = await post(`/admin/boxes/${boxId}/toggle`, `csrf=${csrf2}`, { cookie: cookie2 });
  assert.equal(res.status, 303);
  assert.equal((await get(`/d/${token}`)).status, 404);
  assert.equal((await json('POST', api, { name: 'a.pdf', size: 3 })).status, 404);
  await post(`/admin/boxes/${boxId}/toggle`, `csrf=${csrf2}`, { cookie: cookie2 });
  assert.equal((await get(`/d/${token}`)).status, 200);
  await post(`/admin/boxes/${boxId}/rotate`, `csrf=${csrf2}`, { cookie: cookie2 });
  assert.equal((await get(`/d/${token}`)).status, 404);
  page = await (await get('/admin', { cookie: cookie2 })).text();
  const newToken = new RegExp(`${base}/d/([A-Za-z0-9_-]{43})`).exec(page)[1];
  assert.notEqual(newToken, token);
  assert.equal((await get(`/d/${newToken}`)).status, 200);

  // Suppression, puis déconnexion.
  res = await post(`/admin/files/${fileId}/delete`, `csrf=${csrf2}`, { cookie: cookie2 });
  assert.equal(res.status, 303);
  assert.equal(app.store.files.size, 0);
  assert.equal(fs.readdirSync(filesDir).length, 0);
  res = await post('/admin/logout', `csrf=${csrf2}`, { cookie: cookie2 });
  assert.equal(res.status, 303);
  assert.equal((await get('/admin', { cookie: cookie2 })).status, 303);

  // Trop d'essais de mot de passe : bloqué.
  let last;
  for (let i = 0; i < 9; i += 1) last = await post('/admin/login', 'password=nope');
  assert.equal(last.status, 429);
});

test('suppression automatique après la durée de conservation', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const port = await freePort();
  const app = await startApp(dataDir, port, crypto.randomBytes(32).toString('base64url'), hashPassword(PASSWORD));
  t.after(async () => {
    await stop(app);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const box = await app.store.createBox('Test');
  const session = await app.uploads.start(box, { name: 'a.csv', size: 5 });
  await app.uploads.receiveChunk(box, session.uploadId, 0, async () => Buffer.from('a;b;c'));
  await app.uploads.finish(box, session.uploadId);
  assert.equal(app.store.files.size, 1);
  assert.equal(await app.store.purgeOlderThan(new Date(Date.now() - 86400e3)), 0);
  assert.equal(await app.store.purgeOlderThan(new Date(Date.now() + 1000)), 1);
  assert.equal(app.store.files.size, 0);
});

test('limites tenues sous requêtes parallèles, accusé rejouable, noms mal formés', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depot-test-'));
  const port = await freePort();
  const app = await startApp(dataDir, port, crypto.randomBytes(32).toString('base64url'), hashPassword(PASSWORD));
  const base = `http://127.0.0.1:${port}`;
  t.after(async () => {
    await stop(app);
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  const box = await app.store.createBox('Test');
  const token = /\/d\/(.+)$/.exec(app.store.boxLink(box, base))[1];
  const api = `${base}/api/d/${token}/uploads`;
  const start = (body) =>
    fetch(api, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' } });

  // 20 démarrages simultanés : 6 au plus pour un même lien.
  const responses = await Promise.all(Array.from({ length: 20 }, (_, i) => start({ name: `f${i}.csv`, size: 10 })));
  const accepted = responses.filter((r) => r.status === 201);
  assert.equal(accepted.length, 6);
  assert.ok(responses.every((r) => r.status === 201 || r.status === 429));
  assert.equal(app.uploads.sessions.size, 6);

  // Abandon : la place est rendue.
  const first = await accepted[0].json();
  assert.equal((await fetch(`${api}/${first.uploadId}`, { method: 'DELETE' })).status, 204);
  assert.equal(app.uploads.sessions.size, 5);
  for (const r of accepted.slice(1)) {
    const { uploadId } = await r.json();
    await fetch(`${api}/${uploadId}`, { method: 'DELETE' });
  }
  assert.equal(app.uploads.sessions.size, 0);
  assert.equal(fs.readdirSync(path.join(dataDir, 'tmp')).length, 0);

  // Nom avec une demi-paire de substitution : nettoyé, téléchargeable.
  const res = await start({ name: 'rapport \ud83d.pdf', size: 3 });
  assert.equal(res.status, 201);
  const session = await res.json();
  assert.equal((await fetch(`${api}/${session.uploadId}/0`, { method: 'PUT', body: Buffer.from('abc') })).status, 200);
  const complete = () => fetch(`${api}/${session.uploadId}/complete`, { method: 'POST' });
  const receipt = await (await complete()).json();
  assert.equal(receipt.name, 'rapport �.pdf');
  // Réponse perdue puis rejouée : même accusé, pas de doublon.
  const again = await complete();
  assert.equal(again.status, 200);
  assert.deepEqual(await again.json(), receipt);
  assert.equal(app.store.files.size, 1);
  const meta = [...app.store.files.values()][0];
  assert.match(require('../lib/names').contentDisposition(meta.name), /filename\*=UTF-8''rapport%20%EF%BF%BD\.pdf/);
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
