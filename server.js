'use strict';

// Portail de dépôt de documents : files.aymenbenali.com
// Aucune dépendance externe : modules intégrés de Node.js uniquement.

const http = require('node:http');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const { loadConfig } = require('./lib/config');
const { deriveKey, decryptChunk, TAG_LENGTH } = require('./lib/crypto');
const { Store } = require('./lib/store');
const { Uploads, UploadError } = require('./lib/uploads');
const { verifyPassword } = require('./lib/password');
const { Sessions, RateLimiter, safeEqual } = require('./lib/guards');
const { cleanText, contentDisposition } = require('./lib/names');
const {
  SECURITY_HEADERS,
  HttpError,
  send,
  sendHtml,
  sendJson,
  redirect,
  readBody,
  readExact,
  parseCookies,
  clientIp,
} = require('./lib/http');
const views = require('./lib/views');

function log(event, data = {}) {
  process.stdout.write(`${JSON.stringify({ t: new Date().toISOString(), ev: event, ...data })}\n`);
}

const TYPES = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
};

// Fichiers statiques chargés en mémoire au démarrage : aucune lecture de chemin venu d'une requête.
function loadAssets(dir) {
  const files = new Map();
  const walk = (sub) => {
    for (const entry of fs.readdirSync(path.join(dir, sub), { withFileTypes: true })) {
      const rel = sub ? `${sub}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(rel);
      else if (TYPES[path.extname(entry.name)]) {
        const body = fs.readFileSync(path.join(dir, rel));
        const version = crypto.createHash('sha256').update(body).digest('hex').slice(0, 10);
        files.set(rel, { body, version, type: TYPES[path.extname(entry.name)] });
      }
    }
  };
  walk('');
  return {
    get: (name) => files.get(name),
    url: (name) => `/assets/${name}?v=${files.get(name).version}`,
  };
}

const NOTICES = {
  created: 'Lien créé. Copiez-le et envoyez-le à votre client.',
  rotated: 'Nouveau lien créé. L\'ancien ne fonctionne plus.',
  on: 'Lien réactivé.',
  off: 'Lien désactivé.',
  deleted: 'Fichier supprimé.',
};

function waitDrain(res) {
  return new Promise((resolve) => {
    const done = () => {
      res.off('drain', done);
      res.off('close', done);
      resolve();
    };
    res.on('drain', done);
    res.on('close', done);
  });
}

function createApp(config, { logger = log } = {}) {
  const metaKey = deriveKey(config.masterKey, 'depot/meta/v1');
  const store = new Store({ dataDir: config.dataDir, metaKey, log: logger });
  const uploads = new Uploads({ store, config, log: logger });
  const sessions = new Sessions();
  // Pas de limite globale sur la connexion : elle permettrait à n'importe qui de bloquer l'accès.
  // Le mot de passe généré (144 bits) et scrypt rendent l'essai en ligne inutile ; la limite par
  // adresse et le plafond de vérifications simultanées protègent le serveur.
  const limits = {
    login: new RateLimiter(8, 15 * 60e3),
    badToken: new RateLimiter(30, 10 * 60e3),
    api: new RateLimiter(20000, 10 * 60e3),
  };
  let passwordChecks = 0;
  const assets = loadAssets(path.join(__dirname, 'public'));
  const cookieName = config.secureCookies ? '__Host-depot' : 'depot';

  function cookie(value, maxAge) {
    const secure = config.secureCookies ? '; Secure' : '';
    return `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure}`;
  }

  function sameOrigin(req) {
    const origin = req.headers.origin;
    return !origin || origin === config.publicOrigin;
  }

  function adminSession(req) {
    return sessions.get(parseCookies(req.headers.cookie)[cookieName]);
  }

  async function adminForm(req, session) {
    if (!sameOrigin(req)) throw new HttpError(403, 'Requête refusée.');
    const form = new URLSearchParams((await readBody(req, 8192)).toString('utf8'));
    if (!safeEqual(form.get('csrf') || '', session.csrf)) throw new HttpError(403, 'Session expirée. Rechargez la page.');
    return form;
  }

  function notify(box, meta) {
    if (!config.notifyUrl) return;
    fetch(config.notifyUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        event: 'depot',
        client: box.name,
        file: meta.name,
        size: meta.size,
        at: meta.uploadedAt,
        admin: `${config.publicOrigin}/admin`,
      }),
      signal: AbortSignal.timeout(5000),
    }).catch((error) => logger('notification_echec', { error: error.message }));
  }

  function serveAsset(req, res, name, version) {
    const asset = assets.get(name);
    if (!asset) return sendHtml(res, 404, views.notFound(assets));
    const cache = version === asset.version ? 'public, max-age=31536000, immutable' : 'public, max-age=300';
    return send(res, 200, asset.body, { 'Content-Type': asset.type, 'Cache-Control': cache });
  }

  async function download(res, meta) {
    const handle = await fsp.open(store.dataPath(meta.id), 'r');
    const key = Buffer.from(meta.key, 'base64');
    const prefix = Buffer.from(meta.prefix, 'base64');
    const chunkSize = meta.chunkSize;
    const count = Math.max(1, Math.ceil(meta.size / chunkSize));
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': 'application/octet-stream',
      'Content-Length': meta.size,
      'Content-Disposition': contentDisposition(meta.name),
      'Cache-Control': 'no-store',
    });
    try {
      for (let index = 0; index < count && !res.destroyed; index += 1) {
        const length = index < count - 1 ? chunkSize : meta.size - chunkSize * (count - 1);
        const buffer = Buffer.alloc(length + TAG_LENGTH);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, index * (chunkSize + TAG_LENGTH));
        if (bytesRead !== buffer.length) throw new Error('fichier tronqué');
        const plain = decryptChunk(key, prefix, index, index === count - 1, buffer);
        if (!res.write(plain)) await waitDrain(res);
      }
      res.end();
    } catch (error) {
      logger('telechargement_echec', { file: meta.id, error: error.message });
      res.destroy();
    } finally {
      await handle.close();
    }
  }

  async function depositApi(req, res, box, uploadId, step) {
    if (!sameOrigin(req)) throw new HttpError(403, 'Requête refusée.');
    if (!uploadId) {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      if (!/^application\/json\b/.test(req.headers['content-type'] || '')) throw new HttpError(415, 'JSON attendu.');
      let input;
      try {
        input = JSON.parse((await readBody(req, 16384)).toString('utf8'));
      } catch (error) {
        if (error instanceof HttpError) throw error;
        throw new HttpError(400, 'Requête illisible.');
      }
      return sendJson(res, 201, await uploads.start(box, input || {}));
    }
    if (step === undefined) {
      if (req.method !== 'DELETE') throw new HttpError(405, 'Méthode non autorisée.');
      await uploads.abort(box, uploadId);
      return send(res, 204, '');
    }
    if (step === 'complete') {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      const meta = await uploads.finish(box, uploadId);
      logger('depot_recu', { box: box.id, size: meta.size });
      notify(box, meta);
      return sendJson(res, 200, { name: meta.name, size: meta.size, sha256: meta.sha256, receivedAt: meta.uploadedAt });
    }
    if (req.method !== 'PUT') throw new HttpError(405, 'Méthode non autorisée.');
    const index = Number(step);
    const result = await uploads.receiveChunk(box, uploadId, index, (expected) => readExact(req, expected));
    return sendJson(res, 200, result);
  }

  async function adminRoute(req, res, pathname, url) {
    const ip = clientIp(req);

    if (pathname === '/admin/login') {
      if (req.method === 'GET' || req.method === 'HEAD') {
        if (adminSession(req)) return redirect(res, '/admin');
        const status = url.searchParams.get('sortie') === '1' ? 'Vous êtes déconnecté.' : '';
        return sendHtml(res, 200, views.login(assets, { status }));
      }
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      if (!sameOrigin(req)) throw new HttpError(403, 'Requête refusée.');
      if (!limits.login.hit(ip)) {
        logger('connexion_limitee');
        return sendHtml(res, 429, views.login(assets, { error: 'Trop d\'essais. Réessayez dans 15 minutes.' }));
      }
      const form = new URLSearchParams((await readBody(req, 4096)).toString('utf8'));
      if (passwordChecks >= 4) {
        return sendHtml(res, 503, views.login(assets, { error: 'Serveur occupé. Réessayez dans un instant.' }));
      }
      passwordChecks += 1;
      let valid = false;
      try {
        valid = await verifyPassword(form.get('password') || '', config.adminPasswordHash);
      } finally {
        passwordChecks -= 1;
      }
      if (valid) {
        const session = sessions.create();
        logger('connexion_admin');
        return redirect(res, '/admin', { 'Set-Cookie': cookie(session.id, 12 * 3600) });
      }
      logger('connexion_refusee');
      return sendHtml(res, 401, views.login(assets, { error: 'Mot de passe incorrect.' }));
    }

    const session = adminSession(req);
    if (!session) {
      if (req.method === 'GET' || req.method === 'HEAD') return redirect(res, '/admin/login');
      throw new HttpError(401, 'Connectez-vous à nouveau.');
    }

    if (pathname === '/admin') {
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Méthode non autorisée.');
      const boxes = store.boxes.map((box) => ({
        box,
        link: store.boxLink(box, config.publicOrigin),
        files: store.filesOf(box.id),
        usage: store.usage(box.id),
      }));
      return sendHtml(
        res,
        200,
        views.dashboard(assets, {
          boxes,
          csrf: session.csrf,
          notice: Object.hasOwn(NOTICES, url.searchParams.get('ok') || '') ? NOTICES[url.searchParams.get('ok')] : '',
          freeBytes: await store.freeBytes(),
          retentionDays: config.retentionDays,
        }),
      );
    }

    if (pathname === '/admin/logout') {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      await adminForm(req, session);
      sessions.destroy(parseCookies(req.headers.cookie)[cookieName]);
      return redirect(res, '/admin/login?sortie=1', { 'Set-Cookie': cookie('', 0) });
    }

    if (pathname === '/admin/boxes') {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      const form = await adminForm(req, session);
      const name = cleanText(form.get('name') || '', 80).replace(/\s+/g, ' ');
      if (!name) return redirect(res, '/admin');
      const box = await store.createBox(name);
      logger('espace_cree', { box: box.id });
      return redirect(res, `/admin?ok=created#box-${box.id}`);
    }

    let match = /^\/admin\/boxes\/([a-f0-9]{16})\/(rotate|toggle)$/.exec(pathname);
    if (match) {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      await adminForm(req, session);
      const box = store.boxById(match[1]);
      if (!box) throw new HttpError(404, 'Espace introuvable.');
      if (match[2] === 'rotate') {
        await store.rotateBox(box.id);
        logger('lien_remplace', { box: box.id });
        return redirect(res, `/admin?ok=rotated#box-${box.id}`);
      }
      await store.setBoxActive(box.id, !box.active);
      logger(box.active ? 'lien_reactive' : 'lien_desactive', { box: box.id });
      return redirect(res, `/admin?ok=${box.active ? 'on' : 'off'}#box-${box.id}`);
    }

    match = /^\/admin\/files\/([a-f0-9]{32})(\/delete)?$/.exec(pathname);
    if (match) {
      const meta = store.files.get(match[1]);
      if (!meta) throw new HttpError(404, 'Fichier introuvable.');
      if (match[2]) {
        if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
        await adminForm(req, session);
        await store.deleteFile(meta.id);
        logger('fichier_supprime', { file: meta.id });
        return redirect(res, `/admin?ok=deleted#box-${meta.boxId}`);
      }
      if (req.method !== 'GET') throw new HttpError(405, 'Méthode non autorisée.');
      logger('fichier_telecharge', { file: meta.id });
      return download(res, meta);
    }

    return sendHtml(res, 404, views.notFound(assets));
  }

  async function route(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const { pathname } = url;
    const isRead = req.method === 'GET' || req.method === 'HEAD';

    if (pathname === '/healthz') return send(res, 200, 'ok', { 'Content-Type': 'text/plain; charset=utf-8' });
    if (pathname.startsWith('/assets/')) {
      if (!isRead) throw new HttpError(405, 'Méthode non autorisée.');
      return serveAsset(req, res, pathname.slice('/assets/'.length), url.searchParams.get('v'));
    }
    if (pathname === '/robots.txt') return send(res, 200, 'User-agent: *\nDisallow: /\n', { 'Content-Type': 'text/plain; charset=utf-8' });

    const pages = {
      '/': () => views.home(assets),
      '/securite': () => views.security(assets, config),
      '/confidentialite': () => views.privacy(assets, config),
      '/mentions-legales': () => views.legal(assets),
    };
    if (pages[pathname]) {
      if (!isRead) throw new HttpError(405, 'Méthode non autorisée.');
      return sendHtml(res, 200, pages[pathname]());
    }

    if (pathname === '/admin' || pathname.startsWith('/admin/')) return adminRoute(req, res, pathname, url);

    const ip = clientIp(req);
    let match = /^\/d\/([^/]*)$/.exec(pathname);
    if (match) {
      if (!isRead) throw new HttpError(405, 'Méthode non autorisée.');
      if (limits.badToken.blocked(ip)) return sendHtml(res, 429, views.invalidLink(assets));
      const token = match[1];
      const box = /^[A-Za-z0-9_-]{43}$/.test(token) ? store.boxByToken(token) : null;
      if (!box || !box.active) {
        limits.badToken.hit(ip);
        return sendHtml(res, 404, views.invalidLink(assets));
      }
      return sendHtml(res, 200, views.deposit(assets, { box, token, maxBytes: config.maxFileBytes }));
    }

    match = /^\/api\/d\/([A-Za-z0-9_-]{43})\/uploads(?:\/([a-f0-9]{32})(?:\/(\d{1,6}|complete))?)?$/.exec(pathname);
    if (match) {
      if (!limits.api.hit(ip) || limits.badToken.blocked(ip)) throw new HttpError(429, 'Trop de requêtes. Réessayez dans quelques minutes.');
      const box = store.boxByToken(match[1]);
      if (!box || !box.active) {
        limits.badToken.hit(ip);
        throw new HttpError(404, 'Ce lien de dépôt ne fonctionne plus.');
      }
      return depositApi(req, res, box, match[2], match[3]);
    }

    return sendHtml(res, 404, views.notFound(assets));
  }

  async function handler(req, res) {
    try {
      await route(req, res);
    } catch (error) {
      const status = error instanceof HttpError || error instanceof UploadError ? error.status : 500;
      if (status === 500) logger('erreur', { error: error.message });
      const api = req.url.startsWith('/api/');
      const message = status === 500 ? 'Erreur du serveur. Réessayez dans un instant.' : error.message;
      // Corps non lu (bloc refusé, requête trop grosse) : la connexion est fermée après la réponse.
      const headers = req.complete ? {} : { Connection: 'close' };
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (api) sendJson(res, status, { error: message, ...(error.extra || {}) }, headers);
      else send(res, status, message, { 'Content-Type': 'text/plain; charset=utf-8', ...headers });
      if (!req.complete) res.on('finish', () => req.destroy());
    }
  }

  async function housekeeping() {
    try {
      await uploads.sweep();
      sessions.sweep();
      for (const limiter of Object.values(limits)) limiter.sweep();
      const cutoff = new Date(Date.now() - config.retentionDays * 86400e3);
      const removed = await store.purgeOlderThan(cutoff);
      if (removed) logger('suppression_automatique', { files: removed });
    } catch (error) {
      logger('menage_echec', { error: error.message });
    }
  }

  const server = http.createServer(handler);
  // Connexions gardées plus longtemps que Traefik (90 s) pour éviter des 502 au moment où il les réutilise.
  server.requestTimeout = 120_000;
  server.headersTimeout = 100_000;
  server.keepAliveTimeout = 95_000;

  return { server, store, uploads, sessions, limits, housekeeping, init: () => store.init() };
}

async function main() {
  const config = loadConfig();
  const app = createApp(config);
  await app.init();
  await app.housekeeping();
  const timer = setInterval(app.housekeeping, 15 * 60e3);
  timer.unref();
  app.server.listen(config.port, () => log('demarrage', { port: config.port, espaces: app.store.boxes.length, fichiers: app.store.files.size }));
  const stop = () => {
    log('arret');
    app.server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 10_000).unref();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (require.main === module) {
  main().catch((error) => {
    log('demarrage_impossible', { error: error.message });
    process.exit(1);
  });
}

module.exports = { createApp };
