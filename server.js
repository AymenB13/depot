'use strict';

// Portail de dépôt de documents : files.aymenbenali.com
// Aucune dépendance externe : modules intégrés de Node.js uniquement.

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { loadConfig } = require('./lib/config');
const { deriveKey } = require('./lib/crypto');
const { Store } = require('./lib/store');
const { Uploads, UploadError } = require('./lib/uploads');
const { ProofOfWork, DailyVolume } = require('./lib/antispam');
const { scanFile } = require('./lib/antivirus');
const { decryptedChunks } = require('./lib/files');
const { verifyPassword } = require('./lib/password');
const { Sessions, RateLimiter, safeEqual } = require('./lib/guards');
const { contentDisposition } = require('./lib/names');
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
  const antispam = {
    pow: new ProofOfWork(deriveKey(config.masterKey, 'depot/pow/v1'), config.powBits),
    perIp: new DailyVolume(config.dailyBytesPerIp),
    total: new DailyVolume(config.dailyBytesTotal),
  };
  const uploads = new Uploads({ store, config, log: logger, antispam });
  const sessions = new Sessions();
  // Pas de limite globale sur la connexion : elle permettrait à n'importe qui de bloquer l'accès.
  const limits = {
    login: new RateLimiter(8, 15 * 60e3),
    starts: new RateLimiter(60, 60 * 60e3),
    api: new RateLimiter(20000, 10 * 60e3),
  };
  let passwordChecks = 0;
  const assets = loadAssets(path.join(__dirname, 'public'));
  const wwwHost = `www.${new URL(config.publicOrigin).host}`;
  const cookieName = config.secureCookies ? '__Host-depot' : 'depot';

  // ---- Antivirus : une analyse à la fois ; en cas d'échec, nouvel essai au passage suivant ----
  const scanQueue = [];
  let scanning = false;

  function enqueueScans() {
    for (const meta of store.files.values()) {
      if ((!meta.scan || meta.scan.status === 'pending') && !scanQueue.includes(meta.id)) scanQueue.push(meta.id);
    }
    runScans();
  }

  async function runScans() {
    if (scanning) return;
    scanning = true;
    try {
      while (scanQueue.length > 0) {
        const meta = store.files.get(scanQueue.shift());
        if (!meta || (meta.scan && meta.scan.status !== 'pending')) continue;
        const result = await scanFile(store, meta, { host: config.clamavHost, port: config.clamavPort });
        if (!store.files.has(meta.id)) continue;
        if (result.status === 'error') {
          logger('analyse_impossible', { file: meta.id, detail: result.detail });
          continue;
        }
        meta.scan = { status: result.status, signature: result.signature || '', at: new Date().toISOString() };
        await store.saveMeta(meta);
        logger(result.status === 'clean' ? 'analyse_saine' : 'virus_detecte', { file: meta.id });
      }
    } catch (error) {
      logger('analyse_echec', { error: error.message });
    } finally {
      scanning = false;
    }
  }

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

  function serveAsset(req, res, name, version) {
    const asset = assets.get(name);
    if (!asset) return sendHtml(res, 404, views.notFound(assets));
    const cache = version === asset.version ? 'public, max-age=31536000, immutable' : 'public, max-age=300';
    return send(res, 200, asset.body, { 'Content-Type': asset.type, 'Cache-Control': cache });
  }

  async function download(res, meta) {
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'Content-Type': 'application/octet-stream',
      'Content-Length': meta.size,
      'Content-Disposition': contentDisposition(meta.name),
      'Cache-Control': 'no-store',
    });
    try {
      for await (const plain of decryptedChunks(store, meta)) {
        if (res.destroyed) return;
        if (!res.write(plain)) await waitDrain(res);
      }
      res.end();
    } catch (error) {
      logger('telechargement_echec', { file: meta.id, error: error.message });
      res.destroy();
    }
  }

  async function depositApi(req, res, ip, uploadId, step) {
    if (!sameOrigin(req)) throw new HttpError(403, 'Requête refusée.');
    if (!uploadId) {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      if (!limits.starts.hit(ip)) throw new HttpError(429, 'Trop d\'envois depuis votre connexion. Réessayez plus tard.');
      if (!/^application\/json\b/.test(req.headers['content-type'] || '')) throw new HttpError(415, 'JSON attendu.');
      let input;
      try {
        input = JSON.parse((await readBody(req, 16384)).toString('utf8'));
      } catch (error) {
        if (error instanceof HttpError) throw error;
        throw new HttpError(400, 'Requête illisible.');
      }
      if (!input || typeof input !== 'object') throw new HttpError(400, 'Requête illisible.');
      const started = await uploads.start(input, ip);
      logger('envoi_commence', { size: input.size });
      return sendJson(res, 201, started);
    }
    if (step === undefined) {
      if (req.method !== 'DELETE') throw new HttpError(405, 'Méthode non autorisée.');
      await uploads.abort(uploadId);
      return send(res, 204, '');
    }
    if (step === 'complete') {
      if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
      const meta = await uploads.finish(uploadId);
      logger('depot_recu', { file: meta.id, size: meta.size });
      enqueueScans();
      return sendJson(res, 200, { name: meta.name, size: meta.size, receivedAt: meta.uploadedAt });
    }
    if (req.method !== 'PUT') throw new HttpError(405, 'Méthode non autorisée.');
    const result = await uploads.receiveChunk(uploadId, Number(step), (expected) => readExact(req, expected));
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
      return sendHtml(
        res,
        200,
        views.dashboard(assets, {
          files: store.list(),
          csrf: session.csrf,
          deleted: url.searchParams.get('ok') === 'deleted',
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

    const match = /^\/admin\/files\/([a-f0-9]{32})(\/delete)?$/.exec(pathname);
    if (match) {
      const meta = store.files.get(match[1]);
      if (!meta) throw new HttpError(404, 'Fichier introuvable.');
      if (match[2]) {
        if (req.method !== 'POST') throw new HttpError(405, 'Méthode non autorisée.');
        await adminForm(req, session);
        await store.deleteFile(meta.id);
        logger('fichier_supprime', { file: meta.id });
        return redirect(res, '/admin?ok=deleted');
      }
      if (req.method !== 'GET') throw new HttpError(405, 'Méthode non autorisée.');
      // Rien ne sort avant le feu vert de l'antivirus.
      if (!meta.scan || meta.scan.status !== 'clean') throw new HttpError(409, 'Fichier pas encore vérifié par l\'antivirus, ou bloqué.');
      logger('fichier_telecharge', { file: meta.id });
      return download(res, meta);
    }

    return sendHtml(res, 404, views.notFound(assets));
  }

  async function route(req, res) {
    // www.files… renvoie vers l'adresse principale, chemin compris.
    if (String(req.headers.host || '').toLowerCase() === wwwHost) {
      return send(res, 301, '', { Location: `${config.publicOrigin}${req.url.startsWith('/') ? req.url : '/'}` });
    }
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
      '/': () => views.deposit(assets, { maxBytes: config.maxFileBytes, powBits: config.powBits }),
      '/securite': () => views.security(assets, config),
      '/confidentialite': () => views.privacy(assets, config),
      '/mentions-legales': () => views.legal(assets),
    };
    if (Object.hasOwn(pages, pathname)) {
      if (!isRead) throw new HttpError(405, 'Méthode non autorisée.');
      return sendHtml(res, 200, pages[pathname]());
    }

    if (pathname === '/admin' || pathname.startsWith('/admin/')) return adminRoute(req, res, pathname, url);

    const ip = clientIp(req);
    if (pathname === '/api/challenge') {
      if (!isRead) throw new HttpError(405, 'Méthode non autorisée.');
      if (!limits.api.hit(ip)) throw new HttpError(429, 'Trop de requêtes. Réessayez dans quelques minutes.');
      return sendJson(res, 200, antispam.pow.issue());
    }
    const match = /^\/api\/uploads(?:\/([a-f0-9]{32})(?:\/(\d{1,6}|complete))?)?$/.exec(pathname);
    if (match) {
      if (!limits.api.hit(ip)) throw new HttpError(429, 'Trop de requêtes. Réessayez dans quelques minutes.');
      return depositApi(req, res, ip, match[1], match[2]);
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
      antispam.pow.sweep();
      antispam.perIp.sweep();
      antispam.total.sweep();
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

  return {
    server,
    store,
    uploads,
    antispam,
    sessions,
    limits,
    housekeeping,
    enqueueScans,
    scansIdle: () => !scanning && scanQueue.length === 0,
    init: () => store.init(),
  };
}

async function main() {
  const config = loadConfig();
  const app = createApp(config);
  await app.init();
  await app.housekeeping();
  setInterval(app.housekeeping, 15 * 60e3).unref();
  // Fichiers encore à analyser (antivirus indisponible un moment) : nouvel essai toutes les 2 minutes.
  app.enqueueScans();
  setInterval(app.enqueueScans, 2 * 60e3).unref();
  app.server.listen(config.port, () => log('demarrage', { port: config.port, fichiers: app.store.files.size }));
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
