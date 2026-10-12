'use strict';

// Réponses HTTP avec les en-têtes de sécurité, lecture des corps de requête avec plafond.

const net = require('node:net');

const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; " +
    "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  'Strict-Transport-Security': 'max-age=31536000',
  'X-Content-Type-Options': 'nosniff',
  // same-origin : le lien de dépôt ne part jamais vers un autre site, et les formulaires gardent un
  // en-tête Origin vérifiable (avec no-referrer, Chrome envoie « Origin: null »).
  'Referrer-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Frame-Options': 'DENY',
  'X-Robots-Tag': 'noindex, nofollow',
});

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, body, headers = {}) {
  const buffer = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Cache-Control': 'no-store',
    'Content-Length': buffer.length,
    ...headers,
  });
  res.end(buffer);
}

function sendHtml(res, status, page, headers = {}) {
  send(res, status, page, { 'Content-Type': 'text/html; charset=utf-8', ...headers });
}

function sendJson(res, status, data, headers = {}) {
  send(res, status, JSON.stringify(data), { 'Content-Type': 'application/json; charset=utf-8', ...headers });
}

function redirect(res, location, headers = {}) {
  send(res, 303, '', { Location: location, ...headers });
}

// Corps entier, plafonné (formulaires, JSON).
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = req.headers['content-length'];
    if (declared !== undefined && Number(declared) > limit) {
      reject(new HttpError(413, 'Requête trop volumineuse.'));
      return;
    }
    const chunks = [];
    let total = 0;
    let done = false;
    const finish = (error, value) => {
      if (done) return;
      done = true;
      if (error) reject(error);
      else resolve(value);
    };
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > limit) {
        finish(new HttpError(413, 'Requête trop volumineuse.'));
        req.pause();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => finish(null, Buffer.concat(chunks)));
    req.on('aborted', () => finish(new HttpError(400, 'Requête interrompue.')));
    req.on('error', (error) => finish(error));
  });
}

// Exactement `expected` octets, annoncés par Content-Length.
async function readExact(req, expected) {
  const raw = req.headers['content-length'];
  if (raw === undefined || !/^\d+$/.test(raw)) throw new HttpError(411, 'Longueur du bloc manquante.');
  if (Number(raw) !== expected) throw new HttpError(400, 'Taille de bloc inattendue.');
  const body = await readBody(req, expected);
  if (body.length !== expected) throw new HttpError(400, 'Bloc incomplet.');
  return body;
}

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  for (const part of String(header).split(';')) {
    const index = part.indexOf('=');
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    if (name && !(name in cookies)) cookies[name] = part.slice(index + 1).trim();
  }
  return cookies;
}

// Une adresse IPv6 compte pour son préfixe /64 (un abonné en reçoit souvent un entier).
function ipKey(ip) {
  if (!net.isIPv6(ip)) return ip;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return mapped[1];
  const [head, tail = ''] = ip.split('%')[0].split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right] : left;
  return `${groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

// Le portail est servi par Traefik : la dernière adresse de X-Forwarded-For est celle que Traefik a
// vue, les précédentes peuvent venir du client et ne comptent pas. En-tête anormal : adresse du pair.
function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length <= 1024) {
    const last = forwarded.slice(forwarded.lastIndexOf(',') + 1).trim();
    if (net.isIP(last)) return ipKey(last);
  }
  return ipKey(req.socket.remoteAddress || 'inconnue');
}

module.exports = {
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
  ipKey,
};
