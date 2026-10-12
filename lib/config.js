'use strict';

// Configuration lue dans l'environnement (voir deploy/compose.yaml et /opt/depot/app.env).

const GIB = 1024 ** 3;

function number(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} invalide : ${raw}`);
  return value;
}

function loadConfig(env = process.env) {
  const masterKey = Buffer.from(env.MASTER_KEY || '', 'base64url');
  if (masterKey.length !== 32) {
    throw new Error('MASTER_KEY manquante ou invalide (32 octets en base64url)');
  }
  const adminPasswordHash = env.ADMIN_PASSWORD_HASH || '';
  if (!/^scrypt:\d+:\d+:\d+:[A-Za-z0-9_-]{16,}:[A-Za-z0-9_-]{32,}$/.test(adminPasswordHash)) {
    throw new Error('ADMIN_PASSWORD_HASH manquant ou invalide');
  }
  const publicUrl = new URL(env.PUBLIC_URL || 'https://files.aymenbenali.com');
  let notifyUrl = null;
  if (env.NOTIFY_URL) {
    const url = new URL(env.NOTIFY_URL);
    if (url.protocol !== 'https:') throw new Error('NOTIFY_URL doit commencer par https://');
    notifyUrl = url.href;
  }
  return Object.freeze({
    port: number(env, 'PORT', 8080),
    dataDir: env.DATA_DIR || '/data',
    masterKey,
    adminPasswordHash,
    publicOrigin: publicUrl.origin,
    retentionDays: number(env, 'RETENTION_DAYS', 90),
    maxFileBytes: number(env, 'MAX_FILE_BYTES', 4 * GIB),
    boxQuotaBytes: number(env, 'BOX_QUOTA_BYTES', 40 * GIB),
    // Le portail refuse un dépôt qui laisserait moins que cet espace libre sur le disque du VPS.
    minFreeBytes: number(env, 'MIN_FREE_BYTES', 20 * GIB),
    notifyUrl,
    // Cookies « Secure » partout, sauf pour les tests en local (http).
    secureCookies: env.INSECURE_COOKIES !== '1',
  });
}

module.exports = { loadConfig, GIB };
