'use strict';

// Stockage sur disque, dans DATA_DIR (bind mount /opt/depot/data sur le VPS) :
//   boxes.json          espaces de dépôt (un par client) ; nom et lien chiffrés, empreinte du jeton
//   files/<id>.bin      contenu chiffré par blocs
//   files/<id>.meta     métadonnées chiffrées (nom, taille, empreinte, déposant, message, clé du fichier)
//   tmp/                envois en cours, vidé à chaque démarrage

const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { sealJson, openJson, sha256Hex, randomHex, newToken } = require('./crypto');

async function writeFileAtomic(file, data) {
  const tmp = `${file}.${randomHex(6)}.tmp`;
  const handle = await fsp.open(tmp, 'wx', 0o600);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fsp.rename(tmp, file);
}

function sameHex(a, b) {
  const x = Buffer.from(String(a), 'hex');
  const y = Buffer.from(String(b), 'hex');
  return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y);
}

class Store {
  constructor({ dataDir, metaKey, log }) {
    this.dataDir = dataDir;
    this.filesDir = path.join(dataDir, 'files');
    this.tmpDir = path.join(dataDir, 'tmp');
    this.boxesFile = path.join(dataDir, 'boxes.json');
    this.metaKey = metaKey;
    this.log = log;
    this.boxes = [];
    this.files = new Map();
  }

  async init() {
    await fsp.mkdir(this.filesDir, { recursive: true, mode: 0o700 });
    await fsp.rm(this.tmpDir, { recursive: true, force: true });
    await fsp.mkdir(this.tmpDir, { recursive: true, mode: 0o700 });

    let stored = [];
    try {
      const data = JSON.parse(await fsp.readFile(this.boxesFile, 'utf8'));
      stored = Array.isArray(data.boxes) ? data.boxes : [];
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    this.boxes = stored.map((box) => ({
      id: box.id,
      name: openJson(this.metaKey, Buffer.from(box.nameSealed, 'base64'), `box-name:${box.id}`).name,
      active: box.active !== false,
      createdAt: box.createdAt,
      tokenHash: box.tokenHash,
      tokenSealed: box.tokenSealed,
    }));

    const names = await fsp.readdir(this.filesDir);
    const metas = new Set(names.filter((n) => /^[a-f0-9]{32}\.meta$/.test(n)).map((n) => n.slice(0, 32)));
    for (const id of metas) {
      try {
        const blob = await fsp.readFile(path.join(this.filesDir, `${id}.meta`));
        this.files.set(id, openJson(this.metaKey, blob, `meta:${id}`));
      } catch {
        this.log('meta_illisible', { file: id });
      }
    }
    // Contenus sans métadonnées (arrêt au milieu d'un enregistrement) et fichiers temporaires.
    for (const name of names) {
      const orphan = name.endsWith('.bin') && !metas.has(name.slice(0, -4));
      if (orphan || name.endsWith('.tmp')) await fsp.rm(path.join(this.filesDir, name), { force: true });
    }
  }

  // ---- Espaces de dépôt ----

  boxById(id) {
    return this.boxes.find((box) => box.id === id) || null;
  }

  // Parcourt tous les espaces pour un temps de réponse constant.
  boxByToken(token) {
    const hash = sha256Hex(token);
    let found = null;
    for (const box of this.boxes) {
      if (sameHex(box.tokenHash, hash)) found = box;
    }
    return found;
  }

  boxLink(box, origin) {
    const { token } = openJson(this.metaKey, Buffer.from(box.tokenSealed, 'base64'), `box-token:${box.id}`);
    return `${origin}/d/${token}`;
  }

  setToken(box) {
    const token = newToken();
    box.tokenHash = sha256Hex(token);
    box.tokenSealed = sealJson(this.metaKey, { token }, `box-token:${box.id}`).toString('base64');
  }

  async createBox(name) {
    const box = { id: randomHex(8), name, active: true, createdAt: new Date().toISOString() };
    this.setToken(box);
    this.boxes.push(box);
    await this.saveBoxes();
    return box;
  }

  async rotateBox(id) {
    const box = this.boxById(id);
    if (!box) return null;
    this.setToken(box);
    await this.saveBoxes();
    return box;
  }

  async setBoxActive(id, active) {
    const box = this.boxById(id);
    if (!box) return null;
    box.active = Boolean(active);
    await this.saveBoxes();
    return box;
  }

  async saveBoxes() {
    const boxes = this.boxes.map((box) => ({
      id: box.id,
      nameSealed: sealJson(this.metaKey, { name: box.name }, `box-name:${box.id}`).toString('base64'),
      active: box.active,
      createdAt: box.createdAt,
      tokenHash: box.tokenHash,
      tokenSealed: box.tokenSealed,
    }));
    await writeFileAtomic(this.boxesFile, JSON.stringify({ version: 1, boxes }, null, 2));
  }

  // ---- Fichiers ----

  filesOf(boxId) {
    return [...this.files.values()]
      .filter((file) => file.boxId === boxId)
      .sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
  }

  usage(boxId) {
    let total = 0;
    for (const file of this.files.values()) if (file.boxId === boxId) total += file.size;
    return total;
  }

  dataPath(id) {
    return path.join(this.filesDir, `${id}.bin`);
  }

  async commitFile(meta, tmpPath) {
    await fsp.rename(tmpPath, this.dataPath(meta.id));
    await writeFileAtomic(path.join(this.filesDir, `${meta.id}.meta`), sealJson(this.metaKey, meta, `meta:${meta.id}`));
    this.files.set(meta.id, meta);
  }

  async deleteFile(id) {
    if (!this.files.has(id)) return false;
    this.files.delete(id);
    await fsp.rm(path.join(this.filesDir, `${id}.meta`), { force: true });
    await fsp.rm(this.dataPath(id), { force: true });
    return true;
  }

  async purgeOlderThan(cutoff) {
    let removed = 0;
    for (const file of [...this.files.values()]) {
      if (file.uploadedAt < cutoff.toISOString()) {
        await this.deleteFile(file.id);
        removed += 1;
      }
    }
    return removed;
  }

  async freeBytes() {
    const stats = await fsp.statfs(this.dataDir);
    return stats.bavail * stats.bsize;
  }
}

module.exports = { Store, writeFileAtomic };
