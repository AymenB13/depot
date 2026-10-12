'use strict';

// Stockage sur disque, dans DATA_DIR (bind mount /opt/depot/data sur le VPS) :
//   files/<id>.bin      contenu chiffré par blocs
//   files/<id>.meta     métadonnées chiffrées (nom, taille, déposant, clé du fichier, antivirus)
//   tmp/                envois en cours, vidé à chaque démarrage

const fsp = require('node:fs/promises');
const path = require('node:path');
const { sealJson, openJson, randomHex } = require('./crypto');

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

class Store {
  constructor({ dataDir, metaKey, log }) {
    this.dataDir = dataDir;
    this.filesDir = path.join(dataDir, 'files');
    this.tmpDir = path.join(dataDir, 'tmp');
    this.metaKey = metaKey;
    this.log = log;
    this.files = new Map();
  }

  async init() {
    await fsp.mkdir(this.filesDir, { recursive: true, mode: 0o700 });
    await fsp.rm(this.tmpDir, { recursive: true, force: true });
    await fsp.mkdir(this.tmpDir, { recursive: true, mode: 0o700 });
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

  list() {
    return [...this.files.values()].sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
  }

  usage() {
    let total = 0;
    for (const file of this.files.values()) total += file.size;
    return total;
  }

  dataPath(id) {
    return path.join(this.filesDir, `${id}.bin`);
  }

  async saveMeta(meta) {
    await writeFileAtomic(path.join(this.filesDir, `${meta.id}.meta`), sealJson(this.metaKey, meta, `meta:${meta.id}`));
  }

  async commitFile(meta, tmpPath) {
    await fsp.rename(tmpPath, this.dataPath(meta.id));
    await this.saveMeta(meta);
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
