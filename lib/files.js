'use strict';

// Lecture d'un fichier stocké : chaque bloc est déchiffré et vérifié avant d'être rendu.

const fsp = require('node:fs/promises');
const { decryptChunk, TAG_LENGTH } = require('./crypto');

async function* decryptedChunks(store, meta) {
  const handle = await fsp.open(store.dataPath(meta.id), 'r');
  try {
    const key = Buffer.from(meta.key, 'base64');
    const prefix = Buffer.from(meta.prefix, 'base64');
    const chunkSize = meta.chunkSize;
    const count = Math.max(1, Math.ceil(meta.size / chunkSize));
    for (let index = 0; index < count; index += 1) {
      const length = index < count - 1 ? chunkSize : meta.size - chunkSize * (count - 1);
      const buffer = Buffer.alloc(length + TAG_LENGTH);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, index * (chunkSize + TAG_LENGTH));
      if (bytesRead !== buffer.length) throw new Error('fichier tronqué');
      yield decryptChunk(key, prefix, index, index === count - 1, buffer);
    }
  } finally {
    await handle.close();
  }
}

module.exports = { decryptedChunks };
