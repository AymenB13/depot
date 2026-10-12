'use strict';

// Outils pour l'installation sur le VPS (lancés dans l'image, sans réseau) :
//   node cli.js gen-key                 clé de chiffrement (32 octets, base64url)
//   node cli.js gen-password            mot de passe administrateur aléatoire
//   node cli.js hash-password < mdp     empreinte scrypt à mettre dans ADMIN_PASSWORD_HASH
//   node cli.js check-config            vérifie l'environnement

const crypto = require('node:crypto');
const { hashPassword } = require('./lib/password');

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

async function run(command) {
  switch (command) {
    case 'gen-key':
      return crypto.randomBytes(32).toString('base64url');
    case 'gen-password':
      return crypto.randomBytes(18).toString('base64url');
    case 'hash-password':
      return hashPassword(await readStdin());
    case 'check-config':
      require('./lib/config').loadConfig();
      return 'ok';
    default:
      throw new Error('Usage : node cli.js gen-key | gen-password | hash-password | check-config');
  }
}

run(process.argv[2])
  .then((output) => process.stdout.write(`${output}\n`))
  .catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
