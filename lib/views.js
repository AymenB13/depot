'use strict';

// Pages HTML, rendues côté serveur. Tout texte variable passe par esc().

const { ALLOWED_EXTENSIONS } = require('./names');

const CONTACT = 'contact@aymenbenali.com';
// Adresse fiscale (domicile), comme sur la page légale du site principal.
const ADDRESS = 'Av. del Regne de València, 87, #70, 46006 València, Espagne';

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  const units = ['Ko', 'Mo', 'Go', 'To'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value < 10 ? 1 : 0;
  return `${value.toLocaleString('fr-FR', { maximumFractionDigits: digits })} ${units[unit]}`;
}

const dateFormat = new Intl.DateTimeFormat('fr-FR', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'Europe/Madrid',
});

function formatDate(iso) {
  return dateFormat.format(new Date(iso));
}

function layout({ title, body, assets, scripts = [], wide = false }) {
  const scriptTags = scripts.map((name) => `<script src="${assets.url(name)}" defer></script>`).join('');
  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)}</title>
<link rel="stylesheet" href="${assets.url('app.css')}">
<link rel="icon" href="${assets.url('favicon.svg')}" type="image/svg+xml">
${scriptTags}
</head>
<body>
<div class="page${wide ? ' page-wide' : ''}">
<header class="brand"><a class="brand-link" href="/"><span class="brand-ring" aria-hidden="true"></span>Aymen Benali</a></header>
${body}
<footer class="foot">
<nav aria-label="Informations"><a href="/securite">Sécurité</a><a href="/confidentialite">Confidentialité</a><a href="/mentions-legales">Mentions légales</a></nav>
</footer>
</div>
</body>
</html>`;
}

function deposit(assets, { maxBytes, powBits }) {
  return layout({
    title: 'Envoyer des documents · Aymen Benali',
    assets,
    scripts: ['pow.js', 'depot.js'],
    body: `<main class="sheet" data-depot data-max="${maxBytes}" data-bits="${powBits}" data-ext="${esc(ALLOWED_EXTENSIONS.join(','))}">
<h1>Envoyer des documents</h1>
<p class="lead">Vos fichiers arrivent chiffrés et passent à l'antivirus. Seul Aymen Benali y a accès.</p>

<div class="field name-field"><label for="uploader">Prénom et nom</label>
<input id="uploader" type="text" maxlength="80" autocomplete="name" required></div>
<div class="trap" aria-hidden="true"><label for="website">Ne pas remplir</label><input id="website" type="text" tabindex="-1" autocomplete="off"></div>

<div class="drop" id="drop">
<svg class="drop-icon" viewBox="0 0 48 48" aria-hidden="true"><path d="M8 30v8a2 2 0 0 0 2 2h28a2 2 0 0 0 2-2v-8"/><path d="M24 6v24"/><path d="M15 21l9 9 9-9"/></svg>
<p class="drop-title">Glissez vos fichiers ici</p>
<button type="button" class="button secondary" id="choose">Choisir des fichiers</button>
<input id="picker" type="file" multiple hidden>
<p class="drop-hint">PDF, Excel, CSV, Word, PowerPoint, ZIP… Jusqu'à ${esc(formatBytes(maxBytes))} par fichier.</p>
</div>

<ul class="queue" id="queue" aria-live="polite"></ul>
<p class="alert" id="alert" role="alert" hidden></p>
<p class="all-done" id="done" hidden>Tous les fichiers sont arrivés. Vous pouvez fermer cette page.</p>
<noscript><p class="alert">Activez JavaScript dans votre navigateur pour envoyer des fichiers.</p></noscript>
</main>`,
  });
}

function notFound(assets) {
  return layout({
    title: 'Page introuvable · Aymen Benali',
    assets,
    body: `<main class="sheet">
<h1>Page introuvable</h1>
<p><a href="/">Envoyer des documents</a></p>
</main>`,
  });
}

function security(assets, { retentionDays }) {
  return layout({
    title: 'Sécurité · Envoi de documents',
    assets,
    body: `<main class="sheet prose">
<h1>Sécurité</h1>
<p class="lead">Ce que deviennent vos documents, de votre navigateur jusqu'à leur suppression.</p>

<h2>Pendant l'envoi</h2>
<p>La connexion entre votre navigateur et le serveur est chiffrée (HTTPS). Les pages ne chargent rien depuis un autre site : ni police, ni script, ni outil de mesure d'audience. Aucun compte n'est nécessaire.</p>

<h2>Sur le serveur</h2>
<p>Chaque fichier est chiffré dès sa réception (AES-256-GCM), avec une clé propre à chaque fichier. Son nom est chiffré lui aussi. Il passe ensuite à l'antivirus (ClamAV) : un fichier infecté est bloqué et n'est jamais ouvert.</p>
<p>Le serveur est un serveur privé (VPS) hébergé par Hostinger en France. Le portail y tourne dans un conteneur isolé des autres services, sans privilèges.</p>

<h2>Qui peut lire vos documents</h2>
<p>Seul Aymen Benali, depuis un espace protégé par mot de passe. Personne ne peut consulter ni télécharger les fichiers depuis cette page, pas même la personne qui les a envoyés. Vos documents servent uniquement à la mission pour laquelle vous les avez transmis et restent couverts par les engagements de confidentialité convenus avec vous.</p>

<h2>Durée de conservation</h2>
<p>Les fichiers sont supprimés automatiquement ${esc(retentionDays)} jours après leur dépôt, ou plus tôt à votre demande.</p>

<h2>Une question</h2>
<p>Écrivez à <a href="mailto:${CONTACT}">${CONTACT}</a>.</p>
</main>`,
  });
}

function privacy(assets, { retentionDays }) {
  return layout({
    title: 'Confidentialité · Envoi de documents',
    assets,
    body: `<main class="sheet prose">
<h1>Confidentialité</h1>
<p class="lead">Les données que ce portail traite, pourquoi, et combien de temps.</p>

<h2>Responsable du traitement</h2>
<p>Aymen Benali, ${ADDRESS}. Contact : <a href="mailto:${CONTACT}">${CONTACT}</a>.</p>

<h2>Données traitées</h2>
<ul>
<li>Vos prénom et nom.</li>
<li>Les documents que vous envoyez, leur nom et leur taille, ainsi que les données personnelles qu'ils peuvent contenir.</li>
<li>La date et l'heure de chaque envoi.</li>
<li>Votre adresse IP, gardée en mémoire 24 heures au plus pour limiter les abus. Le portail ne l'enregistre pas. L'hébergement peut conserver des journaux techniques de connexion pendant une durée limitée.</li>
</ul>

<h2>Finalités et base légale</h2>
<p>Recevoir et exploiter les documents nécessaires à une mission de conseil : exécution du contrat ou de mesures précontractuelles (article 6, paragraphe 1, point b, du RGPD). Protéger le service contre les abus et les virus : intérêt légitime (article 6, paragraphe 1, point f).</p>

<h2>Destinataires</h2>
<p>Seul Aymen Benali accède aux documents. L'hébergeur, Hostinger, agit comme sous-traitant ; les fichiers sont chiffrés sur ses disques. Aucune donnée n'est vendue ni cédée. Les données restent dans l'Union européenne.</p>

<h2>Durée de conservation</h2>
<p>Les fichiers et leurs informations sont supprimés automatiquement ${esc(retentionDays)} jours après leur dépôt, ou plus tôt à votre demande. Les copies de travail nécessaires à la mission suivent les engagements de confidentialité convenus avec vous.</p>

<h2>Cookies</h2>
<p>L'envoi de documents n'utilise aucun cookie. L'espace d'administration, réservé à Aymen Benali, utilise un seul cookie de session, strictement nécessaire. Aucun outil de mesure d'audience ni de publicité.</p>

<h2>Vos droits</h2>
<p>Vous pouvez demander l'accès à vos données, leur rectification, leur effacement ou leur portabilité, la limitation du traitement, ou vous y opposer, en écrivant à <a href="mailto:${CONTACT}">${CONTACT}</a>. Vous pouvez aussi saisir l'autorité espagnole de protection des données, l'AEPD (<a href="https://www.aepd.es">www.aepd.es</a>).</p>
</main>`,
  });
}

function legal(assets) {
  return layout({
    title: 'Mentions légales · Envoi de documents',
    assets,
    body: `<main class="sheet prose">
<h1>Mentions légales</h1>

<h2>Éditeur</h2>
<p>Aymen Benali, entrepreneur individuel (autónomo), non inscrit au registre du commerce (Registro Mercantil).</p>
<dl class="facts">
<dt>NIF</dt><dd>Z3071357B</dd>
<dt>TVA intracommunautaire</dt><dd>ESZ3071357B</dd>
<dt>Adresse</dt><dd>${ADDRESS}</dd>
<dt>Contact</dt><dd><a href="mailto:${CONTACT}">${CONTACT}</a></dd>
<dt>Directeur de la publication</dt><dd>Aymen Benali</dd>
</dl>

<h2>Hébergement</h2>
<p>Hostinger International Ltd, 61 Lordou Vironos Street, 6023 Larnaca, Chypre (<a href="https://www.hostinger.com">hostinger.com</a>). Le serveur est situé en France.</p>

<h2>Objet du site</h2>
<p>Ce site permet aux clients et partenaires d'Aymen Benali de lui transmettre des documents dans le cadre de ses missions de conseil.</p>

<h2>Documents déposés</h2>
<p>Les documents restent la propriété de ceux qui les transmettent. Ils ne servent qu'à la mission concernée. Tout envoi abusif ou malveillant est refusé et supprimé.</p>

<h2>Droit applicable</h2>
<p>Mentions établies conformément à la loi espagnole 34/2002 sur les services de la société de l'information (LSSI-CE). Le droit espagnol s'applique.</p>
<p>Voir aussi la page <a href="/confidentialite">Confidentialité</a> et la page <a href="/securite">Sécurité</a>.</p>
</main>`,
  });
}

// ---- Administration ----

function login(assets, { error = '', status = '' } = {}) {
  return layout({
    title: 'Connexion · Administration',
    assets,
    body: `<main class="sheet narrow">
<h1>Administration</h1>
${status ? `<p class="notice">${esc(status)}</p>` : ''}
${error ? `<p class="alert" role="alert">${esc(error)}</p>` : ''}
<form method="post" action="/admin/login" class="stack">
<div class="field"><label for="password">Mot de passe</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus></div>
<button class="button primary" type="submit">Se connecter</button>
</form>
</main>`,
  });
}

function hidden(csrf) {
  return `<input type="hidden" name="csrf" value="${esc(csrf)}">`;
}

function scanCell(file) {
  const scan = file.scan || { status: 'pending' };
  if (scan.status === 'clean') return '<span class="scan ok">Sain</span>';
  if (scan.status === 'infected') return `<span class="scan bad">Virus : ${esc(scan.signature || 'détecté')}</span>`;
  return '<span class="scan wait">Analyse en cours</span>';
}

function dashboard(assets, { files, csrf, deleted, freeBytes, retentionDays }) {
  const rows = files
    .map((file) => {
      const clean = file.scan && file.scan.status === 'clean';
      return `<tr>
<td class="file-name"><span>${esc(file.name)}</span>${file.uploaderName ? `<small>${esc(file.uploaderName)}</small>` : ''}</td>
<td class="num">${esc(formatBytes(file.size))}</td>
<td>${esc(formatDate(file.uploadedAt))}</td>
<td>${scanCell(file)}</td>
<td><div class="actions">${clean ? `<a class="button small primary" href="/admin/files/${file.id}">Télécharger</a>` : ''}
<form method="post" action="/admin/files/${file.id}/delete" data-confirm="Supprimer définitivement ce fichier ?">${hidden(csrf)}<button class="button small ghost" type="submit">Supprimer</button></form></div></td>
</tr>`;
    })
    .join('');
  const table = files.length
    ? `<div class="table-wrap"><table class="files">
<thead><tr><th scope="col">Fichier</th><th scope="col" class="num">Taille</th><th scope="col">Reçu le</th><th scope="col">Antivirus</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
<tbody>${rows}</tbody></table></div>`
    : '<p class="quiet empty">Aucun document pour l\'instant.</p>';

  return layout({
    title: 'Documents reçus · Administration',
    assets,
    scripts: ['admin.js'],
    wide: true,
    body: `<main class="sheet">
<div class="admin-head">
<h1>Documents reçus</h1>
<form method="post" action="/admin/logout">${hidden(csrf)}<button class="button ghost small" type="submit">Se déconnecter</button></form>
</div>
${deleted ? '<p class="notice" role="status">Fichier supprimé.</p>' : ''}
${table}
<p class="quiet meta-line">Espace libre sur le serveur : ${esc(formatBytes(freeBytes))}. Suppression automatique ${esc(retentionDays)} jours après le dépôt.</p>
</main>`,
  });
}

module.exports = {
  esc,
  formatBytes,
  deposit,
  notFound,
  security,
  privacy,
  legal,
  login,
  dashboard,
};
