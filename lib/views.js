'use strict';

// Pages HTML, rendues côté serveur. Tout texte variable passe par esc().

const { ALLOWED_EXTENSIONS } = require('./names');

const CONTACT = 'contact@aymenbenali.com';
const OFFICE = 'Calle Doctor Juan José Dómine 6, pl. 2, pta. 10, 46011 València, Espagne';

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

function home(assets) {
  return layout({
    title: 'Dépôt de documents · Aymen Benali',
    assets,
    body: `<main class="sheet">
<h1>Dépôt de documents</h1>
<p class="lead">Cet espace permet aux clients d'Aymen Benali de lui transmettre des documents de façon sécurisée.</p>
<p>Pour déposer des fichiers, ouvrez le lien personnel qu'il vous a envoyé.</p>
<p class="quiet">Pas de lien ? Écrivez à <a href="mailto:${CONTACT}">${CONTACT}</a>.</p>
</main>`,
  });
}

function deposit(assets, { box, token, maxBytes }) {
  return layout({
    title: `Déposer des documents · ${box.name}`,
    assets,
    scripts: ['depot.js'],
    body: `<main class="sheet" data-depot data-token="${esc(token)}" data-max="${maxBytes}" data-ext="${esc(ALLOWED_EXTENSIONS.join(','))}">
<h1>Déposer des documents</h1>
<p class="lead">Espace réservé à <strong>${esc(box.name)}</strong>. Seul Aymen Benali a accès aux fichiers déposés ici.</p>

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
<noscript><p class="alert">Activez JavaScript dans votre navigateur pour déposer des fichiers.</p></noscript>
</main>`,
  });
}

function invalidLink(assets) {
  return layout({
    title: 'Lien inactif · Aymen Benali',
    assets,
    body: `<main class="sheet">
<h1>Ce lien ne fonctionne pas</h1>
<p class="lead">Il est incomplet ou il a été désactivé.</p>
<p>Demandez un nouveau lien à Aymen Benali : <a href="mailto:${CONTACT}">${CONTACT}</a>.</p>
</main>`,
  });
}

function notFound(assets) {
  return layout({
    title: 'Page introuvable · Aymen Benali',
    assets,
    body: `<main class="sheet">
<h1>Page introuvable</h1>
<p><a href="/">Retour à l'accueil</a></p>
</main>`,
  });
}

function security(assets, { retentionDays }) {
  return layout({
    title: 'Sécurité · Dépôt de documents',
    assets,
    body: `<main class="sheet prose">
<h1>Sécurité</h1>
<p class="lead">Ce que deviennent vos documents, de votre navigateur jusqu'à leur suppression.</p>

<h2>Pendant l'envoi</h2>
<p>La connexion entre votre navigateur et le serveur est chiffrée (HTTPS). Les pages ne chargent rien depuis un autre site : ni police, ni script, ni outil de mesure d'audience.</p>

<h2>Votre lien de dépôt</h2>
<p>Chaque client reçoit un lien personnel, impossible à deviner. Ce lien permet uniquement de déposer : personne ne peut s'en servir pour consulter ou télécharger les documents déjà envoyés. Aymen Benali peut le désactiver ou le remplacer à tout moment.</p>

<h2>Sur le serveur</h2>
<p>Chaque fichier est chiffré dès sa réception (AES-256-GCM), avec une clé propre à chaque fichier. Son nom est chiffré lui aussi. Les fichiers ne sont jamais ouverts ni exécutés sur le serveur.</p>
<p>Le serveur est un serveur privé (VPS) hébergé par Hostinger en France. Le portail y tourne dans un conteneur isolé des autres services, sans privilèges.</p>

<h2>Qui peut lire vos documents</h2>
<p>Seul Aymen Benali, depuis un espace protégé par mot de passe. Vos documents servent uniquement à la mission pour laquelle vous les avez transmis et restent couverts par les engagements de confidentialité convenus avec vous.</p>

<h2>Durée de conservation</h2>
<p>Les fichiers sont supprimés automatiquement ${esc(retentionDays)} jours après leur dépôt, ou plus tôt à votre demande.</p>

<h2>Un doute, un lien envoyé par erreur</h2>
<p>Écrivez à <a href="mailto:${CONTACT}">${CONTACT}</a> : le lien est désactivé dès réception de votre message.</p>
</main>`,
  });
}

function privacy(assets, { retentionDays }) {
  return layout({
    title: 'Confidentialité · Dépôt de documents',
    assets,
    body: `<main class="sheet prose">
<h1>Confidentialité</h1>
<p class="lead">Les données que ce portail traite, pourquoi, et combien de temps.</p>

<h2>Responsable du traitement</h2>
<p>Aymen Benali, ${OFFICE}. Contact : <a href="mailto:${CONTACT}">${CONTACT}</a>.</p>

<h2>Données traitées</h2>
<ul>
<li>Les documents que vous déposez, leur nom et leur taille, ainsi que les données personnelles qu'ils peuvent contenir.</li>
<li>La date et l'heure de chaque dépôt.</li>
<li>Votre adresse IP, gardée en mémoire quelques minutes au plus pour limiter les abus. Le portail ne l'enregistre pas. L'hébergement peut conserver des journaux techniques de connexion pendant une durée limitée.</li>
</ul>

<h2>Finalités et base légale</h2>
<p>Recevoir et exploiter les documents nécessaires à une mission de conseil : exécution du contrat ou de mesures précontractuelles (article 6, paragraphe 1, point b, du RGPD). Protéger le service contre les abus : intérêt légitime (article 6, paragraphe 1, point f).</p>

<h2>Destinataires</h2>
<p>Seul Aymen Benali accède aux documents. L'hébergeur, Hostinger, agit comme sous-traitant ; les fichiers sont chiffrés sur ses disques. Aucune donnée n'est vendue ni cédée. Les données restent dans l'Union européenne.</p>

<h2>Durée de conservation</h2>
<p>Les fichiers et leurs informations sont supprimés automatiquement ${esc(retentionDays)} jours après leur dépôt, ou plus tôt à votre demande. Les copies de travail nécessaires à la mission suivent les engagements de confidentialité convenus avec vous.</p>

<h2>Cookies</h2>
<p>Le dépôt n'utilise aucun cookie. L'espace d'administration, réservé à Aymen Benali, utilise un seul cookie de session, strictement nécessaire. Aucun outil de mesure d'audience ni de publicité.</p>

<h2>Vos droits</h2>
<p>Vous pouvez demander l'accès à vos données, leur rectification, leur effacement ou leur portabilité, la limitation du traitement, ou vous y opposer, en écrivant à <a href="mailto:${CONTACT}">${CONTACT}</a>. Vous pouvez aussi saisir l'autorité espagnole de protection des données, l'AEPD (<a href="https://www.aepd.es">www.aepd.es</a>).</p>
</main>`,
  });
}

function legal(assets) {
  return layout({
    title: 'Mentions légales · Dépôt de documents',
    assets,
    body: `<main class="sheet prose">
<h1>Mentions légales</h1>

<h2>Éditeur</h2>
<p>Aymen Benali, entrepreneur individuel (autónomo), non inscrit au registre du commerce (Registro Mercantil).</p>
<dl class="facts">
<dt>NIF</dt><dd>Z3071357B</dd>
<dt>TVA intracommunautaire</dt><dd>ESZ3071357B</dd>
<dt>Adresse</dt><dd>${OFFICE}</dd>
<dt>Contact</dt><dd><a href="mailto:${CONTACT}">${CONTACT}</a></dd>
<dt>Directeur de la publication</dt><dd>Aymen Benali</dd>
</dl>

<h2>Hébergement</h2>
<p>Hostinger International Ltd, 61 Lordou Vironos Street, 6023 Larnaca, Chypre (<a href="https://www.hostinger.com">hostinger.com</a>). Le serveur est situé en France.</p>

<h2>Objet du site</h2>
<p>Ce site permet aux clients d'Aymen Benali de lui transmettre des documents dans le cadre de ses missions de conseil. Il n'est pas ouvert au public : déposer un fichier nécessite un lien personnel.</p>

<h2>Documents déposés</h2>
<p>Les documents restent la propriété de ceux qui les transmettent. Ils ne servent qu'à la mission concernée.</p>

<h2>Droit applicable</h2>
<p>Mentions établies conformément à la loi espagnole 34/2002 sur les services de la société de l'information (LSSI-CE). Le droit espagnol s'applique.</p>
<p>Voir aussi la page <a href="/confidentialite">Confidentialité</a> et la page <a href="/securite">Sécurité</a>.</p>
</main>`,
  });
}

// ---- Administration ----

function login(assets, { error = '', status = '' } = {}) {
  return layout({
    title: 'Connexion · Dépôt de documents',
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

function fileRows(files, csrf) {
  if (files.length === 0) return '<p class="quiet empty">Aucun document pour l\'instant.</p>';
  const rows = files
    .map((file) => {
      return `<tr>
<td class="file-name"><span>${esc(file.name)}</span>${file.uploaderName ? `<small>Déposé par ${esc(file.uploaderName)}</small>` : ''}${file.message ? `<small class="message">${esc(file.message)}</small>` : ''}</td>
<td class="num">${esc(formatBytes(file.size))}</td>
<td>${esc(formatDate(file.uploadedAt))}</td>
<td><code class="hash" title="${esc(file.sha256)}">${esc(file.sha256.slice(0, 12))}…</code></td>
<td><div class="actions"><a class="button small primary" href="/admin/files/${file.id}">Télécharger</a>
<form method="post" action="/admin/files/${file.id}/delete" data-confirm="Supprimer définitivement ce fichier ?">${hidden(csrf)}<button class="button small ghost" type="submit">Supprimer</button></form></div></td>
</tr>`;
    })
    .join('');
  return `<div class="table-wrap"><table class="files">
<thead><tr><th scope="col">Fichier</th><th scope="col" class="num">Taille</th><th scope="col">Reçu le</th><th scope="col">Empreinte</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
<tbody>${rows}</tbody></table></div>`;
}

function dashboard(assets, { boxes, csrf, notice, freeBytes, retentionDays }) {
  const sections = boxes
    .map(
      ({ box, link, files, usage }) => `<section class="box${box.active ? '' : ' box-off'}" id="box-${box.id}" aria-labelledby="title-${box.id}">
<div class="box-head">
<h2 id="title-${box.id}">${esc(box.name)}</h2>
<span class="status">${box.active ? 'Lien actif' : 'Lien désactivé'}</span>
<span class="quiet usage">${files.length === 0 ? 'Aucun fichier' : `${files.length} fichier${files.length > 1 ? 's' : ''}, ${esc(formatBytes(usage))}`}</span>
</div>
${
  box.active
    ? `<div class="link-row"><input class="link" id="link-${box.id}" type="text" readonly value="${esc(link)}" aria-label="Lien de dépôt pour ${esc(box.name)}">
<button type="button" class="button secondary" data-copy="link-${box.id}">Copier le lien</button></div>`
    : ''
}
<div class="box-actions">
<form method="post" action="/admin/boxes/${box.id}/rotate" data-confirm="L'ancien lien ne fonctionnera plus. Créer un nouveau lien ?">${hidden(csrf)}<button class="button ghost small" type="submit">Remplacer le lien</button></form>
<form method="post" action="/admin/boxes/${box.id}/toggle">${hidden(csrf)}<button class="button ghost small" type="submit">${box.active ? 'Désactiver le lien' : 'Réactiver le lien'}</button></form>
</div>
${fileRows(files, csrf)}
</section>`,
    )
    .join('');

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
${notice ? `<p class="notice" role="status">${esc(notice)}</p>` : ''}
<form method="post" action="/admin/boxes" class="new-box">
${hidden(csrf)}
<div class="field"><label for="box-name">Nouveau lien de dépôt pour</label>
<input id="box-name" name="name" type="text" maxlength="80" required placeholder="Nom du client"></div>
<button class="button primary" type="submit">Créer le lien</button>
</form>
${sections || '<p class="quiet empty">Aucun espace de dépôt. Créez un lien pour votre premier client.</p>'}
<p class="quiet meta-line">Espace libre sur le serveur : ${esc(formatBytes(freeBytes))}. Suppression automatique ${esc(retentionDays)} jours après le dépôt.</p>
</main>`,
  });
}

module.exports = {
  esc,
  formatBytes,
  home,
  deposit,
  invalidLink,
  notFound,
  security,
  privacy,
  legal,
  login,
  dashboard,
};
