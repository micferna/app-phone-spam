# 📵 Anti-Spam Collectif

Application communautaire de lutte contre le démarchage téléphonique.
Le principe : **un seul signalement protège tout le groupe.** Quand un
membre signale un numéro, tous les téléphones du groupe sont prévenus dès
que ce numéro rappelle — et selon le réglage choisi, l'appel sonne avec une
alerte, est silencié (appel manqué), ou bloqué.

Pensé pour un usage entre proches (famille, amis, asso) : chaque membre a sa
propre clé, l'accès se fait sur invitation, et le serveur est
auto-hébergeable.

![CI](https://github.com/micferna/app-phone-spam/actions/workflows/ci.yml/badge.svg)
[![Télécharger l'APK](https://img.shields.io/github/v/release/micferna/app-phone-spam?label=T%C3%A9l%C3%A9charger%20l%27APK&color=c43c2e)](https://github.com/micferna/app-phone-spam/releases/latest)

## 📥 Télécharger

**[➜ Dernière version (APK Android)](https://github.com/micferna/app-phone-spam/releases/latest)** —
installe l'APK (sideload, Android 10+), renseigne l'URL de ton serveur et ta
clé personnelle, appuie sur **Activer**. Il te faut un backend auto-hébergé et
une clé (voir plus bas) : l'accès se fait sur invitation.

## Sommaire

- [Architecture](#architecture)
- [L'app Android](#lapp-android)
- [Le backend](#le-backend)
- [Rejoindre un groupe](#rejoindre-un-groupe)
- [Référence API](#référence-api)
- [Listes publiques auto-actualisées](#listes-publiques-auto-actualisées)
- [Sécurité](#sécurité)
- [Qualité & CI/CD](#qualité--cicd)

## Architecture

| Composant | Techno | État |
|---|---|---|
| `backend/` | Rust (axum) + SQLite, Docker | ✅ en ligne : https://antispam-03a9be84.runship.fr |
| `app/` (Android) | Flutter + Kotlin natif | ✅ APK compilable |
| `app/` (iOS) | Flutter + extension CallKit | ⏳ à venir (nécessite un Mac + compte Apple) |

Sur Android, le filtrage temps réel passe par un `CallScreeningService`
(rôle système `ROLE_CALL_SCREENING`, Android 10+) : à chaque appel entrant,
le téléphone interroge l'API et décide quoi faire. Sur iOS, l'API Apple
n'autorise pas le lookup en direct — il faudra précharger la liste via une
extension CallKit synchronisée sur `/api/numbers`.

> **⚠️ L'app n'est pas un dialer.** Elle ne remplace pas l'écran d'appel
> de ton téléphone (qui s'affiche normalement) : elle agit en arrière-plan
> comme « application d'identification des appels et des spams ». Son effet
> dépend du mode (voir plus bas) — et seul le mode **Bloquer** rejette
> réellement l'appel. Un numéro normal ne produit rien de visible :
> c'est attendu.

## L'app Android

### Compiler l'APK

```bash
cd app
flutter pub get
flutter build apk --release
# → app/build/app/outputs/flutter-apk/app-release.apk
```

### Premier lancement

1. Renseigner l'URL du serveur (préremplie) et sa **clé API personnelle**.
2. Appuyer sur **Activer** pour accorder le rôle de filtrage d'appels.
3. Choisir le comportement face aux appels suspects (modifiable à tout
   moment, effet immédiat).

### Les trois modes de filtrage

| Mode | Comportement sur un numéro suspect |
|---|---|
| **Alerter** | L'appel sonne + notification « ⚠️ Signalé par N personnes ». |
| **Silencieux** | Pas de sonnerie : l'appel devient un appel manqué, détail en notification. |
| **Bloquer** | L'appel est rejeté directement (l'appelant tombe sur la messagerie). |

En modes *Silencieux* et *Bloquer*, la décision attend la réponse du serveur
(≈ 4 s max, limite imposée par Android). **Si le serveur est injoignable,
l'appel sonne normalement** — on ne rate jamais un appel légitime à cause
d'une panne réseau.

Pour un numéro **inconnu** du groupe, une notification discrète propose un
bouton **« Signaler comme spam »** qui prévient tout le groupe en un tap,
sans ouvrir l'app.

### Autres fonctionnalités de l'app

- **Overlay plein écran** (mode Alerter) : sur un appel suspect, un écran
  rouge s'affiche par-dessus l'appel avec l'info riche (signalements,
  opérateur) et les actions Signaler / Raccrocher — façon Truecaller, sans
  être l'app téléphone par défaut.
- **Onglet Historique** : journal local des appels screenés (numéro,
  verdict, action, opérateur, heure) — pour voir après coup ce qui a été
  bloqué/alerté.
- **Exemption des contacts** (activée par défaut) : un numéro dans tes
  contacts n'est jamais filtré, pour éviter les faux positifs.
- **Cache hors-ligne** : la liste des numéros connus est synchronisée
  localement, donc le blocage/silence reste instantané et fiable même si le
  serveur est lent ou injoignable.
- **Détection des SMS suspects** (opt-in) : un `SmsReceiver` (permission
  `RECEIVE_SMS`) analyse chaque SMS entrant via `/api/check-sms`
  (vérification de l'expéditeur + heuristiques anti-smishing : liens
  raccourcis, marques usurpées, mots-clés d'arnaque) et **alerte** si
  suspect. Il ne peut pas *bloquer* le SMS (réservé à l'app SMS par défaut),
  seulement prévenir. Les SMS suspects apparaissent aussi dans l'Historique.

## Le backend

```bash
cd backend
cargo run --release              # ou : docker compose up -d
```

### Initialisation (public sérieux)

L'initialisation exige un secret de déploiement `BOOTSTRAP_TOKEN` (variable
d'environnement) pour éviter qu'un scanner ne revendique un serveur neuf.
Une seule fois, tant que le serveur n'a aucun membre :

```bash
curl -X POST http://localhost:3000/api/bootstrap \
  -H 'X-Bootstrap-Token: <BOOTSTRAP_TOKEN>' \
  -H 'Content-Type: application/json' -d '{"name":"TonPrénom"}'
```

La réponse contient ta clé perso (`apiKey`) **et la clé admin (`adminKey`),
affichée cette unique fois** — seule son empreinte SHA-256 est conservée en
base. L'endpoint se verrouille ensuite (403 définitif). Une variable
d'environnement `ADMIN_KEY` reste prioritaire pour l'accès admin.

### Ajouter des membres

- **À distance :** `POST /api/users` avec le header `X-Admin-Key`
- **En masse :** `POST /api/reports/bulk` avec le header `X-Admin-Key`
- **Via demandes d'adhésion :** voir ci-dessous

## Rejoindre un groupe

Le projet est **ouvert** : n'importe qui peut demander à rejoindre un groupe
depuis la page d'accueil du serveur, mais l'accès reste **sur invitation**
(une clé par membre, pour éviter les faux signalements de masse).

1. Le candidat remplit le formulaire de la page d'accueil (nom, moyen de
   contact, petit mot).
2. L'admin liste les demandes : `GET /api/join-requests` (header `X-Admin-Key`).
3. Il approuve (`POST /api/join-requests/:id/approve` → renvoie la clé à
   transmettre) ou rejette (`.../reject`).

Chaque demande est fortement limitée en débit et la file d'attente est
plafonnée (anti-flood).

## Référence API

Toutes les routes de données exigent le header `X-Api-Key` (clé personnelle).
Les routes admin exigent `X-Admin-Key`.

| Route | Accès | Rôle |
|---|---|---|
| `GET /` | public | Page de présentation + formulaire d'adhésion |
| `GET /api/health` | public | Test de disponibilité |
| `POST /api/bootstrap` | public (1×) | Initialisation du serveur |
| `POST /api/join-requests` | public | Déposer une demande d'adhésion |
| `POST /api/reports` `{number, category?, comment?}` | membre | Signaler un numéro |
| `DELETE /api/reports/:number` | membre | Retirer son propre signalement |
| `GET /api/lookup/:number` | membre | Vérification temps réel |
| `GET /api/numbers` | membre | Liste complète (synchro) |
| `GET /api/join-requests` | admin | Lister les demandes en attente |
| `POST /api/join-requests/:id/approve` | admin | Approuver → crée le membre + clé |
| `POST /api/join-requests/:id/reject` | admin | Rejeter une demande |
| `POST /api/users` `{name}` | admin | Créer un membre directement |
| `GET /api/users` | admin | Lister les membres (sans les clés) |
| `DELETE /api/users/{id}` | admin | Supprimer un membre + ses données (RGPD) |
| `POST /api/reports/bulk` `{numbers[], label?}` | admin | Import en masse (sans rate-limit) |
| `GET /api/operators` | membre | Réputation par opérateur (quels grossistes concentrent le spam) |
| `POST /api/check-sms` `{sender, text}` | membre | Analyse anti-smishing d'un SMS |
| `POST /api/feedback` `{number, wasSpam}` | membre | Retour « était-ce du spam ? » (affine le score) |
| `GET /api/federation/feed` | public | Flux des numéros confirmés (≥2 membres), pour la fédération |
| `GET /api/stats` | admin | Statistiques (dashboard) |
| `GET`·`POST /admin` | admin | Dashboard web (auth par clé) |
| `GET /api/alerts` | membre | Campagnes de démarchage actives |
| `POST /api/invites` | admin | Créer une invitation à usage unique (QR) |
| `POST /api/invite/redeem` `{token, name}` | public | Consommer une invitation → crée le membre |
| `GET /api/export` | admin | Télécharger un dump SQLite (backup off-site) |
| `POST /api/update-lists` | admin | Forcer la mise à jour des listes publiques |

Un numéro est marqué `suspicious` s'il est signalé par le groupe, présent
dans une liste publique importée, **ou** dans les préfixes ARCEP réservés au
démarchage (décision 2022-1583 : 0162, 0163, 0270, 0271, 0377, 0378, 0424,
0425, 0568, 0569, 0948, 0949 — détection intégrée, aucun import nécessaire).

### Fonctionnalités avancées

- **Score de confiance** (`suspicionScore` 0-100) combinant signalements,
  ARCEP, listes, réputation opérateur et **détection de campagne** (pic de
  signalements sur une plage dans les dernières 24 h → `campaignActive`).
- **Décision de blocage** (`suspicious`) : signaux fiables (signalement d'un
  membre de confiance, présence en liste, plage ARCEP) **+** deux heuristiques
  qui rattrapent les fixes 02/05 « neufs » utilisés pour contourner les plages
  ARCEP — une **campagne active** sur la plage, et un **score ≥ seuil**
  (`BLOCK_SCORE_THRESHOLD`, défaut 70 ; `0` désactive la clause de score). Ces
  heuristiques sont neutralisées si les membres ont majoritairement blanchi le
  numéro (« pas spam »), jamais un signal fiable.
- **Feedback utilisateur** : « était-ce du spam ? » tempère le score et réduit
  les faux positifs.
- **Auto-signalement** : les numéros bloqués/silenciés par l'app et encore
  inconnus du groupe sont remontés automatiquement (catégorie `demarchage` pour
  l'ARCEP, sinon `auto`) → nourrit la détection de campagne et la réputation.
  Désactivable dans les réglages.
- **Fédération** : un serveur expose `/api/federation/feed` (numéros confirmés
  par ≥ 2 membres, anonymisé) ; via `FEDERATION_PEERS` (env, URLs séparées par
  des virgules) un serveur importe le flux de ses pairs → effet réseau.
- **Dashboard admin** (`/admin`, clé admin) : KPIs, campagnes actives, top
  opérateurs, signalements récents, feedback.
- **Aide au 33700** : l'app propose de transférer un SMS suspect à la
  plateforme nationale (33700).
- **Onboarding par QR** : l'admin génère une invitation à usage unique (QR) ;
  le nouveau membre la scanne depuis l'écran de connexion → clé créée
  automatiquement, sans échange manuel.
- **Sauvegardes** : dump SQLite quotidien rotatif (7 jours) sur le volume +
  `GET /api/export` (admin) pour récupérer un backup off-site.
- **Bandeau « campagne active »** et **notification de mise à jour** (nouvelle
  release GitHub) dans l'app.
- **Réglages avancés** : « ne pas déranger la nuit » (silence des appels
  suspects sur une plage horaire), **filtrage des numéros masqués** (sonner /
  silencier / bloquer les appels anonymes, décision 100 % locale), **règles par
  catégorie** (filtrer VoIP 09 / international / surtaxé 08, décision locale
  hors-ligne, suit le mode de filtrage) et **whitelist** manuelle de numéros.

### Identification de l'opérateur (open data ARCEP MAJNUM)

Le lookup renvoie aussi l'**opérateur attributaire** du numéro
(`operator` = mnémonique ARCEP, `operatorName` = libellé si connu), via le
fichier public [MAJNUM](https://www.data.gouv.fr/datasets/ressources-en-numerotation-telephonique)
(~21 600 tranches, rechargé toutes les 24 h). Ça enrichit la notification
(« opérateur : Oxilog ») et révèle les patterns : le démarchage se
concentre sur une poignée de grossistes VoIP (Oxilog, Ubicentrex,
Manifone, IP Directions…). `GET /api/status` indique le nombre de tranches
chargées.

## Listes publiques auto-actualisées

Les sources (spamtel, begone-fr, définies dans `backend/src/lists.rs`) sont
téléchargées **au démarrage puis toutes les 24 h** depuis une allowlist
d'hôtes (anti-SSRF) : préfixes ARCEP et opérateurs VoIP utilisés par les
spammeurs restent à jour tout seuls. Chaque rafraîchissement remplace
entièrement la source ; une source vide ou en erreur conserve les données
précédentes. Désactivable avec `UPDATE_LISTS=0`. Mise à jour forcée :
`POST /api/update-lists` (admin). Un préfixe importé doit faire au moins
5 chiffres (garde-fou anti-empoisonnement si une source amont est compromise).

## Sécurité

Le serveur est conçu pour résister à un scan/abus automatisé dès sa mise en
ligne :

- **Sécurité mémoire** : backend en Rust (pas de null, pas de data race).
- **Authentification** par clé (192 bits d'entropie), comparaison à temps
  constant (`subtle::ConstantTimeEq`).
- **Clé admin** jamais stockée en clair — seul son hash SHA-256 est en base ;
  `ADMIN_KEY` et `BOOTSTRAP_TOKEN` fournis par variables d'environnement.
- **Rate-limiting** par IP (IP réelle via `CF-Connecting-IP` derrière
  Cloudflare) : plafond global, quotas serrés sur `bootstrap`, `reports`,
  `join-requests`, et **blocage après 20 clés invalides** (anti-bruteforce).
- **Validation stricte des entrées** : un signalement n'accepte qu'un numéro
  au format E.164 ; tout le reste (SQL, HTML, payloads) est rejeté en 400.
- **Anti-injection** : requêtes SQL exclusivement paramétrées (sqlx),
  échappement HTML systématique de toute donnée rendue dans une page.
- **En-têtes** `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`.
- **Corps de requête plafonné** (8 ko), longueurs de champs bornées.

## Qualité & CI/CD

Automatisations GitHub (dans `.github/`) :

- **`ci.yml`** — à chaque push/PR : `cargo fmt --check`, `cargo clippy`
  (warnings = erreurs), `cargo test` et `cargo audit` (échoue sur CVE) pour
  le backend ; `flutter analyze` + `flutter test` pour l'app.
- **`dependabot.yml`** — mises à jour hebdomadaires des dépendances (cargo,
  pub, Docker, GitHub Actions) + alertes de sécurité automatiques.

En local :

```bash
cd backend
cargo fmt --check                        # formatage
cargo clippy --all-targets -- -D warnings # lint strict
cargo test                               # tests unitaires
cargo audit                              # CVE des dépendances
cargo deny check advisories bans sources # supply-chain
```

## Licence & vie privée

Un numéro de téléphone est une donnée personnelle. Cette app est prévue pour
un usage privé entre proches ; toute diffusion plus large impliquerait un
mécanisme de contestation/retrait et une base légale RGPD. Le retrait d'un
signalement est possible à tout moment (`DELETE /api/reports/:number` ou le
bouton ↩️ dans l'app).
