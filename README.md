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
![CodeQL](https://github.com/micferna/app-phone-spam/actions/workflows/codeql.yml/badge.svg)

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
| `backend/` | Node.js (Express) + SQLite, Docker | ✅ en ligne : https://antispam-83384cb3.runship.fr |
| `app/` (Android) | Flutter + Kotlin natif | ✅ APK compilable |
| `app/` (iOS) | Flutter + extension CallKit | ⏳ à venir (nécessite un Mac + compte Apple) |

Sur Android, le filtrage temps réel passe par un `CallScreeningService`
(rôle système `ROLE_CALL_SCREENING`, Android 10+) : à chaque appel entrant,
le téléphone interroge l'API et décide quoi faire. Sur iOS, l'API Apple
n'autorise pas le lookup en direct — il faudra précharger la liste via une
extension CallKit synchronisée sur `/api/numbers`.

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

## Le backend

```bash
cd backend
npm install
npm start                        # ou : docker compose up -d
```

### Initialisation « premier arrivé »

Une seule fois, tant que le serveur n'a aucun membre :

```bash
curl -X POST http://localhost:3000/api/bootstrap \
  -H 'Content-Type: application/json' -d '{"name":"TonPrénom"}'
```

La réponse contient ta clé perso (`apiKey`) **et la clé admin (`adminKey`),
affichée cette unique fois** — seule son empreinte SHA-256 est conservée en
base, elle n'apparaît jamais dans les logs. L'endpoint se verrouille ensuite
(403 définitif). Une variable d'environnement `ADMIN_KEY` reste prioritaire
si tu préfères fournir la clé toi-même.

### Ajouter des membres

- **En local :** `npm run add-user -- "Prénom"`
- **À distance :** `POST /api/users` avec le header `X-Admin-Key`
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
| `POST /api/update-lists` | admin | Forcer la mise à jour des listes publiques |

Un numéro est marqué `suspicious` s'il est signalé par le groupe, présent
dans une liste publique importée, **ou** dans les préfixes ARCEP réservés au
démarchage (décision 2022-1583 : 0162, 0163, 0270, 0271, 0377, 0378, 0424,
0425, 0568, 0569, 0948, 0949 — détection intégrée, aucun import nécessaire).

## Listes publiques auto-actualisées

Les sources déclarées dans `backend/sources.json` (spamtel, begone-fr) sont
téléchargées **au démarrage puis toutes les 24 h** : préfixes ARCEP et
opérateurs VoIP utilisés par les spammeurs restent à jour tout seuls. Chaque
rafraîchissement remplace entièrement la source (un numéro retiré en amont
disparaît aussi ici) ; une source vide ou en erreur conserve les données
précédentes. Désactivable avec `UPDATE_LISTS=0`.

```bash
npm run update-lists                                # forcer manuellement
node scripts/import.js liste.txt "source" "Label"   # importer un fichier local
```

Format d'un fichier local : un numéro par ligne ; `0162*` = préfixe couvrant
toute la plage. Un préfixe importé doit faire au moins 5 chiffres (garde-fou
anti-empoisonnement si une source amont est compromise).

## Sécurité

Le serveur est conçu pour résister à un scan/abus automatisé dès sa mise en
ligne :

- **Authentification** par clé (192 bits d'entropie), comparaison à temps
  constant (`timingSafeEqual`).
- **Clé admin** jamais stockée ni journalisée en clair — seul son hash
  SHA-256 est en base.
- **Rate-limiting** par IP (IP réelle via `CF-Connecting-IP` derrière
  Cloudflare) : plafond global, quotas serrés sur `bootstrap`, `reports`,
  `join-requests`, et **blocage après 20 clés invalides** (anti-bruteforce).
- **Validation stricte des entrées** : un signalement n'accepte qu'un numéro
  au format E.164 ; tout le reste (SQL, HTML, payloads) est rejeté en 400.
- **Anti-XSS** : requêtes SQL exclusivement paramétrées, échappement HTML
  systématique de toute donnée utilisateur rendue dans une page.
- **En-têtes** `Content-Security-Policy` (aucun script, aucune ressource
  externe), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.
- **Corps de requête plafonné** (8 ko), longueurs de champs bornées.

## Qualité & CI/CD

Automatisations GitHub (dans `.github/`) :

- **`ci.yml`** — à chaque push/PR : lint ESLint + tests + `npm audit`
  (échoue sur CVE haute/critique) pour le backend ; `flutter analyze` +
  `flutter test` pour l'app.
- **`codeql.yml`** — analyse SAST CodeQL (requêtes *security-and-quality*),
  sur push/PR et en rescan hebdomadaire.
- **`dependabot.yml`** — mises à jour hebdomadaires des dépendances (npm,
  pub, Docker, GitHub Actions) + alertes de sécurité automatiques.

En local :

```bash
cd backend
npm run lint      # ESLint (bonnes pratiques)
npm test          # tests unitaires (node:test)
npm audit         # vulnérabilités des dépendances
```

## Licence & vie privée

Un numéro de téléphone est une donnée personnelle. Cette app est prévue pour
un usage privé entre proches ; toute diffusion plus large impliquerait un
mécanisme de contestation/retrait et une base légale RGPD. Le retrait d'un
signalement est possible à tout moment (`DELETE /api/reports/:number` ou le
bouton ↩️ dans l'app).
