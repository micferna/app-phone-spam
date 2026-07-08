# App anti-spam téléphonique communautaire

Application perso (toi + proches) : chaque personne qui signale un numéro de
démarchage le partage automatiquement avec tout le groupe. À l'appel entrant,
l'app affiche « ⚠️ Signalé par N personnes » et laisse le choix de décrocher.

## Architecture

- **`backend/`** — API Node.js + SQLite auto-hébergée (Docker). ✅
  Déployée sur https://antispam-83384cb3.runship.fr (stack runship)
- **`app/`** — App mobile Flutter. Android fait ✅, iOS à venir.
  - Android : `SpamScreeningService` (rôle `ROLE_CALL_SCREENING`, Android 10+)
    interroge l'API à chaque appel entrant. Numéro suspect → alerte
    « ⚠️ Signalé par N personnes » ; numéro inconnu → notification discrète
    avec bouton **Signaler comme spam** qui prévient tout le groupe.
  - iOS : extension CallKit → liste synchronisée depuis `/api/numbers` (à venir).

### Compiler l'app Android

```bash
cd app && flutter build apk --release
# APK : app/build/app/outputs/flutter-apk/app-release.apk
```

Au premier lancement, renseigner l'URL du serveur et sa clé API personnelle,
puis appuyer sur **Activer** pour donner le rôle de filtrage d'appels.

## Démarrer le backend

```bash
cd backend
npm install
npm start                        # ou : docker compose up -d
```

Puis **initialisation au premier arrivé** (une seule fois, tant que le
serveur n'a aucun membre) :

```bash
curl -X POST http://localhost:3000/api/bootstrap \
  -H 'Content-Type: application/json' -d '{"name":"TonPrénom"}'
```

La réponse contient ta clé perso (`apiKey`) **et la clé admin
(`adminKey`), affichée cette unique fois** — seule son empreinte SHA-256
est conservée en base, elle n'apparaît jamais dans les logs. L'endpoint
renvoie ensuite 403 pour toujours. Les proches suivants : `npm run
add-user -- "Prénom"` en local, ou `POST /api/users` avec le header
`X-Admin-Key`. (Une variable d'environnement `ADMIN_KEY` reste
prioritaire si tu préfères la fournir toi-même.)

## API (header `X-Api-Key` obligatoire)

| Route | Rôle |
|---|---|
| `POST /api/reports` `{number, category?, comment?}` | Signaler un numéro |
| `DELETE /api/reports/:number` | Retirer son signalement |
| `GET /api/lookup/:number` | Vérif temps réel (appel entrant) |
| `GET /api/numbers` | Liste complète (synchro iOS) |
| `POST /api/join-requests` (public) | Demande d'adhésion (formulaire de la page d'accueil) |
| `GET /api/join-requests` (admin) | Lister les demandes en attente |
| `POST /api/join-requests/:id/approve` (admin) | Approuver → crée l'utilisateur + renvoie sa clé |
| `POST /api/join-requests/:id/reject` (admin) | Rejeter une demande |
| `POST /api/users` (header `X-Admin-Key`) | Créer un proche directement |

Un numéro est `suspicious` s'il est signalé par le groupe, présent dans une
liste publique importée, **ou** dans les préfixes ARCEP réservés au démarchage
(décision 2022-1583 : 0162, 0163, 0270, 0271, 0377, 0378, 0424, 0425, 0568,
0569, 0948, 0949 — détection intégrée, aucun import nécessaire).

## Listes publiques (mise à jour automatique)

Les sources déclarées dans `backend/sources.json` (spamtel, begone-fr) sont
téléchargées **au démarrage puis toutes les 24 h** — préfixes ARCEP et
opérateurs VoIP utilisés par les spammeurs restent donc à jour tout seuls.
Chaque refresh remplace entièrement la source (un numéro retiré en amont
disparaît aussi ici) ; une source vide ou en erreur conserve les données
précédentes. Désactivable avec `UPDATE_LISTS=0`.

```bash
npm run update-lists                                # forcer manuellement
node scripts/import.js liste.txt "source" "Label"   # importer un fichier local
```

Format fichier local : un numéro par ligne ; `0162*` = préfixe couvrant la plage.
