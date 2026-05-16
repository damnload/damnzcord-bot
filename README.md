# Damnzcord — Bot & API

Backend du projet Damnzcord. Ce dépôt fait tourner deux choses dans le même process Node.js :
- **Le bot Discord** — création et gestion des comptes via commandes `!`
- **L'API REST + WebSocket** — sert le site damnzcord.html (Express 5 + Socket.io)

Hébergé sur **Railway**.

---

## Stack

| Outil | Rôle |
|---|---|
| Node.js | Runtime |
| Express 5 | API REST |
| Socket.io | Temps réel (messages, typing, DMs) |
| discord.js v14 | Bot Discord |
| Supabase (PostgreSQL) | Base de données |
| bcrypt | Hachage des mots de passe |
| jsonwebtoken | Auth JWT (7 jours) |

---

## Structure des fichiers

```
damnzcord-bot/
├── server.js     ← Point d'entrée — lance api.js + index.js
├── api.js        ← Express + Socket.io
├── index.js      ← Bot Discord
├── db.js         ← Client Supabase + toutes les requêtes
├── passwords.js  ← Helpers bcrypt (hash, verify, generateTemp)
├── package.json
└── .env          ← Variables d'environnement (ne pas commiter)
```

---

## Variables d'environnement

Copier `.env.example` en `.env` et remplir les valeurs :

```env
DISCORD_TOKEN=      # Token du bot (Discord Developer Portal → Bot → Reset Token)
GUILD_ID=           # ID du serveur Discord (clic droit → Copier l'identifiant)
SUPABASE_URL=       # URL du projet Supabase
SUPABASE_KEY=       # Clé service_role Supabase (Settings → API)
JWT_SECRET=         # Clé secrète longue et aléatoire pour signer les JWT
BCRYPT_ROUNDS=10    # Nombre de rounds bcrypt (10 recommandé)
PORT=8080           # Géré automatiquement par Railway
```

---

## Installation locale

```bash
git clone https://github.com/ton-user/damnzcord-bot
cd damnzcord-bot
npm install
cp .env.example .env
# Remplir le .env
node server.js
```

---

## Déploiement sur Railway

1. Créer un nouveau projet Railway → **Deploy from GitHub repo**
2. Sélectionner ce dépôt
3. Dans **Variables**, ajouter toutes les clés du `.env`
4. Railway détecte automatiquement `npm start` (`node server.js`)
5. Aller dans **Settings → Networking → Generate Domain** pour obtenir l'URL publique
6. Copier cette URL dans le `vercel.json` du site

---

## Schéma Supabase

Exécuter ces requêtes dans **Supabase → SQL Editor** :

```sql
-- Utilisateurs
CREATE TABLE users (
  id            BIGSERIAL PRIMARY KEY,
  discord_id    TEXT NOT NULL UNIQUE,
  username      TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  avatar_url    TEXT DEFAULT NULL,
  display_name  TEXT DEFAULT NULL,
  nickname      TEXT DEFAULT NULL,
  bio           TEXT DEFAULT NULL,
  banner_url    TEXT DEFAULT NULL,
  temp_password BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ DEFAULT NULL
);

-- Messages des channels
CREATE TABLE messages (
  id         BIGSERIAL PRIMARY KEY,
  channel_id TEXT NOT NULL,
  server_id  BIGINT REFERENCES servers(id) ON DELETE CASCADE,
  discord_id TEXT NOT NULL,
  username   TEXT NOT NULL,
  content    TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Serveurs
CREATE TABLE servers (
  id           BIGSERIAL PRIMARY KEY,
  name         TEXT NOT NULL,
  color        TEXT NOT NULL DEFAULT '#e8621a',
  invite_code  TEXT NOT NULL UNIQUE,
  owner_id     TEXT NOT NULL REFERENCES users(discord_id) ON DELETE CASCADE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Membres des serveurs
CREATE TABLE server_members (
  server_id  BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  discord_id TEXT   NOT NULL REFERENCES users(discord_id) ON DELETE CASCADE,
  role       TEXT   NOT NULL DEFAULT 'member'
               CHECK (role IN ('owner', 'admin', 'moderator', 'vip', 'member')),
  joined_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (server_id, discord_id)
);

-- Channels des serveurs
CREATE TABLE server_channels (
  id         BIGSERIAL PRIMARY KEY,
  server_id  BIGINT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name       TEXT   NOT NULL,
  type       TEXT   NOT NULL DEFAULT 'text'
               CHECK (type IN ('text', 'announcement', 'rules')),
  category   TEXT   NOT NULL DEFAULT 'Général',
  position   INT    NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Messages privés (supprimés automatiquement après 14 jours)
CREATE TABLE dm_messages (
  id         BIGSERIAL PRIMARY KEY,
  room       TEXT NOT NULL,  -- format : "discordId1:discordId2" (triés)
  discord_id TEXT NOT NULL REFERENCES users(discord_id) ON DELETE CASCADE,
  username   TEXT NOT NULL,
  content    TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index
CREATE INDEX idx_messages_server_channel ON messages(server_id, channel_id);
CREATE INDEX idx_dm_messages_room        ON dm_messages(room, created_at DESC);
CREATE INDEX idx_dm_messages_created_at  ON dm_messages(created_at);
CREATE INDEX idx_server_channels_server  ON server_channels(server_id, position);
CREATE INDEX idx_server_members_discord  ON server_members(discord_id);

-- Suppression automatique des DMs après 14 jours
-- Activer pg_cron d'abord : Supabase → Database → Extensions → pg_cron
SELECT cron.schedule(
  'purge-dm-messages',
  '0 3 * * *',
  $$DELETE FROM dm_messages WHERE created_at < NOW() - INTERVAL '14 days'$$
);
```

---

## API REST

Toutes les routes (sauf `/login`) nécessitent le header :
```
Authorization: Bearer <jwt_token>
```

### Authentification
| Méthode | Route | Description |
|---|---|---|
| POST | `/login` | Connexion — retourne un JWT |
| GET | `/me` | Infos du compte connecté |
| POST | `/change-password` | Changer le mot de passe |
| POST | `/update-avatar` | Mettre à jour l'avatar |
| POST | `/update-profile` | Modifier display_name, nickname, bio, banner_url |

### Serveur par défaut
| Méthode | Route | Description |
|---|---|---|
| GET | `/server` | Structure du serveur Damnzcord (hardcodé) |
| GET | `/members` | Liste tous les membres |
| GET | `/messages/:channelId` | 50–200 derniers messages d'un channel |

### Serveurs utilisateurs
| Méthode | Route | Description |
|---|---|---|
| GET | `/servers` | Serveurs de l'utilisateur connecté |
| POST | `/servers` | Créer un serveur |
| GET | `/servers/:id` | Structure d'un serveur (channels par catégorie) |
| PATCH | `/servers/:id` | Modifier nom/couleur (admin/owner) |
| DELETE | `/servers/:id` | Supprimer un serveur (owner) |
| POST | `/servers/:id/leave` | Quitter un serveur |
| GET | `/servers/:id/members` | Membres du serveur |
| GET | `/servers/:id/messages/:channelId` | Messages d'un channel |
| POST | `/servers/:id/channels` | Créer un channel (admin/owner) |
| POST | `/servers/:id/channels/reorder` | Réordonner les channels (admin/owner) |
| DELETE | `/servers/:id/channels/:channelId` | Supprimer un channel (admin/owner) |

### Invitations
| Méthode | Route | Description |
|---|---|---|
| GET | `/invite/:code` | Aperçu du serveur sans rejoindre |
| POST | `/invite/:code` | Rejoindre via code d'invitation |

### Messages Privés
| Méthode | Route | Description |
|---|---|---|
| GET | `/dm/conversations` | Liste des conversations DM |
| GET | `/dm/:otherDiscordId` | 50 derniers messages avec un utilisateur |
| GET | `/users/search?q=xxx` | Rechercher un utilisateur par pseudo |

---

## WebSocket (Socket.io)

Connexion avec auth JWT :
```js
const socket = io('https://ton-url.railway.app', {
  auth: { token: 'Bearer eyJ...' }
});
```

### Événements émis par le client
| Événement | Payload | Description |
|---|---|---|
| `join_server` | `{ serverId }` | Rejoindre la room d'un serveur |
| `join_channel` | `{ serverId, channelId }` ou `channelId` (string) | Rejoindre un channel |
| `rejoin` | `{ serverId, channelId }` | Réintégrer les rooms après reconnexion |
| `send_message` | `{ serverId, channelId, content }` | Envoyer un message dans un channel |
| `join_dm` | `{ otherDiscordId }` | Rejoindre une room DM |
| `send_dm` | `{ otherDiscordId, content }` | Envoyer un message privé |
| `typing_start` | `{ channelId, serverId? }` | Début de saisie dans un channel |
| `typing_stop` | `{ channelId, serverId? }` | Fin de saisie dans un channel |
| `typing_start_dm` | `{ otherDiscordId }` | Début de saisie dans un DM |
| `typing_stop_dm` | `{ otherDiscordId }` | Fin de saisie dans un DM |

### Événements émis par le serveur
| Événement | Description |
|---|---|
| `new_message` | Nouveau message dans un channel |
| `new_dm` | Nouveau message privé |
| `members_update` | Mise à jour de la liste des membres (serveur par défaut) |
| `server_members_update` | Mise à jour des membres d'un serveur utilisateur |
| `server_updated` | Nom ou couleur d'un serveur modifié |
| `server_deleted` | Serveur supprimé |
| `channels_updated` | Channels d'un serveur modifiés ou réordonnés |
| `typing_start` | Quelqu'un tape dans un channel |
| `typing_stop` | Quelqu'un a arrêté de taper |
| `typing_start_dm` | Quelqu'un tape dans un DM |
| `typing_stop_dm` | Quelqu'un a arrêté de taper dans un DM |

---

## Commandes du bot Discord

Le bot écoute les messages préfixés par `!` sur le serveur Discord configuré.

| Commande | Description |
|---|---|
| `!createaccount` | Crée un compte Damnzcord lié à l'ID Discord. Le mot de passe temporaire est envoyé en DM. |
| `!resetpassword` | Génère un nouveau mot de passe temporaire et l'envoie en DM. |
| `!setavatar <url>` | Met à jour la photo de profil avec un lien image direct (http/https). |
| `!moncompte` | Envoie les informations du compte en DM (pseudo, ID Discord, statut du mot de passe, avatar). |
| `!help` | Affiche la liste des commandes disponibles. |

> Le bot nécessite d'avoir accès aux **messages privés** des membres pour fonctionner.

---

## Rôles des serveurs

| Rôle | Permissions |
|---|---|
| `owner` | Toutes les permissions, ne peut pas quitter son serveur |
| `admin` | Modifier le serveur, gérer les channels, écrire dans les annonces |
| `moderator` | Membre avec badge, pas de permissions supplémentaires actuellement |
| `vip` | Membre avec badge |
| `member` | Lecture/écriture dans les channels text, lecture seule dans les annonces et règlement |

> Les channels `rules` sont en lecture seule pour **tout le monde** sans exception.  
> Les channels `announcement` sont en lecture seule sauf pour les `owner` et `admin`.

---

## Confidentialité

- Aucune adresse email ni numéro de téléphone collecté
- Authentification via ID Discord uniquement
- Mots de passe hachés avec bcrypt, jamais stockés en clair
- Messages privés supprimés automatiquement après 14 jours (pg_cron)
- Tokens JWT expirés après 7 jours
