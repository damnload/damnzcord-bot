// api.js — API REST + WebSocket Damnzcord
require('dotenv').config();

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const jwt        = require('jsonwebtoken');
const { stmts, supabase }              = require('./db');
const { verifyPassword, hashPassword } = require('./passwords');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'] }
});

const PORT   = process.env.PORT || process.env.API_PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'changeme';

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json());

// ─── Serveur par défaut (hardcodé) ────────────────────────────────────────────
const DEFAULT_SERVER = {
  id: 'damnzcord',
  name: 'Damnzcord',
  categories: [
    {
      name: 'Infos',
      channels: [
        { id: 'reglement',  name: 'règlement',  type: 'rules' },
        { id: 'annonces',   name: 'annonces',   type: 'announcement' },
      ],
    },
    {
      name: 'Général',
      channels: [
        { id: 'general',   name: 'général',    type: 'text' },
        { id: 'off-topic', name: 'off-topic',  type: 'text' },
        { id: 'partages',  name: 'partages',   type: 'text' },
      ],
    },
  ],
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateInviteCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 8; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

// Regroupe les channels d'un serveur en catégories
function groupChannels(channels) {
  const map = {};
  channels.forEach(ch => {
    if (!map[ch.category]) map[ch.category] = [];
    map[ch.category].push({
      id:    ch.id,
      name:  ch.name,
      type:  ch.type,
      topic: ch.topic || null,
    });
  });
  return Object.entries(map).map(([name, chs]) => ({ name, channels: chs }));
}

// ─── Middleware auth ──────────────────────────────────────────────────────────

function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token manquant.' });
  }
  try {
    req.user = jwt.verify(header.slice(7), SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide ou expiré.' });
  }
}

function verifyToken(token) {
  try { return jwt.verify(token, SECRET); }
  catch { return null; }
}

// Vérifie que l'utilisateur est membre du serveur
async function requireMember(req, res, next) {
  const serverId = parseInt(req.params.id, 10);
  if (isNaN(serverId)) return res.status(400).json({ error: 'ID serveur invalide.' });
  req.serverId = serverId;
  const member = await stmts.getServerMember({ server_id: serverId, discord_id: req.user.discord_id });
  if (!member) return res.status(403).json({ error: 'Accès refusé — non membre de ce serveur.' });
  req.member = member;
  next();
}

// Vérifie que l'utilisateur est admin ou owner
async function requireAdmin(req, res, next) {
  const member = req.member;
  if (!member || !['owner', 'admin'].includes(member.role)) {
    return res.status(403).json({ error: 'Permissions insuffisantes.' });
  }
  next();
}

// ─── Routes utilisateurs ─────────────────────────────────────────────────────

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
  }
  const user = await stmts.findByUsername(username);
  if (!user) return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
  await stmts.updateLastLogin({ discord_id: user.discord_id });
  const token = jwt.sign(
    { discord_id: user.discord_id, username: user.username },
    SECRET,
    { expiresIn: '7d' }
  );
  res.json({
    token,
    user: {
      username:      user.username,
      discord_id:    user.discord_id,
      avatar_url:    user.avatar_url,
      temp_password: user.temp_password,
    },
  });
});

app.get('/me', authRequired, async (req, res) => {
  const user = await stmts.findByDiscordId(req.user.discord_id);
  if (!user) return res.status(404).json({ error: 'Compte introuvable.' });
  const { password_hash, ...safe } = user;
  res.json(safe);
});

app.post('/change-password', authRequired, async (req, res) => {
  const { old_password, new_password } = req.body;
  if (!old_password || !new_password) {
    return res.status(400).json({ error: 'Ancien et nouveau mot de passe requis.' });
  }
  if (new_password.length < 8) {
    return res.status(400).json({ error: 'Le nouveau mot de passe doit faire au moins 8 caractères.' });
  }
  const user = await stmts.findByDiscordId(req.user.discord_id);
  if (!user) return res.status(404).json({ error: 'Compte introuvable.' });
  const ok = await verifyPassword(old_password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Ancien mot de passe incorrect.' });
  const hash = await hashPassword(new_password);
  await stmts.updatePassword({ discord_id: req.user.discord_id, password_hash: hash });
  res.json({ success: true });
});

app.post('/update-avatar', authRequired, async (req, res) => {
  const { avatar_url } = req.body;
  if (!avatar_url) return res.status(400).json({ error: 'URL requise.' });
  try {
    const u = new URL(avatar_url);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
  } catch {
    return res.status(400).json({ error: 'URL invalide.' });
  }
  await stmts.updateAvatar({ discord_id: req.user.discord_id, avatar_url });
  res.json({ success: true });
});

app.post('/update-profile', authRequired, async (req, res) => {
  const { display_name, nickname, bio, banner_url, status_text } = req.body;

  if (display_name && display_name.length > 32)
    return res.status(400).json({ error: 'Nom d\'affichage trop long (max 32 car.).' });
  if (nickname && nickname.length > 32)
    return res.status(400).json({ error: 'Prénom trop long (max 32 car.).' });
  if (bio && bio.length > 190)
    return res.status(400).json({ error: 'Bio trop longue (max 190 car.).' });
  if (status_text && status_text.length > 60)
    return res.status(400).json({ error: 'Statut trop long (max 60 car.).' });

  if (banner_url) {
    try {
      const u = new URL(banner_url);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
    } catch {
      return res.status(400).json({ error: 'URL de bannière invalide.' });
    }
  }

  await stmts.updateProfile({
    discord_id:   req.user.discord_id,
    display_name: display_name !== undefined ? (display_name || null) : undefined,
    nickname:     nickname     !== undefined ? (nickname     || null) : undefined,
    bio:          bio          !== undefined ? (bio          || null) : undefined,
    banner_url:   banner_url   !== undefined ? (banner_url   || null) : undefined,
    status_text:  status_text  !== undefined ? (status_text  || null) : undefined,
  });

  // Notifier les membres connectés si statut changé
  if (status_text !== undefined) {
    const { data: allMembers } = await supabase
      .from('users')
      .select('discord_id, username, avatar_url, display_name, nickname, bio, banner_url, status_text, created_at')
      .order('username');
    io.emit('members_update', allMembers || []);
  }

  res.json({ success: true });
});

// ─── Serveur par défaut ──────────────────────────────────────────────────────

app.get('/server', authRequired, (req, res) => {
  res.json(DEFAULT_SERVER);
});

app.get('/members', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('discord_id, username, avatar_url, display_name, nickname, bio, banner_url, status_text, created_at')
    .order('username');
  res.json(data || []);
});

app.get('/messages/:channelId', authRequired, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 500);
  const { data } = await supabase
    .from('messages')
    .select('*')
    .eq('channel_id', req.params.channelId)
    .is('server_id', null)
    .order('created_at', { ascending: true })
    .limit(limit);
  res.json(data || []);
});

// ─── Serveurs utilisateurs ───────────────────────────────────────────────────

// GET /servers — liste les serveurs de l'utilisateur
app.get('/servers', authRequired, async (req, res) => {
  const servers = await stmts.getUserServers(req.user.discord_id);
  res.json(servers);
});

// POST /servers — créer un serveur
app.post('/servers', authRequired, async (req, res) => {
  const { name, color } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom du serveur requis.' });
  if (name.trim().length > 50) return res.status(400).json({ error: 'Nom trop long (50 caractères max).' });

  let invite_code;
  let attempts = 0;
  do {
    invite_code = generateInviteCode();
    const existing = await stmts.getServerByInviteCode(invite_code);
    if (!existing) break;
    attempts++;
  } while (attempts < 5);

  const srv = await stmts.createServer({
    name: name.trim(),
    color: color || '#e8621a',
    invite_code,
    owner_id: req.user.discord_id,
  });
  if (!srv) return res.status(500).json({ error: 'Erreur lors de la création du serveur.' });

  await stmts.addServerMember({ server_id: srv.id, discord_id: req.user.discord_id, role: 'owner' });

  const defaultChannels = [
    { name: 'règlement',  type: 'rules',        category: 'Infos',   position: 0 },
    { name: 'annonces',   type: 'announcement', category: 'Infos',   position: 1 },
    { name: 'général',    type: 'text',         category: 'Général', position: 2 },
    { name: 'off-topic',  type: 'text',         category: 'Général', position: 3 },
  ];
  for (const ch of defaultChannels) {
    await stmts.createServerChannel({ server_id: srv.id, ...ch });
  }

  res.status(201).json({ ...srv, role: 'owner' });
});

// GET /servers/:id — structure du serveur (channels groupés par catégorie)
app.get('/servers/:id', authRequired, requireMember, async (req, res) => {
  const srv = await stmts.getServerById(req.serverId);
  if (!srv) return res.status(404).json({ error: 'Serveur introuvable.' });
  const channels = await stmts.getServerChannels(req.serverId);
  const categories = groupChannels(channels);
  res.json({
    id:          srv.id,
    name:        srv.name,
    color:       srv.color,
    icon_url:    srv.icon_url    || null,
    banner_url:  srv.banner_url  || null,
    description: srv.description || null,
    invite_code: srv.invite_code,
    owner_id:    srv.owner_id,
    categories,
    role:        req.member.role,
  });
});

// GET /servers/:id/members — membres du serveur
app.get('/servers/:id/members', authRequired, requireMember, async (req, res) => {
  const members = await stmts.getServerMembers(req.serverId);
  res.json(members);
});

// GET /servers/:id/messages/:channelId — messages d'un channel
app.get('/servers/:id/messages/:channelId', authRequired, requireMember, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });

  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) {
    return res.status(404).json({ error: 'Channel introuvable.' });
  }

  const msgs = await stmts.getServerMessages({ server_id: req.serverId, channel_id: channelId });
  res.json(msgs);
});

// PATCH /servers/:id — modifier le serveur (admin/owner)
app.patch('/servers/:id', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { name, color, icon_url, banner_url, description } = req.body;
  const updates = {};
  if (name?.trim()) {
    if (name.trim().length > 50) return res.status(400).json({ error: 'Nom trop long.' });
    updates.name = name.trim();
  }
  if (color) updates.color = color;

  // icon_url — null clears it
  if (icon_url !== undefined) {
    if (icon_url) {
      try {
        const u = new URL(icon_url);
        if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
      } catch {
        return res.status(400).json({ error: 'URL d\'icône invalide.' });
      }
      updates.icon_url = icon_url;
    } else {
      updates.icon_url = null;
    }
  }

  // banner_url — null clears it
  if (banner_url !== undefined) {
    if (banner_url) {
      try {
        const u = new URL(banner_url);
        if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
      } catch {
        return res.status(400).json({ error: 'URL de bannière invalide.' });
      }
      updates.banner_url = banner_url;
    } else {
      updates.banner_url = null;
    }
  }

  if (description !== undefined) {
    if (description && description.length > 120) {
      return res.status(400).json({ error: 'Description trop longue (max 120 car.).' });
    }
    updates.description = description || null;
  }

  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Rien à modifier.' });

  const updated = await stmts.updateServer(req.serverId, updates);
  io.to(`server:${req.serverId}`).emit('server_updated', { id: req.serverId, ...updates });
  res.json(updated);
});

// DELETE /servers/:id — supprimer le serveur (owner uniquement)
app.delete('/servers/:id', authRequired, requireMember, async (req, res) => {
  if (req.member.role !== 'owner') {
    return res.status(403).json({ error: 'Seul le propriétaire peut supprimer le serveur.' });
  }
  await stmts.deleteServer(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_deleted', { id: req.serverId });
  res.json({ success: true });
});

// POST /servers/:id/leave — quitter le serveur
app.post('/servers/:id/leave', authRequired, requireMember, async (req, res) => {
  if (req.member.role === 'owner') {
    return res.status(400).json({ error: 'Le propriétaire ne peut pas quitter son serveur. Supprimez-le ou transférez la propriété.' });
  }
  await stmts.removeServerMember({ server_id: req.serverId, discord_id: req.user.discord_id });
  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

// POST /servers/:id/channels — ajouter un channel (admin/owner)
app.post('/servers/:id/channels', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { name, type = 'text', category = 'Général' } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom du channel requis.' });
  if (name.trim().length > 32) return res.status(400).json({ error: 'Nom trop long (32 caractères max).' });
  if (!['text', 'announcement', 'rules'].includes(type)) {
    return res.status(400).json({ error: 'Type de channel invalide.' });
  }

  const existing = await stmts.getServerChannels(req.serverId);
  const position = existing.length;

  const ch = await stmts.createServerChannel({
    server_id: req.serverId,
    name: name.trim(),
    type,
    category: category.trim() || 'Général',
    position,
  });

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });

  res.status(201).json(ch);
});

// PATCH /servers/:id/channels/:channelId — modifier un channel (topic, nom, etc.)
app.patch('/servers/:id/channels/:channelId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });

  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) {
    return res.status(404).json({ error: 'Channel introuvable.' });
  }

  const { name, topic, category } = req.body;
  const updates = {};
  if (name !== undefined) {
    if (!name?.trim()) return res.status(400).json({ error: 'Nom requis.' });
    if (name.trim().length > 32) return res.status(400).json({ error: 'Nom trop long.' });
    updates.name = name.trim();
  }
  if (topic !== undefined) {
    if (topic && topic.length > 80) return res.status(400).json({ error: 'Sujet trop long (max 80 car.).' });
    updates.topic = topic || null;
  }
  if (category !== undefined) {
    updates.category = category?.trim() || 'Général';
  }

  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Rien à modifier.' });

  const updated = await stmts.updateServerChannel(channelId, updates);
  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });
  res.json(updated);
});

// POST /servers/:id/channels/reorder — réordonner les channels (admin/owner)
app.post('/servers/:id/channels/reorder', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { order } = req.body;
  if (!Array.isArray(order) || !order.length) {
    return res.status(400).json({ error: 'Tableau "order" requis.' });
  }

  const existing = await stmts.getServerChannels(req.serverId);
  const existingIds = new Set(existing.map(c => c.id));

  for (const item of order) {
    const id = parseInt(item.id, 10);
    if (isNaN(id) || !existingIds.has(id)) {
      return res.status(400).json({ error: `Channel ID invalide : ${item.id}` });
    }
    if (typeof item.position !== 'number') {
      return res.status(400).json({ error: 'Position doit être un nombre.' });
    }
  }

  for (const item of order) {
    await stmts.updateServerChannel(parseInt(item.id, 10), {
      position: item.position,
      category: item.category?.trim() || 'Général',
    });
  }

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });
  res.json({ success: true });
});

// DELETE /servers/:id/channels/:channelId — supprimer un channel (admin/owner)
app.delete('/servers/:id/channels/:channelId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });

  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) {
    return res.status(404).json({ error: 'Channel introuvable.' });
  }

  const all = await stmts.getServerChannels(req.serverId);
  if (all.length <= 1) return res.status(400).json({ error: 'Impossible de supprimer le dernier channel.' });

  await stmts.deleteServerChannel(channelId);

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });

  res.json({ success: true });
});

// ─── Rôles personnalisés ─────────────────────────────────────────────────────

// GET /servers/:id/roles
app.get('/servers/:id/roles', authRequired, requireMember, async (req, res) => {
  const roles = await stmts.getServerRoles(req.serverId);
  res.json(roles);
});

// PUT /servers/:id/roles/:roleKey — créer/mettre à jour un rôle (admin/owner)
app.put('/servers/:id/roles/:roleKey', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { roleKey } = req.params;
  if (!['moderator', 'vip', 'member'].includes(roleKey)) {
    return res.status(400).json({ error: 'Rôle non modifiable.' });
  }
  const { label, color, icon } = req.body;
  if (label && label.length > 20) return res.status(400).json({ error: 'Label trop long.' });
  if (icon && icon.length > 2) return res.status(400).json({ error: 'Icône trop longue (max 2 car.).' });

  const role = await stmts.upsertServerRole(req.serverId, roleKey, { label, color, icon });
  // Notifier les membres
  io.to(`server:${req.serverId}`).emit('roles_updated', { server_id: req.serverId });
  res.json(role);
});

// ─── Gestion des membres du serveur ─────────────────────────────────────────

// PATCH /servers/:id/members/:discordId/role — changer le rôle d'un membre
app.patch('/servers/:id/members/:discordId/role', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { discordId } = req.params;
  const { role } = req.body;

  const VALID_ROLES = ['owner', 'admin', 'moderator', 'vip', 'member'];
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide.' });
  }

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: discordId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });

  // Règles de permissions
  const myRole = req.member.role;
  if (target.role === 'owner') return res.status(403).json({ error: 'Impossible de modifier le rôle du propriétaire.' });
  if (myRole === 'admin' && target.role === 'admin') {
    return res.status(403).json({ error: 'Un admin ne peut pas modifier le rôle d\'un autre admin.' });
  }
  if (role === 'owner' && myRole !== 'owner') {
    return res.status(403).json({ error: 'Seul le propriétaire peut transférer la propriété.' });
  }

  await stmts.updateServerMemberRole({ server_id: req.serverId, discord_id: discordId, role });

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

// PATCH /servers/:id/members/:discordId/nickname — changer le surnom serveur
app.patch('/servers/:id/members/:discordId/nickname', authRequired, requireMember, async (req, res) => {
  const { discordId } = req.params;
  const { nickname } = req.body;

  const isSelf = String(discordId) === String(req.user.discord_id);
  const isAdmin = ['owner', 'admin'].includes(req.member.role);

  if (!isSelf && !isAdmin) {
    return res.status(403).json({ error: 'Permissions insuffisantes.' });
  }

  if (nickname && nickname.length > 32) {
    return res.status(400).json({ error: 'Surnom trop long (max 32 car.).' });
  }

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: discordId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });

  await stmts.updateServerMemberNickname({
    server_id: req.serverId,
    discord_id: discordId,
    server_nickname: nickname || null,
  });

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

// DELETE /servers/:id/members/:discordId — kick un membre (admin/owner)
app.delete('/servers/:id/members/:discordId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { discordId } = req.params;

  if (String(discordId) === String(req.user.discord_id)) {
    return res.status(400).json({ error: 'Vous ne pouvez pas vous exclure vous-même.' });
  }

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: discordId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });

  if (target.role === 'owner') {
    return res.status(403).json({ error: 'Impossible d\'exclure le propriétaire.' });
  }
  if (req.member.role === 'admin' && target.role === 'admin') {
    return res.status(403).json({ error: 'Un admin ne peut pas exclure un autre admin.' });
  }

  await stmts.removeServerMember({ server_id: req.serverId, discord_id: discordId });

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  // Notify kicked user
  io.to(`server:${req.serverId}`).emit('member_kicked', { discord_id: discordId, server_id: req.serverId });
  res.json({ success: true });
});

// ─── Invitations ─────────────────────────────────────────────────────────────

app.get('/invite/:code', authRequired, async (req, res) => {
  const srv = await stmts.getServerByInviteCode(req.params.code);
  if (!srv) return res.status(404).json({ error: 'Code d\'invitation invalide ou expiré.' });

  const memberCount = (await stmts.getServerMembers(srv.id)).length;
  const alreadyMember = await stmts.isServerMember({ server_id: srv.id, discord_id: req.user.discord_id });

  res.json({
    id:             srv.id,
    name:           srv.name,
    color:          srv.color,
    icon_url:       srv.icon_url || null,
    member_count:   memberCount,
    already_member: alreadyMember,
  });
});

app.post('/invite/:code', authRequired, async (req, res) => {
  const srv = await stmts.getServerByInviteCode(req.params.code);
  if (!srv) return res.status(404).json({ error: 'Code d\'invitation invalide ou expiré.' });

  const alreadyMember = await stmts.isServerMember({ server_id: srv.id, discord_id: req.user.discord_id });
  if (alreadyMember) return res.status(400).json({ error: 'Tu es déjà membre de ce serveur.' });

  await stmts.addServerMember({ server_id: srv.id, discord_id: req.user.discord_id, role: 'member' });

  const members = await stmts.getServerMembers(srv.id);
  io.to(`server:${srv.id}`).emit('server_members_update', { server_id: srv.id, members });

  res.json({ success: true, server_id: srv.id });
});


// ─── DM Routes ───────────────────────────────────────────────────────────────

app.get('/users/search', authRequired, async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) return res.json([]);
  const users = await stmts.searchUsers(q, req.user.discord_id);
  res.json(users);
});

app.get('/dm/conversations', authRequired, async (req, res) => {
  const convs = await stmts.getDmConversations(req.user.discord_id);
  res.json(convs);
});

app.get('/dm/:otherDiscordId', authRequired, async (req, res) => {
  const roomKey = stmts.dmRoomKey(req.user.discord_id, req.params.otherDiscordId);
  const msgs = await stmts.getDmMessages(roomKey);
  res.json(msgs);
});

// ─── Socket.io ────────────────────────────────────────────────────────────────

io.on('connection', async (socket) => {
  const token = socket.handshake.auth?.token;
  const user  = verifyToken(token);
  if (!user) { socket.disconnect(); return; }

  socket.user = user;
  console.log(`[WS] ${user.username} connecté`);

  const { data: allMembers } = await supabase
    .from('users')
    .select('discord_id, username, avatar_url, display_name, nickname, bio, banner_url, status_text, created_at')
    .order('username');
  io.emit('members_update', allMembers || []);

  socket.on('join_server', async ({ serverId }) => {
    if (!serverId) return;
    const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
    if (!isMember) return;
    socket.join(`server:${serverId}`);
  });

  socket.on('join_channel', (payload) => {
    Array.from(socket.rooms).forEach(room => {
      if (room !== socket.id && !room.startsWith('server:')) socket.leave(room);
    });

    if (typeof payload === 'string') {
      socket.join(payload);
    } else {
      const { serverId, channelId } = payload;
      socket.join(`${serverId}:${channelId}`);
    }
  });

  socket.on('rejoin', async ({ serverId, channelId }) => {
    if (serverId) {
      const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
      if (isMember) socket.join(`server:${serverId}`);
    }
    if (channelId) {
      Array.from(socket.rooms).forEach(room => {
        if (room !== socket.id && !room.startsWith('server:')) socket.leave(room);
      });
      if (serverId) {
        socket.join(`${serverId}:${channelId}`);
      } else {
        socket.join(String(channelId));
      }
    }
  });

  socket.on('send_message', async (payload) => {
    if (!payload?.content?.trim()) return;

    const { content, serverId, channelId } = payload;

    if (serverId && channelId) {
      const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
      if (!isMember) return;

      const ch = await stmts.getServerChannelById(channelId);
      if (!ch || ch.server_id !== serverId) return;
      if (ch.type === 'rules') return;
      if (ch.type === 'announcement') {
        const member = await stmts.getServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
        if (!member || !['owner', 'admin'].includes(member.role)) return;
      }

      const msg = await stmts.saveServerMessage({
        server_id:  serverId,
        channel_id: channelId,
        discord_id: socket.user.discord_id,
        username:   socket.user.username,
        content:    content.trim(),
      });
      if (msg) io.to(`${serverId}:${channelId}`).emit('new_message', msg);
    } else if (payload.channelId) {
      const { channelId: defChId } = payload;
      const { data } = await supabase
        .from('messages')
        .insert({
          channel_id: defChId,
          discord_id: socket.user.discord_id,
          username:   socket.user.username,
          content:    content.trim(),
        })
        .select()
        .single();
      if (data) io.to(defChId).emit('new_message', data);
    }
  });

  // ── Typing indicator ─────────────────────────────────────────────────────────

  socket.on('typing_start', async ({ channelId, serverId }) => {
    if (!channelId) return;
    const roomKey = serverId ? `${serverId}:${channelId}` : String(channelId);

    if (serverId) {
      const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
      if (!isMember) return;
    }

    socket.to(roomKey).emit('typing_start', {
      discord_id: socket.user.discord_id,
      username:   socket.user.username,
      channelId,
      serverId: serverId || null,
    });

    if (!socket._typingTimers) socket._typingTimers = {};
    clearTimeout(socket._typingTimers[roomKey]);
    socket._typingTimers[roomKey] = setTimeout(() => {
      socket.to(roomKey).emit('typing_stop', {
        discord_id: socket.user.discord_id,
        channelId,
        serverId: serverId || null,
      });
    }, 4000);
  });

  socket.on('typing_stop', ({ channelId, serverId }) => {
    if (!channelId) return;
    const roomKey = serverId ? `${serverId}:${channelId}` : String(channelId);
    clearTimeout(socket._typingTimers?.[roomKey]);
    if (socket._typingTimers) delete socket._typingTimers[roomKey];
    socket.to(roomKey).emit('typing_stop', {
      discord_id: socket.user.discord_id,
      channelId,
      serverId: serverId || null,
    });
  });


  // ── Messages Privés (DM) ─────────────────────────────────────────────────────

  socket.on('join_dm', async ({ otherDiscordId }) => {
    if (!otherDiscordId) return;
    const roomKey = stmts.dmRoomKey(socket.user.discord_id, otherDiscordId);
    Array.from(socket.rooms).forEach(room => {
      if (room.startsWith('dm:')) socket.leave(room);
    });
    socket.join(`dm:${roomKey}`);
  });

  socket.on('send_dm', async ({ otherDiscordId, content }) => {
    if (!otherDiscordId || !content?.trim()) return;
    const roomKey = stmts.dmRoomKey(socket.user.discord_id, otherDiscordId);
    const msg = await stmts.saveDmMessage({
      room:       roomKey,
      discord_id: socket.user.discord_id,
      username:   socket.user.username,
      content:    content.trim(),
    });
    if (!msg) return;
    io.to(`dm:${roomKey}`).emit('new_dm', { ...msg, otherDiscordId });
    const otherSockets = await io.fetchSockets();
    for (const s of otherSockets) {
      if (s.user?.discord_id === String(otherDiscordId) && !s.rooms.has(`dm:${roomKey}`)) {
        s.emit('new_dm', { ...msg, otherDiscordId: socket.user.discord_id });
      }
    }
  });

  socket.on('typing_start_dm', ({ otherDiscordId }) => {
    if (!otherDiscordId) return;
    const roomKey = stmts.dmRoomKey(socket.user.discord_id, otherDiscordId);
    socket.to(`dm:${roomKey}`).emit('typing_start_dm', {
      discord_id: socket.user.discord_id,
      username:   socket.user.username,
    });
    if (!socket._typingTimers) socket._typingTimers = {};
    const key = `dm:${roomKey}`;
    clearTimeout(socket._typingTimers[key]);
    socket._typingTimers[key] = setTimeout(() => {
      socket.to(`dm:${roomKey}`).emit('typing_stop_dm', { discord_id: socket.user.discord_id });
    }, 4000);
  });

  socket.on('typing_stop_dm', ({ otherDiscordId }) => {
    if (!otherDiscordId) return;
    const roomKey = stmts.dmRoomKey(socket.user.discord_id, otherDiscordId);
    const key = `dm:${roomKey}`;
    clearTimeout(socket._typingTimers?.[key]);
    if (socket._typingTimers) delete socket._typingTimers[key];
    socket.to(`dm:${roomKey}`).emit('typing_stop_dm', { discord_id: socket.user.discord_id });
  });

  socket.on('disconnect', async () => {
    if (socket._typingTimers) {
      Object.keys(socket._typingTimers).forEach(roomKey => {
        clearTimeout(socket._typingTimers[roomKey]);
        socket.to(roomKey).emit('typing_stop', {
          discord_id: socket.user.discord_id,
          channelId: roomKey.includes(':') ? roomKey.split(':')[1] : roomKey,
          serverId:  roomKey.includes(':') ? parseInt(roomKey.split(':')[0], 10) : null,
        });
      });
    }
    console.log(`[WS] ${socket.user?.username} déconnecté`);
    const { data: allMembers } = await supabase
      .from('users')
      .select('discord_id, username, avatar_url, display_name, nickname, bio, banner_url, status_text, created_at')
      .order('username');
    io.emit('members_update', allMembers || []);
  });
});

// ─── Démarrage ────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n✅  API + WebSocket Damnzcord sur http://localhost:${PORT}`);
});
