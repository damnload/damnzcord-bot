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

app.set('io', io);

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
app.use(express.json({ limit: '10mb' })); // augmenté pour les stickers base64

// ─── Serveur par défaut (hardcodé) ────────────────────────────────────────────
const DEFAULT_SERVER = {
  id: 'damnzcord',
  name: 'Damnzcord',
  categories: [
    {
      name: 'Infos',
      channels: [
        { id: 'reglement', name: 'règlement',  type: 'rules' },
        { id: 'annonces',  name: 'annonces',   type: 'announcement' },
      ],
    },
    {
      name: 'Général',
      channels: [
        { id: 'general',   name: 'général',   type: 'text' },
        { id: 'off-topic', name: 'off-topic', type: 'text' },
        { id: 'partages',  name: 'partages',  type: 'text' },
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

function groupChannels(channels) {
  const map = {};
  channels.forEach(ch => {
    if (!map[ch.category]) map[ch.category] = [];
    map[ch.category].push({ id: ch.id, name: ch.name, type: ch.type, topic: ch.topic || null });
  });
  return Object.entries(map).map(([name, chs]) => ({ name, channels: chs }));
}

// Log helper — appelé dans tous les handlers qui modifient le serveur
async function logAction(server_id, type, description, actor_id, actor_username, target_id = null, metadata = {}) {
  try {
    await stmts.createLog({ server_id, type, description, actor_id, actor_username, target_id, metadata });
  } catch (e) {
    console.error('[LOG ERROR]', e.message);
  }
}

// Catégories de types de logs pour le filtre frontend
const LOG_CATEGORIES = {
  member:     ['member_joined', 'member_left', 'member_kicked', 'member_banned', 'ban_lifted'],
  role:       ['role_created', 'role_updated', 'role_deleted', 'role_assigned', 'role_removed'],
  channel:    ['channel_created', 'channel_deleted', 'channel_updated'],
  moderation: ['member_kicked', 'member_banned', 'ban_lifted', 'message_deleted'],
  message:    ['message_deleted'],
  invite:     ['invite_created', 'invite_revoked'],
};

// ─── Middleware auth ──────────────────────────────────────────────────────────

function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token manquant.' });
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

async function requireMember(req, res, next) {
  const serverId = parseInt(req.params.id, 10);
  if (isNaN(serverId)) return res.status(400).json({ error: 'ID serveur invalide.' });
  req.serverId = serverId;
  const member = await stmts.getServerMember({ server_id: serverId, discord_id: req.user.discord_id });
  if (!member) return res.status(403).json({ error: 'Accès refusé — non membre de ce serveur.' });
  req.member = member;
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.member || !['owner', 'admin'].includes(req.member.role)) {
    return res.status(403).json({ error: 'Permissions insuffisantes.' });
  }
  next();
}

async function requireModerator(req, res, next) {
  if (!req.member || !['owner', 'admin', 'moderator'].includes(req.member.role)) {
    return res.status(403).json({ error: 'Permissions insuffisantes.' });
  }
  next();
}

async function requireOwner(req, res, next) {
  if (!req.member || req.member.role !== 'owner') {
    return res.status(403).json({ error: 'Seul le propriétaire peut effectuer cette action.' });
  }
  next();
}

// ─── Routes utilisateurs ─────────────────────────────────────────────────────

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
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
  if (!old_password || !new_password) return res.status(400).json({ error: 'Ancien et nouveau mot de passe requis.' });
  if (new_password.length < 8) return res.status(400).json({ error: 'Le nouveau mot de passe doit faire au moins 8 caractères.' });
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
  if (display_name && display_name.length > 32) return res.status(400).json({ error: 'Nom d\'affichage trop long (max 32 car.).' });
  if (nickname     && nickname.length     > 32) return res.status(400).json({ error: 'Prénom trop long (max 32 car.).' });
  if (bio          && bio.length          > 190) return res.status(400).json({ error: 'Bio trop longue (max 190 car.).' });
  if (status_text  && status_text.length  > 60)  return res.status(400).json({ error: 'Statut trop long (max 60 car.).' });
  if (banner_url) {
    try {
      const u = new URL(banner_url);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
    } catch { return res.status(400).json({ error: 'URL de bannière invalide.' }); }
  }
  await stmts.updateProfile({
    discord_id:   req.user.discord_id,
    display_name: display_name !== undefined ? (display_name || null) : undefined,
    nickname:     nickname     !== undefined ? (nickname     || null) : undefined,
    bio:          bio          !== undefined ? (bio          || null) : undefined,
    banner_url:   banner_url   !== undefined ? (banner_url   || null) : undefined,
    status_text:  status_text  !== undefined ? (status_text  || null) : undefined,
  });
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

app.get('/server', authRequired, (req, res) => res.json(DEFAULT_SERVER));

app.get('/members', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('discord_id, username, avatar_url, display_name, nickname, bio, banner_url, status_text, created_at')
    .order('username');
  res.json(data || []);
});

app.get('/messages/:channelId', authRequired, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 200, 500);
  const since = req.query.since ? parseInt(req.query.since, 10) : null;
  let query = supabase
    .from('messages')
    .select('*')
    .eq('channel_id', req.params.channelId)
    .is('server_id', null)
    .order('created_at', { ascending: true })
    .limit(limit);
  if (since && !isNaN(since)) query = query.gt('id', since);
  const { data } = await query;
  res.json(data || []);
});

// ─── Serveurs ────────────────────────────────────────────────────────────────

app.get('/servers', authRequired, async (req, res) => {
  const servers = await stmts.getUserServers(req.user.discord_id);
  res.json(servers);
});

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
  } while (++attempts < 5);

  const srv = await stmts.createServer({ name: name.trim(), color: color || '#e8621a', invite_code, owner_id: req.user.discord_id });
  if (!srv) return res.status(500).json({ error: 'Erreur lors de la création du serveur.' });

  await stmts.addServerMember({ server_id: srv.id, discord_id: req.user.discord_id, role: 'owner' });

  const defaultChannels = [
    { name: 'règlement',  type: 'rules',        category: 'Infos',   position: 0 },
    { name: 'annonces',   type: 'announcement', category: 'Infos',   position: 1 },
    { name: 'général',    type: 'text',         category: 'Général', position: 2 },
    { name: 'off-topic',  type: 'text',         category: 'Général', position: 3 },
  ];
  for (const ch of defaultChannels) await stmts.createServerChannel({ server_id: srv.id, ...ch });

  res.status(201).json({ ...srv, role: 'owner' });
});

// GET /servers/:id — structure complète du serveur
app.get('/servers/:id', authRequired, requireMember, async (req, res) => {
  const srv = await stmts.getServerById(req.serverId);
  if (!srv) return res.status(404).json({ error: 'Serveur introuvable.' });
  const channels = await stmts.getServerChannels(req.serverId);
  const categories = groupChannels(channels);
  res.json({
    id:                  srv.id,
    name:                srv.name,
    color:               srv.color,
    icon_url:            srv.icon_url            || null,
    banner_url:          srv.banner_url          || null,
    description:         srv.description         || null,
    tag:                 srv.tag                 || null,
    subject:             srv.subject             || null,
    vibe:                srv.vibe                || null,
    language:            srv.language            || null,
    access_mode:         srv.access_mode         || 'open',
    welcome_enabled:     srv.welcome_enabled     || false,
    welcome_channel_id:  srv.welcome_channel_id  || null,
    welcome_message:     srv.welcome_message      || null,
    auto_role_id:        srv.auto_role_id         || null,
    rules:               srv.rules               || null,
    rules_required:      srv.rules_required      || false,
    block_links:         srv.block_links         || false,
    word_filter:         srv.word_filter         || false,
    banned_words:        srv.banned_words        || null,
    invite_code:         srv.invite_code,
    owner_id:            srv.owner_id,
    categories,
    role:                req.member.role,
  });
});

// PATCH /servers/:id — modifier les infos de base (nom, couleur, icône, bannière, description)
app.patch('/servers/:id', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { name, color, icon_url, banner_url, description } = req.body;
  const updates = {};

  if (name !== undefined) {
    if (!name?.trim()) return res.status(400).json({ error: 'Nom requis.' });
    if (name.trim().length > 50) return res.status(400).json({ error: 'Nom trop long.' });
    updates.name = name.trim();
  }
  if (color) updates.color = color;

  if (icon_url !== undefined) {
    if (icon_url) {
      try { const u = new URL(icon_url); if (!['http:', 'https:'].includes(u.protocol)) throw new Error(); }
      catch { return res.status(400).json({ error: 'URL d\'icône invalide.' }); }
      updates.icon_url = icon_url;
    } else { updates.icon_url = null; }
  }

  if (banner_url !== undefined) {
    if (banner_url) {
      try { const u = new URL(banner_url); if (!['http:', 'https:'].includes(u.protocol)) throw new Error(); }
      catch { return res.status(400).json({ error: 'URL de bannière invalide.' }); }
      updates.banner_url = banner_url;
    } else { updates.banner_url = null; }
  }

  if (description !== undefined) {
    if (description && description.length > 120) return res.status(400).json({ error: 'Description trop longue (max 120 car.).' });
    updates.description = description || null;
  }

  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Rien à modifier.' });

  const updated = await stmts.updateServer(req.serverId, updates);
  io.to(`server:${req.serverId}`).emit('server_updated', { id: req.serverId, ...updates });
  res.json(updated);
});

// PATCH /servers/:id/settings — tag, identité, accueil, modération, access_mode
app.patch('/servers/:id/settings', authRequired, requireMember, requireAdmin, async (req, res) => {
  const ALLOWED = [
    'tag', 'subject', 'vibe', 'language', 'access_mode',
    'block_links', 'word_filter', 'banned_words',
    'welcome_enabled', 'welcome_channel_id', 'welcome_message',
    'auto_role_id', 'rules', 'rules_required',
  ];
  const updates = {};
  for (const key of ALLOWED) {
    if (req.body[key] !== undefined) updates[key] = req.body[key];
  }

  // Sanitize tag
  if (updates.tag !== undefined) {
    updates.tag = updates.tag
      ? updates.tag.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 5) || null
      : null;
  }

  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Rien à modifier.' });

  const updated = await stmts.updateServer(req.serverId, updates);
  io.to(`server:${req.serverId}`).emit('server_updated', { id: req.serverId, ...updates });
  res.json({ success: true, ...updated });
});

// DELETE /servers/:id — supprimer le serveur (owner uniquement)
app.delete('/servers/:id', authRequired, requireMember, requireOwner, async (req, res) => {
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
  await logAction(req.serverId, 'member_left', `${req.user.username} a quitté le serveur`, req.user.discord_id, req.user.username);
  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

// POST /servers/:id/transfer — transférer la propriété (owner uniquement)
app.post('/servers/:id/transfer', authRequired, requireMember, requireOwner, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Pseudo requis.' });

  const targetUser = await stmts.findByUsername(username);
  if (!targetUser) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  const targetMember = await stmts.getServerMember({ server_id: req.serverId, discord_id: targetUser.discord_id });
  if (!targetMember) return res.status(404).json({ error: 'Cet utilisateur n\'est pas membre du serveur.' });

  // Transférer : target → owner, moi → admin
  await stmts.updateServerMemberRole({ server_id: req.serverId, discord_id: targetUser.discord_id, role: 'owner' });
  await stmts.updateServerMemberRole({ server_id: req.serverId, discord_id: req.user.discord_id,   role: 'admin' });
  await stmts.updateServer(req.serverId, { owner_id: targetUser.discord_id });

  await logAction(req.serverId, 'role_assigned', `Propriété transférée à @${username}`, req.user.discord_id, req.user.username, targetUser.discord_id);

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

// ─── Membres ──────────────────────────────────────────────────────────────────

app.get('/servers/:id/members', authRequired, requireMember, async (req, res) => {
  const members = await stmts.getServerMembers(req.serverId);
  res.json(members);
});

app.patch('/servers/:id/members/:discordId/role', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { discordId } = req.params;
  const { role } = req.body;
  const VALID = ['admin', 'moderator', 'vip', 'member'];
  if (!VALID.includes(role)) return res.status(400).json({ error: 'Rôle invalide.' });

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: discordId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'Impossible de modifier le rôle du propriétaire.' });
  if (req.member.role === 'admin' && target.role === 'admin') return res.status(403).json({ error: 'Un admin ne peut pas modifier le rôle d\'un autre admin.' });

  const oldRole = target.role;
  await stmts.updateServerMemberRole({ server_id: req.serverId, discord_id: discordId, role });
  await logAction(req.serverId, 'role_assigned', `Rôle de @${target.username} changé : ${oldRole} → ${role}`, req.user.discord_id, req.user.username, discordId);

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

app.patch('/servers/:id/members/:discordId/nickname', authRequired, requireMember, async (req, res) => {
  const { discordId } = req.params;
  const { nickname } = req.body;
  const isSelf  = String(discordId) === String(req.user.discord_id);
  const isAdmin = ['owner', 'admin'].includes(req.member.role);
  if (!isSelf && !isAdmin) return res.status(403).json({ error: 'Permissions insuffisantes.' });
  if (nickname && nickname.length > 32) return res.status(400).json({ error: 'Surnom trop long (max 32 car.).' });

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: discordId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });

  await stmts.updateServerMemberNickname({ server_id: req.serverId, discord_id: discordId, server_nickname: nickname || null });
  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  res.json({ success: true });
});

// DELETE /servers/:id/members/:discordId — kick
app.delete('/servers/:id/members/:discordId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { discordId } = req.params;
  if (String(discordId) === String(req.user.discord_id)) return res.status(400).json({ error: 'Vous ne pouvez pas vous exclure vous-même.' });

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: discordId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'Impossible d\'exclure le propriétaire.' });
  if (req.member.role === 'admin' && target.role === 'admin') return res.status(403).json({ error: 'Un admin ne peut pas exclure un autre admin.' });

  await stmts.removeServerMember({ server_id: req.serverId, discord_id: discordId });

  // Enregistrer dans server_bans en tant que kick (is_kick=true)
  await stmts.createBan({
    server_id:  req.serverId,
    user_id:    discordId,
    username:   target.username || null,
    reason:     req.body?.reason || null,
    banned_by:  req.user.username,
    expires_at: null,
    is_kick:    true,
  });

  await logAction(req.serverId, 'member_kicked', `@${target.username || discordId} exclu`, req.user.discord_id, req.user.username, discordId);

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  io.to(`server:${req.serverId}`).emit('member_kicked', { discord_id: discordId, server_id: req.serverId });
  res.json({ success: true });
});

// ─── Channels ────────────────────────────────────────────────────────────────

app.get('/servers/:id/messages/:channelId', authRequired, requireMember, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });
  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) return res.status(404).json({ error: 'Channel introuvable.' });
  const since = req.query.since ? parseInt(req.query.since, 10) : null;
  const msgs = await stmts.getServerMessages({ server_id: req.serverId, channel_id: channelId, since });
  res.json(msgs);
});

app.post('/servers/:id/channels', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { name, type = 'text', category = 'Général' } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom du channel requis.' });
  if (name.trim().length > 32) return res.status(400).json({ error: 'Nom trop long (32 caractères max).' });
  if (!['text', 'announcement', 'rules', 'voice'].includes(type)) return res.status(400).json({ error: 'Type de channel invalide.' });

  const existing = await stmts.getServerChannels(req.serverId);
  const ch = await stmts.createServerChannel({ server_id: req.serverId, name: name.trim(), type, category: category.trim() || 'Général', position: existing.length });

  await logAction(req.serverId, 'channel_created', `Salon #${name.trim()} créé`, req.user.discord_id, req.user.username, null, { type, category });

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });
  res.status(201).json(ch);
});

app.patch('/servers/:id/channels/:channelId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });
  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) return res.status(404).json({ error: 'Channel introuvable.' });

  const { name, topic, category } = req.body;
  const updates = {};
  if (name !== undefined) {
    if (!name?.trim()) return res.status(400).json({ error: 'Nom requis.' });
    if (name.trim().length > 32) return res.status(400).json({ error: 'Nom trop long.' });
    updates.name = name.trim();
  }
  if (topic    !== undefined) { if (topic && topic.length > 80) return res.status(400).json({ error: 'Sujet trop long (max 80 car.).' }); updates.topic = topic || null; }
  if (category !== undefined) { updates.category = category?.trim() || 'Général'; }

  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Rien à modifier.' });

  const updated = await stmts.updateServerChannel(channelId, updates);
  await logAction(req.serverId, 'channel_updated', `Salon #${ch.name} modifié`, req.user.discord_id, req.user.username);

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });
  res.json(updated);
});

app.post('/servers/:id/channels/reorder', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { order } = req.body;
  if (!Array.isArray(order) || !order.length) return res.status(400).json({ error: 'Tableau "order" requis.' });
  const existing = await stmts.getServerChannels(req.serverId);
  const existingIds = new Set(existing.map(c => c.id));
  for (const item of order) {
    const id = parseInt(item.id, 10);
    if (isNaN(id) || !existingIds.has(id)) return res.status(400).json({ error: `Channel ID invalide : ${item.id}` });
    if (typeof item.position !== 'number') return res.status(400).json({ error: 'Position doit être un nombre.' });
  }
  for (const item of order) {
    await stmts.updateServerChannel(parseInt(item.id, 10), { position: item.position, category: item.category?.trim() || 'Général' });
  }
  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });
  res.json({ success: true });
});

app.delete('/servers/:id/channels/:channelId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });
  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) return res.status(404).json({ error: 'Channel introuvable.' });
  const all = await stmts.getServerChannels(req.serverId);
  if (all.length <= 1) return res.status(400).json({ error: 'Impossible de supprimer le dernier channel.' });

  await stmts.deleteServerChannel(channelId);
  await logAction(req.serverId, 'channel_deleted', `Salon #${ch.name} supprimé`, req.user.discord_id, req.user.username);

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });
  res.json({ success: true });
});

// ─── Rôles ────────────────────────────────────────────────────────────────────

app.get('/servers/:id/roles', authRequired, requireMember, async (req, res) => {
  const roles = await stmts.getServerRoles(req.serverId);
  res.json(roles);
});

// POST /servers/:id/roles — créer un nouveau rôle libre (ou insérer un rôle système)
app.post('/servers/:id/roles', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { label = 'Nouveau rôle', color = '#7a7490', icon = null, role_key: explicitKey } = req.body;
  if (label.length > 20) return res.status(400).json({ error: 'Label trop long (max 20 car.).' });

  // Si role_key explicite (rôle système passé depuis le client), l'utiliser directement
  const role_key = explicitKey
    ? explicitKey
    : `${label.toLowerCase().replace(/\s+/g,'_').replace(/[^a-z0-9_]/g,'').slice(0,20)}_${Date.now().toString(36)}`;

  // Upsert pour éviter les doublons si le rôle système existe déjà
  const role = await stmts.upsertServerRole(req.serverId, role_key, { label, color, icon, hoisted: false, mentionable: false, permissions: {} });
  await logAction(req.serverId, 'role_created', `Rôle "${label}" créé`, req.user.discord_id, req.user.username);
  io.to(`server:${req.serverId}`).emit('roles_updated', { server_id: req.serverId });
  res.status(201).json(role);
});

// PUT /servers/:id/roles/:roleKey — mettre à jour (upsert — crée si n'existe pas)
app.put('/servers/:id/roles/:roleKey', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { roleKey } = req.params;
  const { label, color, icon, hoisted, mentionable, permissions } = req.body;

  if (label && label.length > 20) return res.status(400).json({ error: 'Label trop long (max 20 car.).' });
  if (icon  && icon.length  >  4) return res.status(400).json({ error: 'Icône trop longue.' });

  const role = await stmts.upsertServerRole(req.serverId, roleKey, {
    label:       label       ?? roleKey,
    color:       color       ?? '#7a7490',
    icon:        icon        ?? null,
    hoisted:     hoisted     !== undefined ? !!hoisted     : false,
    mentionable: mentionable !== undefined ? !!mentionable : false,
    permissions: permissions ?? {},
  });

  await logAction(req.serverId, 'role_updated', `Rôle "${label || roleKey}" modifié`, req.user.discord_id, req.user.username);
  io.to(`server:${req.serverId}`).emit('roles_updated', { server_id: req.serverId });
  res.json(role);
});

// DELETE /servers/:id/roles/:roleKey — supprimer un rôle (owner uniquement)
app.delete('/servers/:id/roles/:roleKey', authRequired, requireMember, requireOwner, async (req, res) => {
  const { roleKey } = req.params;
  // On ne peut pas supprimer les rôles système
  const SYSTEM_ROLES = ['owner', 'admin', 'moderator', 'vip', 'member'];
  if (SYSTEM_ROLES.includes(roleKey)) return res.status(400).json({ error: 'Ce rôle système ne peut pas être supprimé.' });

  await stmts.deleteServerRole(req.serverId, roleKey);
  // Remettre les membres avec ce rôle à "member"
  await supabase.from('server_members').update({ role: 'member' }).eq('server_id', req.serverId).eq('role', roleKey);

  await logAction(req.serverId, 'role_deleted', `Rôle "${roleKey}" supprimé`, req.user.discord_id, req.user.username);
  io.to(`server:${req.serverId}`).emit('roles_updated', { server_id: req.serverId });
  res.json({ success: true });
});

// PATCH /servers/:id/roles/reorder
app.patch('/servers/:id/roles/reorder', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { order } = req.body; // [{ role_key, position }]
  if (!Array.isArray(order)) return res.status(400).json({ error: 'Tableau "order" requis.' });
  await stmts.reorderServerRoles(req.serverId, order);
  res.json({ success: true });
});

// ─── Messages — suppression (modération) ─────────────────────────────────────

app.delete('/servers/:id/messages/:msgId', authRequired, requireMember, requireModerator, async (req, res) => {
  const msgId = parseInt(req.params.msgId, 10);
  if (isNaN(msgId)) return res.status(400).json({ error: 'Message ID invalide.' });

  const msg = await stmts.deleteServerMessage(msgId);
  if (!msg) return res.status(404).json({ error: 'Message introuvable.' });

  await logAction(req.serverId, 'message_deleted', `Message #${msgId} supprimé`, req.user.discord_id, req.user.username, msg.discord_id);
  io.to(`${req.serverId}:${msg.channel_id}`).emit('message_deleted', { id: msgId, channel_id: msg.channel_id });
  res.json({ success: true });
});

// ─── Bans ─────────────────────────────────────────────────────────────────────

app.get('/servers/:id/bans', authRequired, requireMember, requireAdmin, async (req, res) => {
  const bans = await stmts.getServerBans(req.serverId);
  res.json(bans);
});

// POST /servers/:id/ban/:userId — bannir par discord_id
app.post('/servers/:id/ban/:userId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  const { reason = null, duration = 0 } = req.body;

  if (String(userId) === String(req.user.discord_id)) return res.status(400).json({ error: 'Vous ne pouvez pas vous bannir vous-même.' });

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: userId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'Impossible de bannir le propriétaire.' });
  if (req.member.role === 'admin' && target.role === 'admin') return res.status(403).json({ error: 'Un admin ne peut pas bannir un autre admin.' });

  const expires_at = duration > 0 ? new Date(Date.now() + duration * 86400000).toISOString() : null;

  await stmts.createBan({ server_id: req.serverId, user_id: userId, username: target.username, reason, banned_by: req.user.username, expires_at, is_kick: false });
  await stmts.removeServerMember({ server_id: req.serverId, discord_id: userId });

  await logAction(req.serverId, 'member_banned', `@${target.username || userId} banni${reason ? ' : ' + reason : ''}`, req.user.discord_id, req.user.username, userId);

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  io.to(`server:${req.serverId}`).emit('member_kicked', { discord_id: userId, server_id: req.serverId });
  res.json({ success: true });
});

// POST /servers/:id/ban/username — bannir par pseudo (depuis le formulaire manuel)
app.post('/servers/:id/ban/username', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { username, reason = null, duration = 0 } = req.body;
  if (!username) return res.status(400).json({ error: 'Pseudo requis.' });

  const user = await stmts.findByUsername(username);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

  // Déléguer au handler par userId (simuler les params)
  const userId = user.discord_id;
  const isMember = await stmts.isServerMember({ server_id: req.serverId, discord_id: userId });
  const expires_at = duration > 0 ? new Date(Date.now() + duration * 86400000).toISOString() : null;

  await stmts.createBan({ server_id: req.serverId, user_id: userId, username, reason, banned_by: req.user.username, expires_at, is_kick: false });
  if (isMember) await stmts.removeServerMember({ server_id: req.serverId, discord_id: userId });

  await logAction(req.serverId, 'member_banned', `@${username} banni${reason ? ' : ' + reason : ''}`, req.user.discord_id, req.user.username, userId);

  if (isMember) {
    const members = await stmts.getServerMembers(req.serverId);
    io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
    io.to(`server:${req.serverId}`).emit('member_kicked', { discord_id: userId, server_id: req.serverId });
  }
  res.json({ success: true });
});

// DELETE /servers/:id/ban/:userId — lever le ban
app.delete('/servers/:id/ban/:userId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { userId } = req.params;
  await stmts.deleteBan(req.serverId, userId);
  await logAction(req.serverId, 'ban_lifted', `Ban levé pour l\'utilisateur #${userId}`, req.user.discord_id, req.user.username, userId);
  res.json({ success: true });
});

// POST /servers/:id/kick/:userId — kick rapide (depuis context menu)
app.post('/servers/:id/kick/:userId', authRequired, requireMember, requireModerator, async (req, res) => {
  const { userId } = req.params;
  const { reason = null } = req.body;

  const target = await stmts.getServerMember({ server_id: req.serverId, discord_id: userId });
  if (!target) return res.status(404).json({ error: 'Membre introuvable.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'Impossible d\'exclure le propriétaire.' });

  await stmts.removeServerMember({ server_id: req.serverId, discord_id: userId });
  await stmts.createBan({ server_id: req.serverId, user_id: userId, username: target.username, reason, banned_by: req.user.username, expires_at: null, is_kick: true });
  await logAction(req.serverId, 'member_kicked', `@${target.username || userId} exclu${reason ? ' : ' + reason : ''}`, req.user.discord_id, req.user.username, userId);

  const members = await stmts.getServerMembers(req.serverId);
  io.to(`server:${req.serverId}`).emit('server_members_update', { server_id: req.serverId, members });
  io.to(`server:${req.serverId}`).emit('member_kicked', { discord_id: userId, server_id: req.serverId });
  res.json({ success: true });
});

// POST /servers/:id/warn/:userId — avertir via DM
app.post('/servers/:id/warn/:userId', authRequired, requireMember, requireModerator, async (req, res) => {
  const { userId } = req.params;
  const { message } = req.body;
  const srv = await stmts.getServerById(req.serverId);
  const warnMsg = message || `Tu as reçu un avertissement sur ${srv?.name || 'ce serveur'}.`;

  const roomKey = stmts.dmRoomKey(req.user.discord_id, userId);
  const dm = await stmts.saveDmMessage({ room: roomKey, discord_id: req.user.discord_id, username: req.user.username, content: warnMsg });
  if (dm) {
    io.to(`dm:${roomKey}`).emit('new_dm', { ...dm, otherDiscordId: userId });
    // Notifier l'utilisateur cible même s'il n'est pas dans la room
    const sockets = await io.fetchSockets();
    for (const s of sockets) {
      if (s.user?.discord_id === String(userId) && !s.rooms.has(`dm:${roomKey}`)) {
        s.emit('new_dm', { ...dm, otherDiscordId: req.user.discord_id });
      }
    }
  }
  res.json({ success: true });
});

// ─── Invitations gérées ───────────────────────────────────────────────────────

app.get('/servers/:id/invites', authRequired, requireMember, requireAdmin, async (req, res) => {
  const invites = await stmts.getServerInvites(req.serverId);
  res.json(invites);
});

app.post('/servers/:id/invites', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { duration = 0, max_uses = 0 } = req.body;
  const code = generateInviteCode();
  const expires_at = duration > 0 ? new Date(Date.now() + duration * 86400000).toISOString() : null;

  const invite = await stmts.createServerInvite({
    server_id:        req.serverId,
    code,
    creator_id:       req.user.discord_id,
    creator_username: req.user.username,
    max_uses:         parseInt(max_uses, 10) || 0,
    expires_at,
  });

  await logAction(req.serverId, 'invite_created', `Invitation ${code} créée`, req.user.discord_id, req.user.username);
  res.json(invite);
});

app.delete('/servers/:id/invites/:code', authRequired, requireMember, requireAdmin, async (req, res) => {
  await stmts.deleteServerInvite(req.serverId, req.params.code);
  await logAction(req.serverId, 'invite_revoked', `Invitation ${req.params.code} révoquée`, req.user.discord_id, req.user.username);
  res.json({ success: true });
});

// GET /invite/:code — rejoindre via invitation (code serveur OU code invitation gérée)
app.get('/invite/:code', authRequired, async (req, res) => {
  // Chercher d'abord dans les invitations gérées
  const { data: managed } = await supabase
    .from('server_invites')
    .select('*, servers(id, name, color, icon_url)')
    .eq('code', req.params.code)
    .single();

  if (managed) {
    // Vérifier expiration
    if (managed.expires_at && new Date(managed.expires_at) < new Date()) {
      return res.status(404).json({ error: 'Ce lien d\'invitation a expiré.' });
    }
    // Vérifier max_uses
    if (managed.max_uses > 0 && managed.use_count >= managed.max_uses) {
      return res.status(404).json({ error: 'Ce lien d\'invitation a atteint son nombre maximum d\'utilisations.' });
    }
    const srv = managed.servers;
    const memberCount = (await stmts.getServerMembers(srv.id)).length;
    const alreadyMember = await stmts.isServerMember({ server_id: srv.id, discord_id: req.user.discord_id });
    return res.json({ id: srv.id, name: srv.name, color: srv.color, icon_url: srv.icon_url || null, member_count: memberCount, already_member: alreadyMember });
  }

  // Fallback : code invite_code du serveur
  const srv = await stmts.getServerByInviteCode(req.params.code);
  if (!srv) return res.status(404).json({ error: 'Code d\'invitation invalide ou expiré.' });

  const memberCount = (await stmts.getServerMembers(srv.id)).length;
  const alreadyMember = await stmts.isServerMember({ server_id: srv.id, discord_id: req.user.discord_id });
  res.json({ id: srv.id, name: srv.name, color: srv.color, icon_url: srv.icon_url || null, member_count: memberCount, already_member: alreadyMember });
});

app.post('/invite/:code', authRequired, async (req, res) => {
  // Chercher d'abord dans les invitations gérées
  const { data: managed } = await supabase
    .from('server_invites')
    .select('*')
    .eq('code', req.params.code)
    .single();

  let serverId;

  if (managed) {
    if (managed.expires_at && new Date(managed.expires_at) < new Date()) return res.status(404).json({ error: 'Ce lien a expiré.' });
    if (managed.max_uses > 0 && managed.use_count >= managed.max_uses) return res.status(404).json({ error: 'Limite d\'utilisations atteinte.' });
    serverId = managed.server_id;

    // Vérifier access_mode
    const srv = await stmts.getServerById(serverId);
    if (srv?.access_mode === 'closed') return res.status(403).json({ error: 'Ce serveur est fermé aux nouvelles inscriptions.' });

    await stmts.incrementInviteUse(req.params.code);
  } else {
    const srv = await stmts.getServerByInviteCode(req.params.code);
    if (!srv) return res.status(404).json({ error: 'Code d\'invitation invalide.' });
    if (srv.access_mode === 'closed') return res.status(403).json({ error: 'Ce serveur est fermé.' });
    serverId = srv.id;
  }

  // Vérifier ban
  const banned = await stmts.isBanned(serverId, req.user.discord_id);
  if (banned) return res.status(403).json({ error: 'Vous êtes banni de ce serveur.' });

  const alreadyMember = await stmts.isServerMember({ server_id: serverId, discord_id: req.user.discord_id });
  if (alreadyMember) return res.status(400).json({ error: 'Tu es déjà membre de ce serveur.' });

  await stmts.addServerMember({ server_id: serverId, discord_id: req.user.discord_id, role: 'member' });
  await logAction(serverId, 'member_joined', `@${req.user.username} a rejoint le serveur`, req.user.discord_id, req.user.username);

  const members = await stmts.getServerMembers(serverId);
  io.to(`server:${serverId}`).emit('server_members_update', { server_id: serverId, members });
  res.json({ success: true, server_id: serverId });
});

// ─── Stickers ────────────────────────────────────────────────────────────────

app.get('/servers/:id/stickers', authRequired, requireMember, async (req, res) => {
  const stickers = await stmts.getServerStickers(req.serverId);
  res.json(stickers);
});

app.post('/servers/:id/stickers', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { name, description, data: base64Data, mime, url: directUrl } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Nom du sticker requis.' });
  if (name.trim().length > 32) return res.status(400).json({ error: 'Nom trop long (max 32 car.).' });

  let finalUrl = directUrl || null;

  // Upload base64 vers Supabase Storage si fourni
  if (base64Data && mime && !directUrl) {
    try {
      const base64 = base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;
      const buffer = Buffer.from(base64, 'base64');

      if (buffer.length > 512 * 1024) return res.status(400).json({ error: 'Fichier trop lourd (max 512 Ko).' });
      if (!['image/png', 'image/gif'].includes(mime)) return res.status(400).json({ error: 'Format non supporté (PNG ou GIF uniquement).' });

      const ext = mime === 'image/gif' ? 'gif' : 'png';
      const filename = `stickers/${req.serverId}/${Date.now()}.${ext}`;

      const { error: uploadError } = await supabase.storage
        .from('assets')
        .upload(filename, buffer, { contentType: mime, upsert: false });

      if (uploadError) return res.status(500).json({ error: 'Erreur d\'upload : ' + uploadError.message });

      const { data: { publicUrl } } = supabase.storage.from('assets').getPublicUrl(filename);
      finalUrl = publicUrl;
    } catch (e) {
      return res.status(500).json({ error: 'Erreur lors du traitement du fichier.' });
    }
  }

  if (!finalUrl) return res.status(400).json({ error: 'Fichier ou URL requis.' });

  const sticker = await stmts.createServerSticker({
    server_id:   req.serverId,
    name:        name.trim(),
    description: description?.trim() || null,
    url:         finalUrl,
    uploader_id: req.user.discord_id,
  });

  res.status(201).json(sticker);
});

app.delete('/servers/:id/stickers/:stickerId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const stickerId = parseInt(req.params.stickerId, 10);
  if (isNaN(stickerId)) return res.status(400).json({ error: 'Sticker ID invalide.' });

  const deleted = await stmts.deleteServerSticker(stickerId, req.serverId);
  if (!deleted) return res.status(404).json({ error: 'Sticker introuvable.' });

  // Supprimer du storage si c'est une URL Supabase
  if (deleted.url?.includes('/assets/')) {
    try {
      const path = deleted.url.split('/assets/')[1];
      if (path) await supabase.storage.from('assets').remove([decodeURIComponent(path)]);
    } catch (e) { /* non bloquant */ }
  }

  res.json({ success: true });
});

// ─── Logs ────────────────────────────────────────────────────────────────────

app.get('/servers/:id/logs', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { type, limit = 100, offset = 0 } = req.query;

  let types = null;
  if (type && type !== 'all') {
    // Résoudre les catégories
    types = type.split(',').flatMap(t => LOG_CATEGORIES[t] || [t]);
    types = [...new Set(types)]; // dédupliquer
  }

  const logs = await stmts.getServerLogs({
    server_id: req.serverId,
    types,
    limit:  Math.min(parseInt(limit, 10) || 100, 500),
    offset: parseInt(offset, 10) || 0,
  });

  res.json(logs);
});

// ─── DM ──────────────────────────────────────────────────────────────────────

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

function _leaveVoice(socket) {
  if (!socket._voiceRoom) return;
  const { serverId, channelId } = socket._voiceRoom;
  socket.leave(`voice:${serverId}:${channelId}`);
  socket.to(`voice:${serverId}:${channelId}`).emit('voice_peer_left', { socketId: socket.id });
  socket._voiceRoom = null;

  const roomKey = `voice:${serverId}:${channelId}`;
  const roomMembers = io.sockets.adapter.rooms.get(roomKey) || new Set();
  const participants = [];
  for (const sid of roomMembers) {
    const s = io.sockets.sockets.get(sid);
    if (s?.user) participants.push({ socketId: sid, discord_id: s.user.discord_id, username: s.user.username, avatar_url: s.user.avatar_url || null, muted: s._voiceMuted || false });
  }
  io.to(`server:${serverId}`).emit('voice_state', { channelId, participants });
}

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
      socket.join(serverId ? `${serverId}:${channelId}` : String(channelId));
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

      // Filtre mots interdits
      const srv = await stmts.getServerById(serverId);
      if (srv?.word_filter && srv?.banned_words) {
        const words = srv.banned_words.split(',').map(w => w.trim().toLowerCase()).filter(Boolean);
        const lower = content.toLowerCase();
        if (words.some(w => w && lower.includes(w))) return; // message silencieusement rejeté
      }

      // Filtre liens externes
      if (srv?.block_links) {
        const urlRegex = /https?:\/\/[^\s]+/gi;
        if (urlRegex.test(content)) return;
      }

      const msg = await stmts.saveServerMessage({ server_id: serverId, channel_id: channelId, discord_id: socket.user.discord_id, username: socket.user.username, content: content.trim() });
      if (msg) io.to(`${serverId}:${channelId}`).emit('new_message', msg);

    } else if (payload.channelId) {
      const { data } = await supabase
        .from('messages')
        .insert({ channel_id: payload.channelId, discord_id: socket.user.discord_id, username: socket.user.username, content: content.trim() })
        .select()
        .single();
      if (data) io.to(payload.channelId).emit('new_message', data);
    }
  });

  // ── Typing ───────────────────────────────────────────────────────────────────

  socket.on('typing_start', async ({ channelId, serverId }) => {
    if (!channelId) return;
    const roomKey = serverId ? `${serverId}:${channelId}` : String(channelId);
    if (serverId) {
      const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
      if (!isMember) return;
    }
    socket.to(roomKey).emit('typing_start', { discord_id: socket.user.discord_id, username: socket.user.username, channelId, serverId: serverId || null });
    if (!socket._typingTimers) socket._typingTimers = {};
    clearTimeout(socket._typingTimers[roomKey]);
    socket._typingTimers[roomKey] = setTimeout(() => {
      socket.to(roomKey).emit('typing_stop', { discord_id: socket.user.discord_id, channelId, serverId: serverId || null });
    }, 4000);
  });

  socket.on('typing_stop', ({ channelId, serverId }) => {
    if (!channelId) return;
    const roomKey = serverId ? `${serverId}:${channelId}` : String(channelId);
    clearTimeout(socket._typingTimers?.[roomKey]);
    if (socket._typingTimers) delete socket._typingTimers[roomKey];
    socket.to(roomKey).emit('typing_stop', { discord_id: socket.user.discord_id, channelId, serverId: serverId || null });
  });

  // ── DM ───────────────────────────────────────────────────────────────────────

  socket.on('join_dm', async ({ otherDiscordId }) => {
    if (!otherDiscordId) return;
    const roomKey = stmts.dmRoomKey(socket.user.discord_id, otherDiscordId);
    Array.from(socket.rooms).forEach(room => { if (room.startsWith('dm:')) socket.leave(room); });
    socket.join(`dm:${roomKey}`);
  });

  socket.on('send_dm', async ({ otherDiscordId, content }) => {
    if (!otherDiscordId || !content?.trim()) return;
    const roomKey = stmts.dmRoomKey(socket.user.discord_id, otherDiscordId);
    const msg = await stmts.saveDmMessage({ room: roomKey, discord_id: socket.user.discord_id, username: socket.user.username, content: content.trim() });
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
    socket.to(`dm:${roomKey}`).emit('typing_start_dm', { discord_id: socket.user.discord_id, username: socket.user.username });
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

  // ── Voice ────────────────────────────────────────────────────────────────────

  socket.on('voice_join', async ({ serverId, channelId }) => {
    const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
    if (!isMember) return;
    const ch = await stmts.getServerChannelById(channelId);
    if (!ch || ch.server_id !== serverId || ch.type !== 'voice') return;

    _leaveVoice(socket);
    socket._voiceRoom  = { serverId, channelId };
    socket._voiceMuted = false;
    const roomKey = `voice:${serverId}:${channelId}`;

    const existing = io.sockets.adapter.rooms.get(roomKey) || new Set();
    const peers = [];
    for (const sid of existing) {
      const s = io.sockets.sockets.get(sid);
      if (s?.user) peers.push({ socketId: sid, discord_id: s.user.discord_id, username: s.user.username, avatar_url: s.user.avatar_url || null, muted: s._voiceMuted || false });
    }
    socket.join(roomKey);
    socket.emit('voice_peers', { peers });
    socket.to(roomKey).emit('voice_peer_joined', { socketId: socket.id, discord_id: socket.user.discord_id, username: socket.user.username, avatar_url: socket.user.avatar_url || null, muted: false });

    const allInRoom = io.sockets.adapter.rooms.get(roomKey) || new Set();
    const participants = [];
    for (const sid of allInRoom) {
      const s = io.sockets.sockets.get(sid);
      if (s?.user) participants.push({ socketId: sid, discord_id: s.user.discord_id, username: s.user.username, avatar_url: s.user.avatar_url || null, muted: s._voiceMuted || false });
    }
    io.to(`server:${serverId}`).emit('voice_state', { channelId, participants });
  });

  socket.on('voice_leave',         ()                              => { _leaveVoice(socket); });
  socket.on('voice_offer',         ({ targetSocketId, offer })    => { io.to(targetSocketId).emit('voice_offer',         { fromSocketId: socket.id, from: { discord_id: socket.user.discord_id, username: socket.user.username, avatar_url: socket.user.avatar_url || null }, offer }); });
  socket.on('voice_answer',        ({ targetSocketId, answer })   => { io.to(targetSocketId).emit('voice_answer',        { fromSocketId: socket.id, answer }); });
  socket.on('voice_ice_candidate', ({ targetSocketId, candidate })=> { io.to(targetSocketId).emit('voice_ice_candidate', { fromSocketId: socket.id, candidate }); });

  socket.on('voice_mute', ({ muted }) => {
    if (!socket._voiceRoom) return;
    socket._voiceMuted = !!muted;
    const { serverId, channelId } = socket._voiceRoom;
    socket.to(`voice:${serverId}:${channelId}`).emit('voice_peer_muted', { socketId: socket.id, muted: !!muted });
  });

  socket.on('screen_share_start', ({ serverId, channelId }) => {
    if (!socket._voiceRoom || socket._voiceRoom.serverId !== serverId || socket._voiceRoom.channelId !== channelId) return;
    socket.to(`voice:${serverId}:${channelId}`).emit('screen_share_started', { socketId: socket.id, username: socket.user.username });
  });

  socket.on('screen_share_stop', ({ serverId, channelId }) => {
    if (!serverId || !channelId) return;
    socket.to(`voice:${serverId}:${channelId}`).emit('screen_share_stopped', { socketId: socket.id });
  });

  // ── Disconnect ───────────────────────────────────────────────────────────────

  socket.on('disconnect', async () => {
    _leaveVoice(socket);
    if (socket._typingTimers) {
      Object.keys(socket._typingTimers).forEach(roomKey => {
        clearTimeout(socket._typingTimers[roomKey]);
        socket.to(roomKey).emit('typing_stop', {
          discord_id: socket.user.discord_id,
          channelId:  roomKey.includes(':') ? roomKey.split(':')[1] : roomKey,
          serverId:   roomKey.includes(':') ? parseInt(roomKey.split(':')[0], 10) : null,
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
