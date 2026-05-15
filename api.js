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
  cors: { origin: '*', methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'] }
});

const PORT   = process.env.PORT || process.env.API_PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'changeme';

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
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
    map[ch.category].push({ id: ch.id, name: ch.name, type: ch.type });
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

// ─── Serveur par défaut ──────────────────────────────────────────────────────

app.get('/server', authRequired, (req, res) => {
  res.json(DEFAULT_SERVER);
});

app.get('/members', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('discord_id, username, avatar_url')
    .order('username');
  res.json(data || []);
});

app.get('/messages/:channelId', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('messages')
    .select('*')
    .eq('channel_id', req.params.channelId)
    .is('server_id', null)
    .order('created_at', { ascending: true })
    .limit(50);
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

  // Générer un code d'invitation unique
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

  // Ajouter le créateur comme owner
  await stmts.addServerMember({ server_id: srv.id, discord_id: req.user.discord_id, role: 'owner' });

  // Créer les channels par défaut
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

  // Vérifie que le channel appartient bien à ce serveur
  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) {
    return res.status(404).json({ error: 'Channel introuvable.' });
  }

  const msgs = await stmts.getServerMessages({ server_id: req.serverId, channel_id: channelId });
  res.json(msgs);
});

// PATCH /servers/:id — modifier le serveur (admin/owner)
app.patch('/servers/:id', authRequired, requireMember, requireAdmin, async (req, res) => {
  const { name, color } = req.body;
  const updates = {};
  if (name?.trim()) {
    if (name.trim().length > 50) return res.status(400).json({ error: 'Nom trop long.' });
    updates.name = name.trim();
  }
  if (color) updates.color = color;
  if (!Object.keys(updates).length) return res.status(400).json({ error: 'Rien à modifier.' });

  const updated = await stmts.updateServer(req.serverId, updates);
  // Notifier les membres connectés
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

  // Position = max existant + 1
  const existing = await stmts.getServerChannels(req.serverId);
  const position = existing.length;

  const ch = await stmts.createServerChannel({
    server_id: req.serverId,
    name: name.trim(),
    type,
    category: category.trim() || 'Général',
    position,
  });

  // Notifier les membres
  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });

  res.status(201).json(ch);
});

// DELETE /servers/:id/channels/:channelId — supprimer un channel (admin/owner)
app.delete('/servers/:id/channels/:channelId', authRequired, requireMember, requireAdmin, async (req, res) => {
  const channelId = parseInt(req.params.channelId, 10);
  if (isNaN(channelId)) return res.status(400).json({ error: 'Channel ID invalide.' });

  const ch = await stmts.getServerChannelById(channelId);
  if (!ch || ch.server_id !== req.serverId) {
    return res.status(404).json({ error: 'Channel introuvable.' });
  }

  // Garder au minimum 1 channel
  const all = await stmts.getServerChannels(req.serverId);
  if (all.length <= 1) return res.status(400).json({ error: 'Impossible de supprimer le dernier channel.' });

  await stmts.deleteServerChannel(channelId);

  const channels = await stmts.getServerChannels(req.serverId);
  io.to(`server:${req.serverId}`).emit('channels_updated', { server_id: req.serverId, channels });

  res.json({ success: true });
});

// ─── Invitations ─────────────────────────────────────────────────────────────

// GET /invite/:code — preview de l'invitation (sans rejoindre)
app.get('/invite/:code', authRequired, async (req, res) => {
  const srv = await stmts.getServerByInviteCode(req.params.code);
  if (!srv) return res.status(404).json({ error: 'Code d\'invitation invalide ou expiré.' });

  const memberCount = (await stmts.getServerMembers(srv.id)).length;
  const alreadyMember = await stmts.isServerMember({ server_id: srv.id, discord_id: req.user.discord_id });

  res.json({
    id:            srv.id,
    name:          srv.name,
    color:         srv.color,
    member_count:  memberCount,
    already_member: alreadyMember,
  });
});

// POST /invite/:code — rejoindre le serveur via invitation
app.post('/invite/:code', authRequired, async (req, res) => {
  const srv = await stmts.getServerByInviteCode(req.params.code);
  if (!srv) return res.status(404).json({ error: 'Code d\'invitation invalide ou expiré.' });

  const alreadyMember = await stmts.isServerMember({ server_id: srv.id, discord_id: req.user.discord_id });
  if (alreadyMember) return res.status(400).json({ error: 'Tu es déjà membre de ce serveur.' });

  await stmts.addServerMember({ server_id: srv.id, discord_id: req.user.discord_id, role: 'member' });

  // Notifier les membres du serveur
  const members = await stmts.getServerMembers(srv.id);
  io.to(`server:${srv.id}`).emit('server_members_update', { server_id: srv.id, members });

  res.json({ success: true, server_id: srv.id });
});

// ─── Socket.io ────────────────────────────────────────────────────────────────

io.on('connection', async (socket) => {
  const token = socket.handshake.auth?.token;
  const user  = verifyToken(token);
  if (!user) { socket.disconnect(); return; }

  socket.user = user;
  console.log(`[WS] ${user.username} connecté`);

  // Mettre à jour la liste des membres (serveur par défaut)
  const { data: allMembers } = await supabase
    .from('users')
    .select('discord_id, username, avatar_url')
    .order('username');
  io.emit('members_update', allMembers || []);

  // Rejoindre un serveur (pour recevoir les events server_updated, members_update, etc.)
  socket.on('join_server', async ({ serverId }) => {
    if (!serverId) return;
    const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
    if (!isMember) return;
    socket.join(`server:${serverId}`);
  });

  // Rejoindre un channel
  // Accepte { serverId, channelId } pour les serveurs utilisateur
  // ou une string pour le serveur par défaut (rétrocompatibilité)
  socket.on('join_channel', (payload) => {
    // Quitter les rooms précédentes (sauf server:* et socket.id)
    Array.from(socket.rooms).forEach(room => {
      if (room !== socket.id && !room.startsWith('server:')) socket.leave(room);
    });

    if (typeof payload === 'string') {
      // Serveur par défaut
      socket.join(payload);
    } else {
      const { serverId, channelId } = payload;
      socket.join(`${serverId}:${channelId}`);
    }
  });

  // Envoyer un message
  socket.on('send_message', async (payload) => {
    if (!payload?.content?.trim()) return;

    const { content, serverId, channelId } = payload;

    if (serverId && channelId) {
      // Message dans un serveur utilisateur
      const isMember = await stmts.isServerMember({ server_id: serverId, discord_id: socket.user.discord_id });
      if (!isMember) return;

      const ch = await stmts.getServerChannelById(channelId);
      if (!ch || ch.server_id !== serverId) return;
      if (ch.type === 'rules' || ch.type === 'announcement') return; // lecture seule

      const msg = await stmts.saveServerMessage({
        server_id:  serverId,
        channel_id: channelId,
        discord_id: socket.user.discord_id,
        username:   socket.user.username,
        content:    content.trim(),
      });
      if (msg) io.to(`${serverId}:${channelId}`).emit('new_message', msg);
    } else if (payload.channelId) {
      // Message dans le serveur par défaut
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

  socket.on('disconnect', async () => {
    console.log(`[WS] ${socket.user?.username} déconnecté`);
    const { data: allMembers } = await supabase
      .from('users')
      .select('discord_id, username, avatar_url')
      .order('username');
    io.emit('members_update', allMembers || []);
  });
});

// ─── Démarrage ────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n✅  API + WebSocket Damnzcord sur http://localhost:${PORT}`);
});
