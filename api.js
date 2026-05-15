// api.js — API REST + WebSocket Damnzcord
require('dotenv').config();

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
const jwt        = require('jsonwebtoken');
const { stmts, supabase }              = require('./db');
const { verifyPassword, hashPassword } = require('./passwords');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT   = process.env.PORT || process.env.API_PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'changeme';

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.options('*', cors());
app.use(express.json());

// ─── Serveur par défaut (hardcodé pour l'instant) ─────────────────────────────

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

// ─── Routes HTTP ─────────────────────────────────────────────────────────────

// POST /login
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

// GET /me
app.get('/me', authRequired, async (req, res) => {
  const user = await stmts.findByDiscordId(req.user.discord_id);
  if (!user) return res.status(404).json({ error: 'Compte introuvable.' });
  const { password_hash, ...safe } = user;
  res.json(safe);
});

// POST /change-password
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

// POST /update-avatar
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

// GET /server — structure du serveur par défaut
app.get('/server', authRequired, (req, res) => {
  res.json(DEFAULT_SERVER);
});

// GET /members — liste des membres
app.get('/members', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('users')
    .select('discord_id, username, avatar_url')
    .order('username');
  res.json(data || []);
});

// GET /messages/:channelId — 50 derniers messages
app.get('/messages/:channelId', authRequired, async (req, res) => {
  const { data } = await supabase
    .from('messages')
    .select('*')
    .eq('channel_id', req.params.channelId)
    .order('created_at', { ascending: true })
    .limit(50);
  res.json(data || []);
});

// ─── Socket.io ────────────────────────────────────────────────────────────────

io.on('connection', (socket) => {

  // Auth via token à la connexion
  const token = socket.handshake.auth?.token;
  const user  = verifyToken(token);
  if (!user) { socket.disconnect(); return; }

  socket.user = user;
  console.log(`[WS] ${user.username} connecté`);

  // Rejoindre un channel
  socket.on('join_channel', (channelId) => {
    // Quitte l'ancien channel
    Object.keys(socket.rooms).forEach(room => {
      if (room !== socket.id) socket.leave(room);
    });
    socket.join(channelId);
  });

  // Envoyer un message
  socket.on('send_message', async ({ channelId, content }) => {
    if (!channelId || !content?.trim()) return;

    // Sauvegarde en base
    const { data } = await supabase
      .from('messages')
      .insert({
        channel_id: channelId,
        discord_id: socket.user.discord_id,
        username:   socket.user.username,
        content:    content.trim(),
      })
      .select()
      .single();

    if (data) {
      // Diffuse à tous les membres du channel
      io.to(channelId).emit('new_message', data);
    }
  });

  socket.on('disconnect', () => {
    console.log(`[WS] ${socket.user?.username} déconnecté`);
  });
});

// ─── Démarrage ────────────────────────────────────────────────────────────────

server.listen(PORT, () => {
  console.log(`\n✅  API + WebSocket Damnzcord sur http://localhost:${PORT}`);
});
