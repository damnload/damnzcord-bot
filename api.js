// api.js — API REST Damnzcord (Supabase)
require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const jwt     = require('jsonwebtoken');
const { stmts }                        = require('./db');
const { verifyPassword, hashPassword } = require('./passwords');

const app    = express();
const PORT   = process.env.API_PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'changeme';

app.use(cors());
app.use(express.json());

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

// ─── Routes ──────────────────────────────────────────────────────────────────

// POST /login  { username, password }
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Identifiant et mot de passe requis.' });
  }

  const user = await stmts.findByUsername(username);
  if (!user) {
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
  }

  const ok = await verifyPassword(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: 'Identifiant ou mot de passe incorrect.' });
  }

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

// POST /change-password  { old_password, new_password }
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

  res.json({ success: true, message: 'Mot de passe mis à jour.' });
});

// POST /update-avatar  { avatar_url }
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

// ─── Démarrage ────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n✅  API Damnzcord démarrée sur http://localhost:${PORT}`);
  console.log(`   POST /login`);
  console.log(`   GET  /me`);
  console.log(`   POST /change-password`);
  console.log(`   POST /update-avatar\n`);
});
