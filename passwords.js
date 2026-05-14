// passwords.js — Génération et hachage des mots de passe

const bcrypt = require('bcrypt');
require('dotenv').config();

const ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;

// Caractères utilisés pour générer le mot de passe temporaire
// Volontairement sans 0/O/1/l/I pour éviter la confusion visuelle
const CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';

/**
 * Génère un mot de passe temporaire lisible
 * Format : xxxx-xxxx-xxxx (plus facile à recopier)
 */
function generateTempPassword() {
  const segment = (n) =>
    Array.from({ length: n }, () => CHARS[Math.floor(Math.random() * CHARS.length)]).join('');
  return `${segment(4)}-${segment(4)}-${segment(4)}`;
}

/**
 * Hash un mot de passe en clair avec bcrypt
 * @param {string} plaintext
 * @returns {Promise<string>} hash
 */
async function hashPassword(plaintext) {
  return bcrypt.hash(plaintext, ROUNDS);
}

/**
 * Vérifie si un mot de passe correspond à un hash
 * @param {string} plaintext
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plaintext, hash) {
  return bcrypt.compare(plaintext, hash);
}

module.exports = { generateTempPassword, hashPassword, verifyPassword };
