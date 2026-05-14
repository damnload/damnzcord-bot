// db.js — Base de données Supabase
require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// ─── API identique à avant ────────────────────────────────────────────────────

const stmts = {

  async findByDiscordId(discord_id) {
    const { data } = await supabase
      .from('users')
      .select('*')
      .eq('discord_id', discord_id)
      .single();
    return data || null;
  },

  async createUser({ discord_id, username, password_hash }) {
    const { data } = await supabase
      .from('users')
      .insert({ discord_id, username, password_hash })
      .select()
      .single();
    return data;
  },

  async updatePassword({ discord_id, password_hash }) {
    await supabase
      .from('users')
      .update({ password_hash, temp_password: false })
      .eq('discord_id', discord_id);
  },

  async resetPassword({ discord_id, password_hash }) {
    await supabase
      .from('users')
      .update({ password_hash, temp_password: true })
      .eq('discord_id', discord_id);
  },

  async updateAvatar({ discord_id, avatar_url }) {
    await supabase
      .from('users')
      .update({ avatar_url })
      .eq('discord_id', discord_id);
  },

  async updateLastLogin({ discord_id }) {
    await supabase
      .from('users')
      .update({ last_login: new Date().toISOString() })
      .eq('discord_id', discord_id);
  },

  async countUsers() {
    const { count } = await supabase
      .from('users')
      .select('*', { count: 'exact', head: true });
    return { total: count || 0 };
  },

  async findByUsername(username) {
    const { data } = await supabase
      .from('users')
      .select('*')
      .ilike('username', username)
      .single();
    return data || null;
  },
};

module.exports = { supabase, stmts };
