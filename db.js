// db.js — Base de données Supabase
require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const stmts = {

  // ─── Utilisateurs ───────────────────────────────────────────────────────────

  async findByDiscordId(discord_id) {
    const { data } = await supabase
      .from('users')
      .select('*')
      .eq('discord_id', discord_id)
      .single();
    return data || null;
  },

  async findByUsername(username) {
    const { data } = await supabase
      .from('users')
      .select('*')
      .ilike('username', username)
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

  async updateProfile({ discord_id, display_name, nickname, bio, banner_url }) {
    const updates = {};
    if (display_name !== undefined) updates.display_name = display_name;
    if (nickname      !== undefined) updates.nickname      = nickname;
    if (bio           !== undefined) updates.bio           = bio;
    if (banner_url    !== undefined) updates.banner_url    = banner_url;
    await supabase
      .from('users')
      .update(updates)
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

  // ─── Serveurs ────────────────────────────────────────────────────────────────

  async getUserServers(discord_id) {
    const { data } = await supabase
      .from('server_members')
      .select(`
        role,
        servers (
          id, name, color, invite_code, owner_id, created_at
        )
      `)
      .eq('discord_id', discord_id);
    if (!data) return [];
    return data.map(row => ({ ...row.servers, role: row.role }));
  },

  async createServer({ name, color, invite_code, owner_id }) {
    const { data } = await supabase
      .from('servers')
      .insert({ name, color, invite_code, owner_id })
      .select()
      .single();
    return data || null;
  },

  async getServerById(id) {
    const { data } = await supabase
      .from('servers')
      .select('*')
      .eq('id', id)
      .single();
    return data || null;
  },

  async getServerByInviteCode(invite_code) {
    const { data } = await supabase
      .from('servers')
      .select('*')
      .eq('invite_code', invite_code)
      .single();
    return data || null;
  },

  async updateServer(id, updates) {
    const { data } = await supabase
      .from('servers')
      .update(updates)
      .eq('id', id)
      .select()
      .single();
    return data || null;
  },

  async deleteServer(id) {
    await supabase.from('servers').delete().eq('id', id);
  },

  // ─── Membres des serveurs ────────────────────────────────────────────────────

  async getServerMembers(server_id) {
    const { data } = await supabase
      .from('server_members')
      .select(`
        discord_id, role, joined_at,
        users (username, avatar_url, display_name, nickname, bio, banner_url)
      `)
      .eq('server_id', server_id)
      .order('joined_at', { ascending: true });
    if (!data) return [];
    return data.map(row => ({
      discord_id:   row.discord_id,
      role:         row.role,
      joined_at:    row.joined_at,
      username:     row.users?.username,
      avatar_url:   row.users?.avatar_url,
      display_name: row.users?.display_name,
      nickname:     row.users?.nickname,
      bio:          row.users?.bio,
      banner_url:   row.users?.banner_url,
    }));
  },

  async getServerMember({ server_id, discord_id }) {
    const { data } = await supabase
      .from('server_members')
      .select('*')
      .eq('server_id', server_id)
      .eq('discord_id', discord_id)
      .single();
    return data || null;
  },

  async isServerMember({ server_id, discord_id }) {
    const { data } = await supabase
      .from('server_members')
      .select('discord_id')
      .eq('server_id', server_id)
      .eq('discord_id', discord_id)
      .single();
    return !!data;
  },

  async addServerMember({ server_id, discord_id, role = 'member' }) {
    await supabase
      .from('server_members')
      .insert({ server_id, discord_id, role });
  },

  async removeServerMember({ server_id, discord_id }) {
    await supabase
      .from('server_members')
      .delete()
      .eq('server_id', server_id)
      .eq('discord_id', discord_id);
  },

  async updateServerMemberRole({ server_id, discord_id, role }) {
    await supabase
      .from('server_members')
      .update({ role })
      .eq('server_id', server_id)
      .eq('discord_id', discord_id);
  },

  // ─── Channels des serveurs ───────────────────────────────────────────────────

  async getServerChannels(server_id) {
    const { data } = await supabase
      .from('server_channels')
      .select('*')
      .eq('server_id', server_id)
      .order('position', { ascending: true });
    return data || [];
  },

  async getServerChannelById(id) {
    const { data } = await supabase
      .from('server_channels')
      .select('*')
      .eq('id', id)
      .single();
    return data || null;
  },

  async createServerChannel({ server_id, name, type, category, position }) {
    const { data } = await supabase
      .from('server_channels')
      .insert({ server_id, name, type, category, position })
      .select()
      .single();
    return data || null;
  },

  async deleteServerChannel(id) {
    await supabase.from('server_channels').delete().eq('id', id);
  },

  async updateServerChannel(id, updates) {
    const { data } = await supabase
      .from('server_channels')
      .update(updates)
      .eq('id', id)
      .select()
      .single();
    return data || null;
  },

  // ─── Messages des serveurs ───────────────────────────────────────────────────

  async getServerMessages({ server_id, channel_id, limit = 200 }) {
    const { data } = await supabase
      .from('messages')
      .select('*')
      .eq('server_id', server_id)
      .eq('channel_id', String(channel_id))
      .order('created_at', { ascending: true })
      .limit(limit);
    return data || [];
  },

  async saveServerMessage({ server_id, channel_id, discord_id, username, content }) {
    const { data } = await supabase
      .from('messages')
      .insert({
        server_id,
        channel_id: String(channel_id),
        discord_id,
        username,
        content,
      })
      .select()
      .single();
    return data || null;
  },

  // ─── Messages Privés (DM) ────────────────────────────────────────────────────

  dmRoomKey(id1, id2) {
    return [String(id1), String(id2)].sort().join(':');
  },

  async getDmMessages(roomKey) {
    const { data } = await supabase
      .from('dm_messages')
      .select('*')
      .eq('room', roomKey)
      .order('created_at', { ascending: true })
      .limit(50);
    return data || [];
  },

  async saveDmMessage({ room, discord_id, username, content }) {
    const { data } = await supabase
      .from('dm_messages')
      .insert({ room, discord_id, username, content })
      .select()
      .single();
    return data || null;
  },

  async getDmConversations(discord_id) {
    const id = String(discord_id);
    const { data } = await supabase
      .from('dm_messages')
      .select('room, username, discord_id, created_at, content')
      .or(`room.like.${id}:%,room.like.%:${id}`)
      .order('created_at', { ascending: false });

    if (!data) return [];

    // Dédupliquer par room, garder le message le plus récent
    const seen = new Map();
    for (const row of data) {
      if (!seen.has(row.room)) seen.set(row.room, row);
    }

    const convs = [];
    for (const [room, lastMsg] of seen) {
      const [a, b] = room.split(':');
      const otherId = a === id ? b : a;
      const other = await supabase
        .from('users')
        .select('discord_id, username, avatar_url, display_name')
        .eq('discord_id', otherId)
        .single();
      if (other.data) {
        convs.push({
          room,
          other: other.data,
          last_message: lastMsg.content,
          last_at: lastMsg.created_at,
        });
      }
    }
    return convs;
  },

  async searchUsers(query, excludeDiscordId) {
    const { data } = await supabase
      .from('users')
      .select('discord_id, username, avatar_url, display_name')
      .ilike('username', `%${query}%`)
      .neq('discord_id', excludeDiscordId)
      .limit(10);
    return data || [];
  },


};

module.exports = { supabase, stmts };
