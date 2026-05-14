// index.js — Bot Damnzcord (Supabase)
require('dotenv').config();

const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const { stmts }                                    = require('./db');
const { generateTempPassword, hashPassword }       = require('./passwords');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.DirectMessages,
  ],
});

const PREFIX     = '!';
const ACCENT     = 0xe8621a;
const COLOR_OK   = 0x3dba6f;
const COLOR_ERR  = 0xe74c3c;
const COLOR_INFO = 0x3498db;

async function dmUser(user, embed) {
  try { await user.send({ embeds: [embed] }); return true; }
  catch { return false; }
}

function errEmbed(desc) {
  return new EmbedBuilder().setColor(COLOR_ERR).setDescription(`❌  ${desc}`);
}
function okEmbed(title, desc) {
  return new EmbedBuilder().setColor(COLOR_OK).setTitle(title).setDescription(desc);
}

// ─── Commandes ───────────────────────────────────────────────────────────────

const commands = {

  async createaccount(message) {
    const discordId = message.author.id;
    const username  = message.author.username;

    const existing = await stmts.findByDiscordId(discordId);
    if (existing) {
      return message.reply({
        embeds: [errEmbed(`Tu as déjà un compte sous le pseudo **${existing.username}**.\nUtilise \`!resetpassword\` si tu as perdu ton mot de passe.`)],
      });
    }

    const tempPwd = generateTempPassword();
    const hash    = await hashPassword(tempPwd);
    await stmts.createUser({ discord_id: discordId, username, password_hash: hash });

    const dmEmbed = new EmbedBuilder()
      .setColor(ACCENT)
      .setTitle('🎉  Compte Damnzcord créé !')
      .setDescription(`Bienvenue **${username}** ! Connecte-toi avec ces identifiants :`)
      .addFields(
        { name: 'Identifiant',        value: `\`${username}\``, inline: true },
        { name: 'Mot de passe temp.', value: `\`${tempPwd}\``,  inline: true },
      )
      .addFields({ name: '⚠️  Important', value: '• Mot de passe **temporaire** — change-le à ta première connexion.\n• Perdu ? Tape `!resetpassword`.' })
      .setFooter({ text: 'Damnzcord — aucune donnée sensible collectée' })
      .setTimestamp();

    const dmOk = await dmUser(message.author, dmEmbed);
    if (dmOk) {
      await message.reply({ embeds: [okEmbed('Compte créé !', `✅  Identifiants envoyés en DM, **${username}** !`)] });
    } else {
      await stmts.resetPassword({ discord_id: discordId, password_hash: '' });
      await message.reply({ embeds: [errEmbed('Impossible de t\'envoyer un DM 😕\nOuvre tes messages privés et retape la commande.')] });
    }
  },

  async resetpassword(message) {
    const discordId = message.author.id;
    const user      = await stmts.findByDiscordId(discordId);

    if (!user) {
      return message.reply({ embeds: [errEmbed('Aucun compte trouvé. Utilise `!createaccount`.')] });
    }

    const newPwd = generateTempPassword();
    const hash   = await hashPassword(newPwd);
    await stmts.resetPassword({ discord_id: discordId, password_hash: hash });

    const dmEmbed = new EmbedBuilder()
      .setColor(COLOR_INFO)
      .setTitle('🔑  Réinitialisation du mot de passe')
      .addFields(
        { name: 'Identifiant',          value: `\`${user.username}\``, inline: true },
        { name: 'Nouveau mot de passe', value: `\`${newPwd}\``,        inline: true },
      )
      .addFields({ name: '⚠️  Important', value: 'Change ce mot de passe temporaire dès ta prochaine connexion.' })
      .setTimestamp();

    const dmOk = await dmUser(message.author, dmEmbed);
    await message.reply({
      embeds: dmOk
        ? [okEmbed('Mot de passe réinitialisé', 'Nouveau mot de passe envoyé en DM ✅')]
        : [errEmbed('Impossible de t\'envoyer un DM. Ouvre tes messages privés et réessaie.')],
    });
  },

  async setavatar(message, args) {
    const discordId = message.author.id;
    const user      = await stmts.findByDiscordId(discordId);
    if (!user) return message.reply({ embeds: [errEmbed('Aucun compte trouvé. Tape `!createaccount` d\'abord.')] });

    const url = args[0];
    if (!url) return message.reply({ embeds: [errEmbed('Usage : `!setavatar https://exemple.com/photo.png`')] });

    try {
      const u = new URL(url);
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error();
    } catch {
      return message.reply({ embeds: [errEmbed('URL invalide. Fournis un lien image direct (http/https).')] });
    }

    await stmts.updateAvatar({ discord_id: discordId, avatar_url: url });
    await message.reply({
      embeds: [new EmbedBuilder().setColor(COLOR_OK).setTitle('🖼️  Avatar mis à jour').setThumbnail(url).setTimestamp()],
    });
  },

  async moncompte(message) {
    const discordId = message.author.id;
    const user      = await stmts.findByDiscordId(discordId);
    if (!user) return message.reply({ embeds: [errEmbed('Aucun compte trouvé. Tape `!createaccount`.')] });

    const embed = new EmbedBuilder()
      .setColor(ACCENT)
      .setTitle('👤  Mon compte Damnzcord')
      .addFields(
        { name: 'Pseudo',       value: user.username,                                                  inline: true },
        { name: 'ID Discord',   value: `\`${user.discord_id}\``,                                      inline: true },
        { name: 'Mot de passe', value: user.temp_password ? '⚠️  Temporaire' : '✅  Personnalisé',    inline: true },
        { name: 'Avatar',       value: user.avatar_url ? `[Voir](${user.avatar_url})` : 'Non défini', inline: true },
      )
      .setFooter({ text: 'Mots de passe jamais stockés en clair.' })
      .setTimestamp();

    if (user.avatar_url) embed.setThumbnail(user.avatar_url);

    const dmOk = await dmUser(message.author, embed);
    await message.reply({
      embeds: dmOk
        ? [okEmbed('Infos envoyées', 'Informations envoyées en DM 📬')]
        : [errEmbed('Impossible d\'envoyer un DM.')],
    });
  },

  async help(message) {
    await message.reply({
      embeds: [new EmbedBuilder()
        .setColor(ACCENT)
        .setTitle('🤖  Commandes Damnzcord')
        .addFields(
          { name: '`!createaccount`',   value: 'Crée ton compte Damnzcord lié à ton ID Discord.' },
          { name: '`!resetpassword`',   value: 'Envoie un nouveau mot de passe temporaire en DM.' },
          { name: '`!setavatar <url>`', value: 'Définit ta photo de profil via un lien image.' },
          { name: '`!moncompte`',       value: 'Affiche les infos de ton compte en DM.' },
        )
        .setFooter({ text: 'Damnzcord — aucune adresse email requis.' })],
    });
  },
};

// ─── Écoute ───────────────────────────────────────────────────────────────────

client.on('messageCreate', async (message) => {
  if (message.author.bot)                  return;
  if (!message.content.startsWith(PREFIX)) return;

  const [rawCmd, ...args] = message.content.slice(PREFIX.length).trim().split(/\s+/);
  const cmd = rawCmd.toLowerCase();
  if (!commands[cmd]) return;

  try {
    await commands[cmd](message, args);
  } catch (err) {
    console.error(`[ERREUR] !${cmd} :`, err);
    await message.reply({ embeds: [errEmbed('Erreur interne. Réessaie dans quelques instants.')] }).catch(() => {});
  }
});

// ─── Démarrage ────────────────────────────────────────────────────────────────

client.once('ready', async () => {
  const { total } = await stmts.countUsers();
  console.log(`\n✅  Bot connecté en tant que ${client.user.tag}`);
  console.log(`📦  Supabase : ${total} compte(s) enregistré(s)`);
  console.log(`🟢  En écoute avec le préfixe "${PREFIX}"\n`);
  client.user.setActivity('Damnzcord | !help', { type: 3 });
});

client.login(process.env.DISCORD_TOKEN);
