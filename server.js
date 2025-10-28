import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import cors from "cors";
import pkg from "pg";
const { Pool } = pkg;

// ✅ Corrige import do discord.js (evita o erro)
import discordPkg from "discord.js";
const {
  Client,
  GatewayIntentBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
} = discordPkg;

// 2️⃣ Criar instância do bot — apenas uma vez
const bot = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages],
});


bot.once("ready", () => {
  console.log(`Bot logado como ${bot.user.tag}`);

 bot.user.setPresence({
  activities: [{ name: process.env.BOT_STATUS, type: 3 }],
  status: "online"
});

  console.log("Status definido: Assistindo Santa Maria RP");
});


console.log("Token lido do .env:", process.env.DISCORD_TOKEN);
bot.login(process.env.DISCORD_TOKEN);


const app = express();
app.use(express.static("public"));
app.use(cookieParser());

// ✅ CORS — permitir frontend da Hostinger
app.use(cors({
  origin: ["https://testes.andredevhub.com"],
  credentials: true,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// ✅ BANCO (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ✅ Garantir tabela de usuários
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        discord_id VARCHAR(50) UNIQUE,
        username VARCHAR(100),
        avatar VARCHAR(200),
        discriminator VARCHAR(10),
        esta_no_servidor BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log("✅ Tabela 'users' verificada e atualizada");
  } catch (err) {
    console.error("❌ Erro ao verificar tabela:", err);
  }
})();

const generateState = () => crypto.randomBytes(16).toString("hex");

// ✅ Middleware de autenticação
const authMiddleware = (req, res, next) => {
  const token = req.cookies.user;
  if (!token) return res.status(401).json({ error: "Não autenticado" });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: "santamariaRP",
      audience: "frontend"
    });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ error: "Token inválido" });
  }
};

// ✅ LOGIN COM DISCORD
app.get("/api/auth/discord", (req, res) => {
  const state = generateState();
  res.cookie("oauth_state", state, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });

  const redirect = `https://discord.com/oauth2/authorize?client_id=${
    process.env.DISCORD_CLIENT_ID
  }&response_type=code&redirect_uri=${encodeURIComponent(
    process.env.DISCORD_REDIRECT_URI
  )}&scope=identify+guilds&state=${state}`;

  res.redirect(redirect);
});

// ✅ CALLBACK DO DISCORD
app.get("/api/auth/discord/callback", async (req, res) => {
  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;
  if (!state || state !== savedState) return res.status(400).send("Invalid state");

  // Limpa o cookie de state
  res.clearCookie("oauth_state");

  try {
    // Trocar código por token
    const tokenResponse = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: process.env.DISCORD_REDIRECT_URI,
      }),
    });

    const tokenData = await tokenResponse.json();
    if (tokenData.error) {
      console.error("❌ Erro ao obter token:", tokenData);
      return res.status(400).send("Erro ao autenticar com o Discord.");
    }

    // Pegar dados do usuário
    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const user = await userResponse.json();

    if (!user.id) return res.status(400).send("Erro ao buscar dados do Discord.");

    // Verificar se está no servidor
    const guildsResponse = await fetch("https://discord.com/api/users/@me/guilds", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const guilds = await guildsResponse.json();
    const estaNoServidor = guilds.some(g => g.id === "1299085549256310924");

    // Salvar no banco
    try {
      await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS status_wl VARCHAR(20) DEFAULT 'nenhum';
    `);

      await pool.query(`
        INSERT INTO users (discord_id, username, avatar, discriminator, esta_no_servidor)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (discord_id) DO UPDATE SET
          username = EXCLUDED.username,
          avatar = EXCLUDED.avatar,
          discriminator = EXCLUDED.discriminator,
          esta_no_servidor = EXCLUDED.esta_no_servidor;
      `, [user.id, user.username, user.avatar, user.discriminator, estaNoServidor]);
    } catch (err) {
      console.error("❌ Erro ao salvar usuário:", err);
    }

    // Criar JWT
    const jwtToken = jwt.sign(
      { ...user, estaNoServidor },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
        issuer: "santamariaRP",
        audience: "frontend"
      }
    );

    res.cookie("user", jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    // Webhook
    const avatarURL = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
      : "https://cdn.discordapp.com/embed/avatars/0.png";
    const horaLogin = new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" });

    if (process.env.DISCORD_WEBHOOK_URL) {
      await fetch(process.env.DISCORD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [{
            title: "🟢 Novo Login no Site",
            color: 5763719,
            thumbnail: { url: avatarURL },
            fields: [
              { name: "👤 Usuário", value: user.username, inline: true },
              { name: "🆔 ID", value: user.id, inline: true },
              { name: "🕒 Horário", value: horaLogin, inline: false },
              { name: "👥 Está no servidor?", value: estaNoServidor ? "✅ Sim" : "❌ Não", inline: true }
            ],
            footer: { text: "Painel de Login - © Santa Maria RP" },
            timestamp: new Date().toISOString(),
          }],
        }),
      });
    }

    res.redirect("https://testes.andredevhub.com/suaconta.html");
  } catch (err) {
    console.error("❌ Erro no callback:", err);
    res.status(500).send("Erro interno ao autenticar com o Discord.");
  }
});

// ✅ ROTA /api/me — usada no frontend da Hostinger
app.get("/api/me", authMiddleware, (req, res) => {
  res.json(req.user);
});

// ✅ ROTA DE LOGOUT (GET)
app.get("/api/logout", (req, res) => {
  res.clearCookie("user", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.redirect("https://testes.andredevhub.com/suaconta.html");
});

// ✅ ROTA DE LOGOUT (POST)
app.post("/api/logout", (req, res) => {
  res.clearCookie("user", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.status(200).json({ message: "Logout realizado com sucesso." });
});

// Endpoint do formulário

// ✅ Rota para consultar status atual da WL
app.get("/api/status-wl", authMiddleware, async (req, res) => {
  try {
    const { id } = req.user;
    const result = await pool.query("SELECT status_wl FROM users WHERE discord_id = $1", [id]);
    const status = result.rows[0]?.status_wl || "nenhum";
    res.json({ status });
  } catch (err) {
    console.error("❌ Erro ao buscar status WL:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// ✅ Rota para envio do formulário
app.post("/api/formulario", express.json(), async (req, res) => {
  try {
    const token = req.cookies.user;
    if (!token) return res.status(401).json({ message: "Não autenticado" });

    // Pega os dados do usuário do JWT
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const { username, id, avatar } = user;

    // 🔎 Verifica status atual da whitelist
    const result = await pool.query("SELECT status_wl FROM users WHERE discord_id = $1", [id]);
    const status = result.rows[0]?.status_wl || "nenhum";

    if (status === "pendente") {
      return res.status(400).json({
        message: "Você já enviou sua whitelist e ela está em análise.",
      });
    }

    // ⚙️ Marca como pendente no banco
    await pool.query("UPDATE users SET status_wl = 'pendente' WHERE discord_id = $1", [id]);

    // 🎯 Dados do formulário
    const { resposta1, resposta2, resposta3, resposta4, resposta5, resposta6 } = req.body;

    const logChannel = await bot.channels.fetch(process.env.LOG_CHANNEL_ID);

    const avatarURL = avatar
      ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png`
      : "https://cdn.discordapp.com/embed/avatars/0.png";

    const embed = new EmbedBuilder()
      .setTitle("📋 Nova WhiteList Recebida")
      .setThumbnail(avatarURL)
      .addFields(
        { name: "👤 Usuário", value: username, inline: true },
        { name: "🆔 ID Discord", value: id, inline: true },
        { name: "🆔 ID Roblox", value: resposta1 || "-", inline: false },
        { name: "👤 Nome do Roblox", value: resposta2 || "-", inline: false },
        { name: "🌍 Em que país moras?", value: resposta3 || "-", inline: false },
        { name: "🎂 Qual é sua idade real?", value: resposta4 || "-", inline: false },
        { name: "🎮 Você joga no PC?", value: resposta5 || "-", inline: false },
        { name: "🎧 Você tem microfone?", value: resposta6 || "-", inline: false }
      )
      .setColor(0x5865F2)
      .setFooter({ text: "Painel de Forms - © Santa Maria RP" })
      .setTimestamp();

    const buttons = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId(`aprovar_${id}`)
        .setLabel("Aprovar")
        .setStyle(ButtonStyle.Success),
      new ButtonBuilder()
        .setCustomId(`reprovar_${id}`)
        .setLabel("Reprovar")
        .setStyle(ButtonStyle.Danger)
    );

    await logChannel.send({ embeds: [embed], components: [buttons] });
    res.json({ message: "Formulário enviado com sucesso!" });

  } catch (err) {
    console.error("❌ Erro ao enviar formulário:", err);
    res.status(500).json({ message: "Erro interno" });
  }
});

// após dotenv.config();
const usuariosProcessados = new Map(); // controla quem já teve a whitelist processada

// ==================== INTERAÇÃO PRINCIPAL ====================
bot.on("interactionCreate", async (interaction) => {
  try {
    // ==================== BOTÕES ====================
    if (interaction.isButton()) {
      const [acao, discordId] = interaction.customId.split("_");

      if (!acao || !discordId) return;

      // 👉 Só bloqueia se o usuário JÁ FOI aprovado/reprovado em um modal anterior
      if (usuariosProcessados.has(discordId)) {
        await interaction.reply({
          content: `⚠️ Esta whitelist já foi ${usuariosProcessados.get(discordId)}!`,
          ephemeral: true,
        });
        return;
      }

      // Mostra o modal (sem marcar como processado ainda!)
      const modal = new ModalBuilder()
        .setCustomId(`modal_${acao}_${discordId}_${interaction.message.id}`)
        .setTitle(acao === "aprovar" ? "Motivo da Aprovação" : "Motivo da Reprovação");

      const motivoInput = new TextInputBuilder()
        .setCustomId("motivo")
        .setLabel("Digite o motivo")
        .setStyle(TextInputStyle.Paragraph)
        .setRequired(true);

      modal.addComponents(new ActionRowBuilder().addComponents(motivoInput));
      await interaction.showModal(modal);
    }

    // ==================== MODAL ENVIADO ====================
    if (interaction.isModalSubmit()) {
      const [_, acao, discordId, mensagemId] = interaction.customId.split("_");

      if (!acao || !discordId || !mensagemId) {
        await interaction.reply({
          content: "⚠️ Erro interno ao processar o modal.",
          ephemeral: true,
        });
        return;
      }

      const motivo = interaction.fields.getTextInputValue("motivo");
      const staffUser = interaction.user;

      // Agora sim, marca como processado
      usuariosProcessados.set(discordId, acao === "aprovar" ? "aprovada" : "reprovada");

      // Busca mensagem original
      let msgOriginal;
      try {
        msgOriginal = await interaction.channel.messages.fetch(mensagemId);
      } catch {
        await interaction.reply({
          content: "⚠️ Mensagem original não encontrada (pode ter sido apagada).",
          ephemeral: true,
        });
        return;
      }

      const embedOriginal = msgOriginal.embeds[0];

      // Canal de destino
      const canalDestino =
        acao === "aprovar"
          ? await bot.channels.fetch(process.env.APPROV_CHANNEL_ID)
          : await bot.channels.fetch(process.env.REPROV_CHANNEL_ID);

      // Envia embed final
      const resultadoEmbed = new EmbedBuilder()
        .setTitle(`📋 Whitelist ${acao === "aprovar" ? "Aprovada" : "Reprovada"}`)
        .setColor(acao === "aprovar" ? 0x57f287 : 0xed4245)
        .addFields(
          { name: "👤 Usuário", value: `<@${discordId}>`, inline: false },
          { name: "👮‍♂️ Moderador", value: staffUser.tag, inline: false },
          { name: "📝 Motivo", value: motivo, inline: false }
        )
        .setFooter({
          text:
            acao === "aprovar"
              ? "✅ Whitelist aprovada"
              : "❌ Whitelist reprovada",
        })
        .setTimestamp();

      await canalDestino.send({ embeds: [resultadoEmbed] });

      // Atualiza mensagem original
      const novoEmbed = EmbedBuilder.from(embedOriginal)
        .setColor(acao === "aprovar" ? 0x57f287 : 0xed4245)
        .setFooter({
          text:
            acao === "aprovar"
              ? "✅ Esta whitelist já foi aprovada"
              : "❌ Esta whitelist já foi reprovada",
        });

      const botoesDesativados = msgOriginal.components[0];
      if (botoesDesativados) {
        botoesDesativados.components =
          botoesDesativados.components.map((btn) =>
            ButtonBuilder.from(btn).setDisabled(true)
          );
      }

      await msgOriginal.edit({
        embeds: [novoEmbed],
        components: botoesDesativados ? [botoesDesativados] : [],
      });

      // Mensagem de sucesso
// Mensagem de sucesso
if (!interaction.replied) {
  await interaction.reply({
    content: `✅ Você ${acao === "aprovar" ? "aprovou" : "reprovou"} <@${discordId}> com sucesso!`,
    ephemeral: true,
  });
}

// ✅ Atualiza o status no banco conforme a ação (aprovação ou reprovação)
        await pool.query(
          "UPDATE users SET status_wl = $1 WHERE discord_id = $2",
          [acao === "aprovar" ? "aprovado" : "reprovado", discordId]
        );
      }
    }
  } catch (err) {
    console.error("❌ Erro na interação:", err);
    if (interaction.isRepliable() && !interaction.replied) {
      await interaction.reply({
        content: "⚠️ Ocorreu um erro ao processar sua ação.",
        ephemeral: true,
      });
    }
  }
});


// ✅ INICIAR SERVIDOR
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));














