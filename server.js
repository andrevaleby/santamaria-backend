import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import cors from "cors";
import pkg from "pg";
const { Pool } = pkg;

dotenv.config();

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

import { Client, GatewayIntentBits, ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder } from "discord.js";

// Inicializa o bot
const bot = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages]
});

bot.once("ready", () => {
  console.log(`🤖 Bot logado como ${bot.user.tag}`);
});

// Endpoint do formulário
app.post("/api/formulario", express.json(), async (req, res) => {
  try {
    const token = req.cookies.user;
    if (!token) return res.status(401).json({ message: "Não autenticado" });

    // Pega os dados do usuário do JWT
    const user = jwt.verify(token, process.env.JWT_SECRET);
    const { username, id, avatar } = user;

    // Dados do formulário
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
      .setFooter({ text: "Painel de Froms - © Santa Maria RP" })
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

// Interações dos botões
bot.on("interactionCreate", async (interaction) => {
  if (!interaction.isButton()) return;
  const id = interaction.customId.split("_")[1];

  if (interaction.customId.startsWith("aprovar_")) {
    const canalAprovado = await bot.channels.fetch(process.env.APPROV_CHANNEL_ID);
    await canalAprovado.send(`✅ **${id} foi aprovado!**`);
    await interaction.reply({ content: `✅ Aprovado com sucesso!`, ephemeral: true });
  } else if (interaction.customId.startsWith("reprovar_")) {
    const canalReprovado = await bot.channels.fetch(process.env.REPROV_CHANNEL_ID);
    await canalReprovado.send(`❌ **${id} foi reprovado.**`);
    await interaction.reply({ content: `❌ Reprovado com sucesso! 😭`, ephemeral: true });
  }
});

bot.login(process.env.BOT_TOKEN);

bot.on("interactionCreate", async (interaction) => {
  try {
    // 1️⃣ Botão clicado
    if (interaction.isButton()) {
      const [acao, discordId] = interaction.customId.split("_"); // ex: "aprovar_123456"

      const modal = new ModalBuilder()
        .setCustomId(`${acao}_modal_${discordId}`)
        .setTitle(acao === "aprovar" ? "Motivo da Aprovação" : "Motivo da Reprovação");

      const motivoInput = new TextInputBuilder()
        .setCustomId("motivo")
        .setLabel("Digite o motivo")
        .setStyle(TextInputStyle.Paragraph)
        .setRequired(true);

      const row = new ActionRowBuilder().addComponents(motivoInput);
      modal.addComponents(row);

      // Mostra o modal para o usuário que clicou
      await interaction.showModal(modal);
    }

    // 2️⃣ Modal enviado
    if (interaction.isModalSubmit()) {
      const [acao, , discordId] = interaction.customId.split("_modal_");
      const motivo = interaction.fields.getTextInputValue("motivo");

      const canal = acao === "aprovar"
        ? await bot.channels.fetch(process.env.APPROV_CHANNEL_ID)
        : await bot.channels.fetch(process.env.REPROV_CHANNEL_ID);

      await canal.send(`**ID do Discord:** ${discordId}\n**Ação:** ${acao === "aprovar" ? "Aprovado ✅" : "Reprovado ❌"}\n**Motivo:** ${motivo}`);

      await interaction.reply({ content: "✅ Ação registrada com motivo!", ephemeral: true });
    }
  } catch (err) {
    console.error("❌ Erro na interação do Discord:", err);
  }
});

// ✅ INICIAR SERVIDOR
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));
