const express = require("express");
const fetch = require("node-fetch");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const { Pool } = require("pg");

dotenv.config();

const app = express();
app.use(express.static("public"));
app.use(cookieParser());
app.use(express.json());

// ✅ CORS — permitir frontend da Hostinger
app.use(cors({
  origin: "https://testes.andredevhub.com",
  credentials: true
}));

// ✅ BANCO (Render)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ✅ Garantir tabela de usuários
(async () => {
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
  console.log("✅ Tabela 'users' verificada");
})();

const generateState = () => crypto.randomBytes(16).toString("hex");

// ✅ LOGIN COM DISCORD
app.get("/api/auth/discord", (req, res) => {
  const state = generateState();
  res.cookie("oauth_state", state, { httpOnly: true, secure: true, sameSite: "none" });

  const redirect = `https://discord.com/oauth2/authorize?client_id=${
    process.env.DISCORD_CLIENT_ID
  }&response_type=code&redirect_uri=${encodeURIComponent(
    process.env.DISCORD_REDIRECT_URI
  )}&scope=identify+guilds&state=${state}`;

  res.redirect(redirect);
});

// ✅ CALLBACK DO DISCORD (Render)
app.get("/api/auth/discord/callback", async (req, res) => {
  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;
  if (!state || state !== savedState) return res.status(400).send("Invalid state");

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

    // Salvar usuário no banco
    await pool.query(
      `
      INSERT INTO users (discord_id, username, avatar, discriminator)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (discord_id) DO UPDATE SET
      username = EXCLUDED.username,
      avatar = EXCLUDED.avatar,
      discriminator = EXCLUDED.discriminator;
    `,
      [user.id, user.username, user.avatar, user.discriminator]
    );

    // Criar JWT
    const jwtToken = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: "1h" });

    // Salvar cookie
    res.cookie("user", jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    // Verificar se o usuário está no servidor
    const guildsResponse = await fetch("https://discord.com/api/users/@me/guilds", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const guilds = await guildsResponse.json();

    const estaNoServidor = Array.isArray(guilds) && guilds.some(g => g.id === "1299085549256310924");

    // Enviar webhook
    const avatarURL = user.avatar
      ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
      : "https://cdn.discordapp.com/embed/avatars/0.png";

    const horaLogin = new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" });

    await fetch(process.env.DISCORD_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        embeds: [
          {
            title: "🟢 Novo Login no Site",
            color: estaNoServidor ? 5763719 : 15548997, // verde se estiver, vermelho se não
            thumbnail: { url: avatarURL },
            fields: [
              { name: "👤 Usuário", value: user.username, inline: true },
              { name: "🆔 ID", value: user.id, inline: true },
              {
                name: "🎮 Está no servidor?",
                value: estaNoServidor ? "✅ Sim" : "❌ Não",
                inline: false,
              },
              { name: "🕒 Horário", value: horaLogin, inline: false },
            ],
            footer: { text: "Painel Santa Maria RP" },
            timestamp: new Date().toISOString(),
          },
        ],
      }),
    });

    // Redirecionar
    if (!estaNoServidor) {
      return res.redirect("https://testes.andredevhub.com/naodiscord.html");
    }

    res.redirect("https://testes.andredevhub.com/suaconta.html");
  } catch (err) {
    console.error("❌ Erro no callback:", err);
    res.status(500).send("Erro interno ao autenticar com o Discord.");
  }
});


    // ✅ Redirecionar para sua hospedagem (Hostinger)
    res.redirect("https://testes.andredevhub.com/suaconta.html");

  } catch (err) {
    console.error("❌ Erro no callback:", err);
    res.status(500).send("Erro interno ao autenticar com o Discord.");
  }
});

// ✅ ROTA /api/me
app.get("/api/me", (req, res) => {
  const token = req.cookies.user;
  if (!token) return res.status(401).json({ error: "Não autenticado" });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    res.json(user);
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
});

// ✅ LOGOUT
app.get("/api/logout", (req, res) => {
  res.clearCookie("user", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.redirect("https://testes.andredevhub.com/suaconta.html");
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('user', {
    httpOnly: true,
    sameSite: 'none',
    secure: true
  });
  res.status(200).json({ message: 'Logout realizado com sucesso.' });
});

// ✅ INICIAR SERVIDOR
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));

