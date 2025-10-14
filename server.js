// ✅ DEPENDÊNCIAS
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

// ✅ FORÇAR HTTPS (Render exige HTTPS para cookies cross-site)
app.use((req, res, next) => {
  if (
    req.headers["x-forwarded-proto"] !== "https" &&
    process.env.NODE_ENV === "production"
  ) {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

// ✅ PERMITIR FRONTEND DO NETLIFY
app.use(
  cors({
    origin: [
      "https://santamariarpteste.netlify.app",
      "https://*.netlify.app",
    ],
    credentials: true,
  })
);

// ✅ CONEXÃO COM BANCO DO RENDER (PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ✅ GARANTIR TABELA USERS
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      discord_id VARCHAR(50) UNIQUE,
      username VARCHAR(100),
      avatar VARCHAR(200),
      discriminator VARCHAR(10),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log("✅ Tabela 'users' verificada");
})();

const generateState = () => crypto.randomBytes(16).toString("hex");

// ✅ LOGIN COM DISCORD
app.get("/api/auth/discord", (req, res) => {
  const state = generateState();
  res.cookie("oauth_state", state, { httpOnly: true, sameSite: "lax" });

  const redirect = `https://discord.com/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(
    process.env.DISCORD_REDIRECT_URI
  )}&scope=identify+guilds&state=${state}`;

  res.redirect(redirect);
});

// ✅ CALLBACK DO DISCORD
app.get("/api/auth/discord/callback", async (req, res) => {
  const { code, state } = req.query;
  const savedState = req.cookies.oauth_state;

  if (!state || state !== savedState)
    return res.status(400).send("Invalid state");

  try {
    // Trocar código por access_token
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
      console.error("Erro ao pegar token:", tokenData);
      return res.status(400).send("Erro ao autenticar com o Discord (token).");
    }

    // Buscar dados do usuário
    const userResponse = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const user = await userResponse.json();
    if (!user.id) {
      console.error("Erro ao buscar usuário:", user);
      return res.status(400).send("Erro ao autenticar com o Discord (user).");
    }

    // Salvar/atualizar no banco
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
    const jwtToken = jwt.sign(user, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    // ✅ Cookie compatível com Netlify e todos os navegadores
    res.cookie("user", jwtToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });

    // Redirecionar pro site
    res.redirect("https://santamariarpteste.netlify.app/suaconta");
  } catch (err) {
    console.error("Erro no callback Discord:", err);
    res.status(500).send("Erro ao autenticar com o Discord.");
  }
});

// ✅ ROTA DE PERFIL
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

// ✅ ROTA DE LOGOUT
app.get("/api/logout", (req, res) => {
  res.clearCookie("user", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.redirect("https://santamariarpteste.netlify.app/");
});

// ✅ INICIAR SERVIDOR
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));

