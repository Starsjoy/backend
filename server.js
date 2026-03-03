import express from "express";
import pkg from "pg";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";
import crypto from "crypto";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Telegraf } from 'telegraf';
dotenv.config();
const { Pool } = pkg;

const app = express();

// ======================
// 🛡️ Trust Proxy — Nginx reverse proxy uchun
// ======================
app.set('trust proxy', 1);

// ======================
// 🛡️ SECURITY: Helmet — HTTP security headers
// ======================
app.use(helmet({
  contentSecurityPolicy: false, // API server uchun kerak emas
  crossOriginEmbedderPolicy: false,
}));

// ======================
// 🛡️ SECURITY: CORS — faqat ruxsat etilgan domenlar
// ======================
const ALLOWED_ORIGINS = [
  'https://vitahealth.uz',
  'https://www.vitahealth.uz',
  'https://web.telegram.org',
  'https://t.me',
  process.env.WEBAPP_URL,
].filter(Boolean);

// Development uchun localhost ham qo'shiladi
if (process.env.NODE_ENV !== 'production') {
  ALLOWED_ORIGINS.push('http://localhost:5173', 'http://localhost:3000', 'http://localhost:5000');
}

app.use(cors({
  origin: function (origin, callback) {
    // Server-to-server (bot.js, balanceChecker) origin=undefined bo'ladi
    if (!origin) return callback(null, true);
    
    if (ALLOWED_ORIGINS.some(allowed => origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      console.warn(`🚫 CORS bloklandi: ${origin}`);
      callback(new Error('CORS policy: Origin not allowed'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Telegram-Init-Data', 'X-Internal-Key'],
}));

app.use(express.json({ limit: '1mb' }));

// ======================
// 🛡️ SECURITY: Rate Limiting
// ======================
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 daqiqa
  max: 200, // har bir IP dan 200 ta request
  message: { error: 'Juda ko\'p so\'rov. 15 daqiqadan keyin urinib ko\'ring.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const orderLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 daqiqa
  max: 10, // har bir IP dan 10 ta order
  message: { error: 'Juda ko\'p order. 5 daqiqadan keyin urinib ko\'ring.' },
});

const searchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 daqiqa
  max: 15, // har bir IP dan 15 ta search
  message: { error: 'Juda ko\'p qidiruv. 1 daqiqadan keyin urinib ko\'ring.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Juda ko\'p urinish.' },
});

// Barcha API larga umumiy rate limit
app.use('/api/', generalLimiter);

// ======================
// 🛡️ SECURITY: Telegram WebApp initData validatsiya
// ======================
function validateTelegramInitData(initData) {
  if (!initData) return null;
  
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    
    // hash ni olib tashlaymiz va sortlaymiz
    params.delete('hash');
    const dataCheckArr = [];
    params.sort();
    params.forEach((val, key) => dataCheckArr.push(`${key}=${val}`));
    const dataCheckString = dataCheckArr.join('\n');
    
    // HMAC SHA256 bilan tekshirish
    const botToken = process.env.BOT_TOKEN;
    if (!botToken) return null;
    
    const secretKey = crypto
      .createHmac('sha256', 'WebAppData')
      .update(botToken)
      .digest();
    
    const checkHash = crypto
      .createHmac('sha256', secretKey)
      .update(dataCheckString)
      .digest('hex');
    
    if (checkHash !== hash) {
      console.warn('🚫 Telegram initData hash mos kelmadi!');
      return null;
    }
    
    // auth_date ni tekshirish (5 daqiqadan eski bo'lmasligi kerak)
    const authDate = parseInt(params.get('auth_date'));
    const now = Math.floor(Date.now() / 1000);
    if (now - authDate > 86400) { // 24 soat
      console.warn('🚫 Telegram initData muddati o\'tgan!');
      return null;
    }
    
    // User ma'lumotlarini qaytarish
    const userStr = params.get('user');
    if (!userStr) return null;
    
    return JSON.parse(userStr);
  } catch (err) {
    console.error('❌ initData validatsiya xatosi:', err.message);
    return null;
  }
}

// Telegram auth middleware — foydalanuvchi endpointlari uchun
function telegramAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  
  // Development mode da skip qilish mumkin
  if (process.env.NODE_ENV !== 'production' && !initData) {
    return next();
  }
  
  const user = validateTelegramInitData(initData);
  if (!user) {
    return res.status(401).json({ error: 'Telegram autentifikatsiya muvaffaqiyatsiz' });
  }
  
  req.telegramUser = user;
  next();
}

// ======================
// 🛡️ SECURITY: Admin auth middleware
// ======================
function adminAuth(req, res, next) {
  const initData = req.headers['x-telegram-init-data'];
  
  // Development mode da initData bo'lmasa ham o'tkazish
  if (process.env.NODE_ENV !== 'production' && !initData) {
    req.adminUser = { id: 0, username: 'dev_admin' };
    return next();
  }
  
  if (!initData) {
    return res.status(401).json({ error: 'Autentifikatsiya kerak' });
  }
  
  const user = validateTelegramInitData(initData);
  if (!user) {
    return res.status(401).json({ error: 'Telegram autentifikatsiya muvaffaqiyatsiz' });
  }
  
  const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(id => Number(id.trim()));
  
  if (!ADMIN_IDS.includes(user.id)) {
    console.warn(`🚫 Admin ruxsatsiz kirish urinishi: ${user.id} (${user.username || 'noma\'lum'})`);
    return res.status(403).json({ error: 'Sizda admin huquqi yo\'q' });
  }
  
  req.adminUser = user;
  next();
}

// ======================
// 🛡️ SECURITY: Internal API middleware (bot.js va balanceChecker uchun)
// ======================
const INTERNAL_SECRET = process.env.INTERNAL_API_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.INTERNAL_API_SECRET) {
  console.warn('⚠️ INTERNAL_API_SECRET .env da yo\'q! Tasodifiy kalit ishlatilmoqda.');
  console.log(`🔑 INTERNAL_API_SECRET=${INTERNAL_SECRET}`);
  console.log('☝️ Bu kalitni .env faylga qo\'shing va bot.js / balanceChecker.js ga ham o\'rnating!');
}

function internalAuth(req, res, next) {
  const key = req.headers['x-internal-key'];
  
  // Localhost dan kelgan so'rovlar tekshiriladi
  const ip = req.ip || req.connection?.remoteAddress || '';
  const isLocalhost = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
  
  // Tashqi IP — bloklash
  if (!isLocalhost) {
    console.warn(`🚫 Tashqi IP dan internal API ga kirish urinishi: ${ip}`);
    return res.status(403).json({ error: 'Ruxsat berilmagan' });
  }
  
  // Localhost — lekin kalit majburiy
  if (key !== INTERNAL_SECRET) {
    console.warn(`🚫 Internal API kalit noto'g'ri! IP: ${ip}`);
    return res.status(403).json({ error: 'Noto\'g\'ri kalit' });
  }
  
  next();
}
const PREMIUM_3 = parseInt(process.env.VITE_PREMIUM_3);
const PREMIUM_6 = parseInt(process.env.VITE_PREMIUM_6);
const PREMIUM_12 = parseInt(process.env.VITE_PREMIUM_12);

// 🛡️ Stars narxi — backend da ham tekshiriladi (frontendga ishonish MUMKIN EMAS!)
const STARS_PRICE_PER_UNIT = parseInt(process.env.STARS_PRICE_PER_UNIT) || parseInt(process.env.VITE_NARX);
if (!STARS_PRICE_PER_UNIT || STARS_PRICE_PER_UNIT <= 0) {
  console.error('❌ STARS_PRICE_PER_UNIT yoki VITE_NARX .env da topilmadi!');
  console.error('💡 .env faylga qo\'shing: STARS_PRICE_PER_UNIT=220');
  process.exit(1);
}
console.log(`💰 Stars narxi: 1⭐ = ${STARS_PRICE_PER_UNIT} UZS`);

// ======================
// 🤖 TELEGRAM BOT - Buyurtmalar kanaliga xabar yuborish
// ======================
const BOT_TOKEN = process.env.BOT_TOKEN;
const ORDERS_CHANNEL = -1003752422150;
let bot = null;

if (BOT_TOKEN) {
  bot = new Telegraf(BOT_TOKEN);
  console.log('✅ Telegram bot initialized for order notifications');
} else {
  console.warn('⚠️ BOT_TOKEN .env da topilmadi - orders channel xabarlar yuborilmaydi');
}

// Buyurtmalar kanali xabari yuborish funksiyasi
async function notifyOrdersChannel(message) {
  if (!bot) {
    console.log('❌ Bot ishga tushmagan, xabar yuborilmadi');
    return;
  }
  try {
    await bot.telegram.sendMessage(ORDERS_CHANNEL, message, { parse_mode: 'HTML' });
    console.log('✅ Orders channel ga xabar yuborildi');
  } catch (err) {
    console.error('❌ Orders channel xabari yuborishda xato:', err.message);
  }
}

// ======================
// 🔧 MAINTENANCE MODE (texnik ishlar rejimi)
// ======================
let maintenanceMode = false;

app.get("/api/maintenance", (req, res) => {
  res.json({ maintenance: maintenanceMode });
});

app.post("/api/admin/maintenance", adminAuth, (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: "enabled (true/false) kerak" });
  }
  maintenanceMode = enabled;
  console.log(`🔧 Maintenance mode: ${enabled ? 'YOQILDI ⛔' : 'O\'CHIRILDI ✅'}`);
  res.json({ success: true, maintenance: maintenanceMode });
});

// ======================
// Postgresga ulanish
// ======================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// ======================
// Jadval yaratish
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      username TEXT,
      recipient TEXT,             -- 🆕 RobynHood uchun kerak bo‘lgan ustun
      stars INTEGER,
      amount INTEGER NOT NULL,
      card_last4 VARCHAR(4),
      status VARCHAR(32) DEFAULT 'pending',
      transaction_id TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'transactions' ready (with recipient)");
})();


(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions_premium (
  id SERIAL PRIMARY KEY,
  username TEXT,
  recipient TEXT,               -- 🆕 RobynHood purchase uchun
  muddat_oy INTEGER,
  amount INTEGER NOT NULL,
  card_last4 VARCHAR(4),
  status VARCHAR(32) DEFAULT 'pending',
  transaction_id TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
);
  `);
  console.log("✅ Table 'transactions_premium' ready");
})();

(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS secret_informations (
  card_number TEXT,
  card_name TEXT,               
  fragment_api TEXT,
  telegram_session TEXT,
  tg_api_id TEXT,
  tg_api_hash TEXT,
  bot_token TEXT
  
);
  `);
  console.log("✅ Table 'secret_informations' ready");
})();

// ======================
// 🎁 GIFT TRANSACTIONS TABLE
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions_gift (
      id SERIAL PRIMARY KEY,
      username TEXT,
      recipient_username TEXT NOT NULL,
      gift_id TEXT NOT NULL,
      stars INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      card_last4 VARCHAR(4),
      anonymous BOOLEAN DEFAULT false,
      comment TEXT,
      status VARCHAR(32) DEFAULT 'pending',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'transactions_gift' ready");
})();

// ======================
// 🆕 REFERRAL SYSTEM TABLES
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      user_id TEXT,
      referral_code TEXT UNIQUE,
      referrer_username TEXT,
      referral_balance INTEGER DEFAULT 0,
      total_earnings INTEGER DEFAULT 0, 
      total_referrals INTEGER DEFAULT 0,
      language VARCHAR(5) DEFAULT 'uz',
      som_balance INTEGER DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);

  // som_balance ustunini qo'shish (mavjud jadvallar uchun)
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS som_balance INTEGER DEFAULT 0;
  `);

  console.log("✅ Table 'users' ready");
})();

(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS last_summa (
      amount TEXT
  
    );
  `);
  console.log("✅ Table 'last_summa' ready");
})();


(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS referral_earnings (
      id SERIAL PRIMARY KEY,
      referrer_username TEXT NOT NULL,
      referee_username TEXT NOT NULL,
      earned_stars INTEGER,
      triggered_by_transaction_id INTEGER,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'referral_earnings' ready");
})();

// referral_withdrawals jadvalini yaratish
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS referral_withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username TEXT NOT NULL,
      recipient_username TEXT NOT NULL,
      amount INTEGER NOT NULL,
      status VARCHAR(32) DEFAULT 'pending',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'referral_withdrawals' ready");
})();

// ======================
// 📊 REFERRAL LEADERBOARD (referrer_username orqali sanash)
// ======================
app.get("/api/referral/leaderboard", telegramAuth, async (req, res) => {
  try {
    const username = req.query.username;
    
    // Top 10 users by referral count (referrer_username orqali sanash)
    const top10 = (await pool.query(
      `WITH referral_counts AS (
        SELECT 
          referrer_username as username,
          COUNT(*) as referrals
        FROM users
        WHERE referrer_username IS NOT NULL
        GROUP BY referrer_username
      )
      SELECT 
        username,
        referrals,
        ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
      FROM referral_counts
      ORDER BY referrals DESC
      LIMIT 10`
    )).rows;

    let me = null;
    if (username) {
      const userRow = (await pool.query(
        `WITH referral_counts AS (
          SELECT 
            referrer_username as username,
            COUNT(*) as referrals
          FROM users
          WHERE referrer_username IS NOT NULL
          GROUP BY referrer_username
        ),
        ranked AS (
          SELECT 
            username,
            referrals,
            ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
          FROM referral_counts
        )
        SELECT * FROM ranked WHERE username = $1`, [username]
      )).rows[0];
      
      if (userRow) {
        me = userRow;
      } else {
        // User hech kimni taklif qilmagan
        me = { username, referrals: 0, rank: null };
      }
    }
    res.json({ top10, me });
  } catch (err) {
    console.error("❌ REFERRAL LEADERBOARD ERROR:", err);
    res.status(500).json({ error: "Leaderboard error" });
  }
});

// ======================
// 👥 MENING DO'STLARIM (taklif qilingan foydalanuvchilar ro'yxati)
// ======================
app.get("/api/referral/my-friends/:username", telegramAuth, async (req, res) => {
  try {
    const { username } = req.params;
    if (!username) return res.status(400).json({ error: "username kerak" });

    const clean = username.startsWith("@") ? username.slice(1) : username;

    // Bu foydalanuvchi tomonidan taklif qilingan barcha do'stlar
    const friends = await pool.query(
      `SELECT 
        username,
        created_at
       FROM users
       WHERE referrer_username = $1
       ORDER BY created_at DESC`,
      [clean]
    );

    res.json({ friends: friends.rows });
  } catch (err) {
    console.error("❌ MY FRIENDS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ======================
// 📊 REFERRAL STATS (referrer_username orqali do'stlar sonini sanash)
// ======================
app.get("/api/referral/friends-count/:username", telegramAuth, async (req, res) => {
  try {
    const { username } = req.params;
    if (!username) return res.status(400).json({ error: "username kerak" });

    const clean = username.startsWith("@") ? username.slice(1) : username;

    // referrer_username orqali do'stlar sonini sanash
    const result = await pool.query(
      `SELECT COUNT(*) as friends_count
       FROM users
       WHERE referrer_username = $1`,
      [clean]
    );

    res.json({ friends_count: parseInt(result.rows[0].friends_count) || 0 });
  } catch (err) {
    console.error("❌ FRIENDS COUNT ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ======================
// 3️⃣ Backend holati
// ======================
app.get("/api/status", (req, res) => {
  res.json({ message: "Sayt aktiv holatda ✅" });
});


// ======================
// 6️⃣ Admin panel - barcha transactionlarni olish
// ======================


app.get("/api/transactions/all", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM transactions ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ======================
// 2️⃣ Status bo‘yicha filter
// ======================
app.get("/api/transactions/status/:status", adminAuth, async (req, res) => {
  const { status } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE status=$1 ORDER BY id DESC",
      [status]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// ======================
// 3️⃣ Transaction status update
// ======================
app.patch("/api/transactions/update/:id", adminAuth, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  try {
    const result = await pool.query(
      "UPDATE transactions SET status=$1 WHERE id=$2 RETURNING *",
      [status, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Transaction not found" });
    res.json({ success: true, transaction: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});


// =================================================
// 1️⃣ Telegram userni qidirish —— RobynHood API versiyasi
// =================================================
app.post("/api/search", searchLimiter, telegramAuth, async (req, res) => {
  try {
    console.log("=== 🔍 /api/search (RobynHood) boshlandi ===");

    let { username } = req.body;
    console.log("📥 Keldi username:", username);

    if (!username) {
      return res.status(400).json({ error: "username kerak" });
    }

    const cleanUsername = username.startsWith("@")
      ? username.slice(1)
      : username;

    console.log("🧹 Tozalangan username:", cleanUsername);

    // 🟦 RobynHood API ga so‘rov yuboramiz
    console.log("🌐 RobynHood API'ga so‘rov yuborilmoqda...");

    const response = await fetch("https://robynhood.parssms.info/api/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.ROB_API_KEY, // bu yerga API key qo'yiladi
        "accept": "application/json",
      },
      body: JSON.stringify({
        product_type: "stars",
        query: cleanUsername,
        quantity: "50",
      }),
    });

    console.log("📡 Javob status kodi:", response.status);

    const text = await response.text();
    console.log("📦 API xom javob:", text);

    let data;
    try {
      data = JSON.parse(text);
    } catch (err) {
      console.error("❌ JSON parse xato:", err);
      return res.status(500).json({
        error: "API noto'g'ri format qaytardi",
        raw: text,
      });
    }

    console.log("🔍 JSON parse bo‘ldi:", data);

    if (!data.ok || !data.found) {
      return res.status(404).json({
        error: "Foydalanuvchi topilmadi",
        details: data,
      });
    }

    const found = data.found;
    const fullName = found.name || cleanUsername;
    const recipient = found.recipient;
    const photoHTML = found.photo || "";

    // HTML <img ...> dan src URL ajratamiz
    const match = photoHTML.match(/src="([^"]+)"/);
    const imageUrl = match ? match[1] : null;

    console.log("👤 Foydalanuvchi:", fullName);
    console.log("🖼️ Rasm URL:", imageUrl);
    console.log("🆔 Recipient ID:", recipient);

    return res.json({
      username: cleanUsername,
      fullName: fullName,
      imageUrl: imageUrl,
      recipient: recipient, // ⚠ MUHIM — purchase uchun shu kerak
    });

  } catch (err) {
    console.error("💥 Server xato:", err);
    return res.status(500).json({
      error: "Serverda xatolik",
      details: err.message,
    });
  }
});


// ======================
// 2️⃣ Order yaratish — RobynHood API uchun moslangan
// ======================
app.post("/api/order", orderLimiter, telegramAuth, async (req, res) => {
  try {
    const { username, recipient, stars } = req.body;

    // ⚠️ Endi recipient majburiy!
    if (!username || !recipient || !stars) {
      return res.status(400).json({
        error: "username, recipient, stars kerak"
      });
    }

    // 🛡️ SECURITY: Stars miqdorini tekshirish (integer, 50-100000)
    const starsNum = parseInt(stars);
    if (!Number.isInteger(starsNum) || starsNum < 50 || starsNum > 100000) {
      return res.status(400).json({
        error: "Stars miqdori 50 dan 100000 gacha bo'lishi kerak"
      });
    }

    // 🛡️ SECURITY: Amount ni SERVER hisoblaydi — frontendga ISHONMAYMIZ!
    const amount = starsNum * STARS_PRICE_PER_UNIT;

    const cleanUsername = username.startsWith("@")
      ? username.slice(1)
      : username;

    // 🔢 Tasodifiy offset (unique amount uchun)
    // TRANSACTION bilan race condition oldini olamiz
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      
      // Advisory lock — faqat amount generation ni serialize qiladi,
      // row-level lock yo'q, match endpointlar bloklanmaydi
      await client.query('SELECT pg_advisory_xact_lock(1001)');
      
      const pendingAmounts = await client.query(
        "SELECT amount FROM transactions WHERE status = 'pending'"
      );
      const usedAmounts = new Set(pendingAmounts.rows.map(r => r.amount));
      
      // Boshqa tablitsalardan ham pending amountlarni tekshiramiz
      const pendingPremium = await client.query(
        "SELECT amount FROM transactions_premium WHERE status = 'pending'"
      );
      pendingPremium.rows.forEach(r => usedAmounts.add(r.amount));
      
      const pendingGift = await client.query(
        "SELECT amount FROM transactions_gift WHERE status = 'pending'"
      );
      pendingGift.rows.forEach(r => usedAmounts.add(r.amount));
      
      // Unique amount topamiz
      let uniqueAmount = amount;
      let attempts = 0;
      const maxAttempts = 200;
      
      while (usedAmounts.has(uniqueAmount) && attempts < maxAttempts) {
        const offset = Math.floor(Math.random() * 101) - 50;
        uniqueAmount = amount + offset;
        attempts++;
      }
      
      if (attempts >= maxAttempts) {
        throw new Error("Unique amount topilmadi, keyinroq urinib ko'ring");
      }

      // 🟦 Yangi yozuv (recipient bilan)
      const result = await client.query(
        `INSERT INTO transactions (username, recipient, stars, amount, status, created_at)
         VALUES ($1, $2, $3, $4, 'pending', NOW())
         RETURNING *`,
        [cleanUsername, recipient, starsNum, uniqueAmount]
      );
      
      await client.query('COMMIT');
      order = result.rows[0];
      
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    console.log(
      `🧾 Order yaratildi: ${order.username} | ${order.recipient} | ${order.amount} so'm | ${order.stars}⭐`
    );

    //  BALANCE CHECKER GA SIGNAL - balansni yangilash
    try {
      fetch('http://localhost:5001/api/balance/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }

    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status FROM transactions WHERE id = $1",
          [order.id]
        );

        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE transactions SET status='expired' WHERE id=$1",
            [order.id]
          );
          console.log(`⏰ Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Expiry tekshirishda xato:", e);
      }
    }, 20 * 60 * 1000);

    res.json(order);

  } catch (err) {
    console.error("❌ /api/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
});



// ======================
// 4️⃣ Order holatini olish (to'g'ri, xavfsiz versiya)
// ======================
app.get("/api/transactions/:id", telegramAuth, async (req, res) => {
  let { id } = req.params;

  // 🛑 ID yo‘q yoki raqam emas
  if (!id || isNaN(id)) {
    return res.status(400).json({ error: "ID noto‘g‘ri yoki kiritilmagan" });
  }

  id = Number(id); // integerga aylantiramiz

  try {
    const result = await pool.query(
      "SELECT * FROM transactions WHERE id = $1",
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "Order not found" });
    }

    res.json(result.rows[0]);

  } catch (err) {
    console.error("❌ /api/transactions/:id error:", err);
    res.status(500).json({ error: "Server error" });
  }
});


// ======================
// 5️⃣ Telegram bot to‘lovni tasdiqlaydi — RobynHood versiyasi
// ======================
app.post("/api/payments/match", internalAuth, async (req, res) => {
  try {
    const { card_last4, amount } = req.body;
    if (!card_last4 || !amount)
      return res.status(400).json({ error: "card_last4 va amount kerak" });

    // 🔐 ATOMIC UPDATE - race condition oldini olish
    // SELECT va UPDATE bir vaqtda, faqat bitta request muvaffaqiyatli bo'ladi
    const updated = await pool.query(
      `UPDATE transactions
       SET status = 'completed',
           card_last4 = $1
       WHERE id = (
         SELECT id FROM transactions 
         WHERE amount = $2 AND status = 'pending' 
         ORDER BY id DESC 
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [card_last4, amount]
    );

    if (!updated.rows.length)
      return res.status(404).json({ message: "Pending payment not found" });

    const order = updated.rows[0];

    console.log(`🎉 To‘lov tasdiqlandi: ${order.username} | ${order.amount} so‘m | ${order.stars}⭐`);

    // 🎁 REFERRAL BONUS LOGIC
    processReferralBonus(order.username, order.stars, order.id)
      .catch(err => console.error("❌ Referral bonus error:", err.message));

    sendStarsToUser(order.id, order.recipient, order.stars)
      .then(tx => {
        console.log(`🌟 ${order.username} ga ${order.stars}⭐ yuborildi! TxID: ${tx}`);
      })
      .catch(err => {
        console.error("❌ Yulduz yuborishda xato:", err.message);
      });

    res.json(updated.rows[0]);

  } catch (err) {
    console.error("❌ /api/payments/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ===============================
// 🔹 ADMIN — SEND STARS MANUALLY
// ===============================
app.post("/api/admin/stars/send/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) return res.status(400).json({ error: "ID noto‘g‘ri" });

    // Orderni topamiz
    const q = await pool.query(
      "SELECT * FROM transactions WHERE id=$1",
      [id]
    );

    if (!q.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });

    const order = q.rows[0];

    if (order.status === "stars_sent")
      return res.status(400).json({ error: "Yulduzlar allaqachon yuborilgan" });

    if (!order.recipient)
      return res.status(400).json({ error: "Recipient ID topilmadi" });

    // Yulduz yuborish funksiyasi
    const result = await sendStarsToUser(order.id, order.recipient, order.stars);

    return res.json({
      success: true,
      message: "Stars yuborildi",
      result,
    });

  } catch (err) {
    console.error("❌ ADMIN SEND STARS ERROR:", err);
    return res.status(500).json({
      error: "Server xatosi",
      details: err.message,
    });
  }
});


// ======================
// 🔹 Yulduzlarni foydalanuvchiga yuborish - RobynHood API orqali --------------------------------REAL?TEST
// ======================

async function sendStarsToUser(orderId, recipientId, stars) {
  try {
    console.log("🔹 sendStarsToUser:", { orderId, recipientId, stars });

    const idempotencyKey = crypto.randomUUID();

    const purchaseBody = {
      product_type: "stars",
      recipient: recipientId,        
      quantity: String(stars),
      idempotency_key: idempotencyKey,
    };

    const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {  // real
    //const purchaseRes = await fetch("https://robynhood.parssms.info/api/test/purchase", { // test

      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "accept": "application/json",
        "X-API-Key": process.env.ROB_API_KEY,
      },
      body: JSON.stringify(purchaseBody),
    });

    const text = await purchaseRes.text();
    let data;

    try {
      data = JSON.parse(text);
    } catch (err) {
      throw new Error("Purchase API noto'g'ri format qaytardi: " + text);
    }

    console.log("📦 Purchase javob:", data);

    if (!data.transaction_id) {
      await pool.query(
        "UPDATE transactions SET status = $1 WHERE id = $2",
        ["failed", orderId]
      );
      throw new Error("Purchase error: " + JSON.stringify(data));
    }

    const txId = data.transaction_id;

    await pool.query(
      `UPDATE transactions
       SET status='stars_sent',
           transaction_id=$1
       WHERE id=$2`,
      [txId, orderId]
    );

    console.log(`✅ Stars yuborildi: ${orderId} -> ${txId}`);

    // 📢 Kanalga xabar
    sendChannelNotification(orderId, 'stars').catch(err => console.error("Notification error:", err));

    return txId;

  } catch (err) {
    console.error("❌ sendStarsToUser error:", err);
    await pool.query("UPDATE transactions SET status='error' WHERE id=$1", [orderId]);
    throw err;
  }
}

// ===============================
// 🎁 REFERRAL BONUS FUNCTION
// ===============================
async function processReferralBonus(username, stars, transactionId) {
  try {
    const clean = username.startsWith("@") ? username.slice(1) : username;

    // Foydalanuvchini topish va referrer ID olish
    const userResult = await pool.query(
      "SELECT referrer_username FROM users WHERE username = $1",
      [clean]
    );

    if (userResult.rows.length === 0) {
      // User database-da yo'q, create qilamiz
      await pool.query(
        "INSERT INTO users (username, referral_code) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING",
        [clean, crypto.randomBytes(6).toString("hex")]
      );
      return;
    }

    const referrer = userResult.rows[0].referrer_username;

    if (!referrer) {
      // Referrer yo'q, bonus yo'q
      return;
    }

    // Bonus calculation: har 50 star uchun 5 star
    const bonusStars = Math.floor(stars / 50) * 5;

    if (bonusStars <= 0) {
      return;
    }

    // Referrer balance-ga qo'shish
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE username = $2`,
      [bonusStars, referrer]
    );

    // Referral earnings log-ga qo'shish
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrer, clean, bonusStars, transactionId]
    );

    // Referrals count update
    await pool.query(
      `UPDATE users 
       SET total_referrals = total_referrals + 1
       WHERE username = $1 AND total_earnings > 0`,
      [referrer]
    );

    console.log(
      `🎁 REFERRAL BONUS: ${referrer} ga ${bonusStars}⭐ bonus qo'shildi (${clean} tomonidan ${stars} star)`
    );

    // === INFLUENCER BONUS ===
    async function processInfluencerBonus(username) {
      try {
        // Check if user already got influencer bonus
        const check = await pool.query(
          `SELECT influencer_bonus FROM users WHERE username = $1`, [username]
        );
        if (check.rows[0] && check.rows[0].influencer_bonus) return; // already given

        // Check referrals count
        const user = await pool.query(
          `SELECT total_referrals FROM users WHERE username = $1`, [username]
        );
        if (user.rows[0] && user.rows[0].total_referrals >= 10) {
          // Give bonus and mark as given
          await pool.query(
            `UPDATE users SET referral_balance = referral_balance + 25, influencer_bonus = true WHERE username = $1`, [username]
          );
          await pool.query(
            `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
             VALUES ($1, $1, 25, NULL)`, [username]
          );
          console.log(`🎉 Influencer bonus: ${username} ga 25⭐ berildi`);
        }
      } catch (err) {
        console.error("❌ Influencer bonus error:", err.message);
      }
    }

    // Check influencer bonus
    await processInfluencerBonus(referrer);
  } catch (err) {
    console.error("❌ processReferralBonus error:", err.message);
  }
}

// ======================
// 🎁 PREMIUM REFERRAL BONUS
// ======================
async function processPremiumReferralBonus(username, transactionId) {
  try {
    const clean = username.startsWith("@") ? username.slice(1) : username;

    const userResult = await pool.query(
      "SELECT referrer_username FROM users WHERE username = $1",
      [clean]
    );

    if (userResult.rows.length === 0) return;
    const referrer = userResult.rows[0].referrer_username;

    if (!referrer) return;

    const bonusStars = 25;

    // Referrer balance-ga qo'shish
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE username = $2`,
      [bonusStars, referrer]
    );

    // Referral earnings log-ga qo'shish
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrer, clean, bonusStars, transactionId]
    );

    console.log(
      `🎁 PREMIUM REFERRAL BONUS: ${referrer} ga ${bonusStars}⭐ bonus qo'shildi (${clean} premium oldi)`
    );

  } catch (err) {
    console.error("❌ processPremiumReferralBonus error:", err.message);
  }
}

//-----------------------
// 🔍 PREMIUM SEARCH (FULL LOG VERSION)
//-----------------------
app.post("/api/premium/search", searchLimiter, telegramAuth, async (req, res) => {
  try {
    let { username } = req.body;

    console.log("\n================ PREMIUM SEARCH ================");
    console.log("📥 Keldi username:", username);

    if (!username) {
      console.log("⛔ username yo‘q");
      return res.status(400).json({ error: "username kerak" });
    }

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    console.log("🧹 Tozalangan username:", clean);

    // RobynHood API
    console.log("🌐 Providerga so‘rov yuborilmoqda...");

    const response = await fetch("https://robynhood.parssms.info/api/search", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.ROB_API_KEY,
        accept: "application/json",
      },
      body: JSON.stringify({
        product_type: "premium",
        query: clean,
        months: "3",
      }),
    });

    console.log("📡 Provider status:", response.status);

    const raw = await response.text();
    console.log("📦 Provider RAW response:", raw);

    // Provider offline -> "false"
    if (raw.trim() === "false") {
      console.log("❌ Provider OFFLINE yoki IP blok");
      return res.status(503).json({
        error: "Provider offline yoki IP bloklangan"
      });
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      console.log("❌ JSON parse xato:", err);
      return res.status(502).json({
        error: "Provider noto‘g‘ri format qaytardi",
        raw
      });
    }

    console.log("🔍 Provider JSON:", data);

    if (!data.ok || !data.found) {
      console.log("❌ found=false → Premium yo‘q yoki user topilmadi");
      return res.status(404).json({
        error: "❌ Premium mavjud emas yoki user yo‘q"
      });
    }

    const found = data.found;

    console.log("👤 found object:", found);

    // 🆔 Provider ID fieldlarini tekshiramiz
    const recipientId =
      found.id ||
      found.user_id ||
      found.uid ||
      found.recipient ||
      found.telegram_id ||
      null;

    console.log("🆔 Aniqlangan recipient ID:", recipientId);

    if (!recipientId) {
      console.log("❌ Provider ID qaytarmadi!");
      return res.status(404).json({
        error: "Provider ID qaytarmadi — premium sotib bo‘lmaydi"
      });
    }

    // 🖼 Rasm URL ajratish
    let imageUrl = null;
    if (found.photo) {
      const m = found.photo.match(/src="([^"]+)"/);
      imageUrl = m ? m[1] : null;
    }

    console.log("🖼 Image URL:", imageUrl);

    // Frontendga qaytariladigan JSON
    const responseJson = {
      username: clean,
      fullName: found.name || clean,
      imageUrl,
      recipient: recipientId
    };

    console.log("➡ Frontendga qaytmoqda:", responseJson);

    return res.json(responseJson);

  } catch (err) {
    console.error("💥 PREMIUM SEARCH SERVER ERROR:", err);
    return res.status(500).json({ error: "Server xato" });
  }
});

//-----------------------
// 🧾 PREMIUM ORDER YARATISH
//-----------------------
app.post("/api/premium", orderLimiter, telegramAuth, async (req, res) => {
  try {
    console.log("\n=============== 🧾 PREMIUM ORDER YARATILMOQDA ===============");

    const { username, recipient, months } = req.body;

    console.log("📥 Keldi:", req.body);

    if (!username || !recipient || !months) {
      console.log("❌ Parametrlar yetarli emas");
      return res.status(400).json({ error: "username, recipient, months kerak" });
    }

    const clean = username.startsWith("@") ? username.slice(1) : username;
    console.log("🧹 Tozalangan username:", clean);

    const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };
    const baseAmount = priceMap[months];

    if (!baseAmount) {
      console.log("❌ months noto‘g‘ri:", months);
      return res.status(400).json({ error: "Noto‘g‘ri months" });
    }

    console.log("💰 Asosiy narx:", baseAmount);

    // 🔐 TRANSACTION bilan race condition oldini olamiz
    console.log("🔄 Takrorlanmas unique amount yaratilyapti...");
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      
      // Advisory lock — faqat amount generation ni serialize qiladi
      await client.query('SELECT pg_advisory_xact_lock(1001)');
      
      const pendingAmounts = await client.query(
        "SELECT amount FROM transactions_premium WHERE status = 'pending'"
      );
      const usedAmounts = new Set(pendingAmounts.rows.map(r => r.amount));
      
      // Boshqa tablitsalardan ham tekshiramiz
      const pendingStars = await client.query(
        "SELECT amount FROM transactions WHERE status = 'pending'"
      );
      pendingStars.rows.forEach(r => usedAmounts.add(r.amount));
      
      const pendingGift = await client.query(
        "SELECT amount FROM transactions_gift WHERE status = 'pending'"
      );
      pendingGift.rows.forEach(r => usedAmounts.add(r.amount));
      
      // Unique amount topamiz
      let unique = baseAmount;
      let attempts = 0;
      const maxAttempts = 200;
      
      while (usedAmounts.has(unique) && attempts < maxAttempts) {
        const offset = Math.floor(Math.random() * 401) - 200;
        unique = baseAmount + offset;
        attempts++;
      }
      
      if (attempts >= maxAttempts) {
        throw new Error("Unique amount topilmadi, keyinroq urinib ko'ring");
      }
      
      console.log("✅ Unique amount topildi:", unique);
      console.log("📝 Bazaga yozilmoqda...");

      const result = await client.query(
        `INSERT INTO transactions_premium (username, recipient, muddat_oy, amount, status, created_at)
         VALUES ($1,$2,$3,$4,'pending', NOW())
         RETURNING *`,
        [clean, recipient, months, unique]
      );
      
      await client.query('COMMIT');
      order = result.rows[0];
      
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    console.log("🎉 ORDER CREATE →", order);

    //  BALANCE CHECKER GA SIGNAL - balansni yangilash
    try {
      fetch('http://localhost:5001/api/balance/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'premium' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }

    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status FROM transactions_premium WHERE id = $1",
          [order.id]
        );

        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE transactions_premium SET status='expired' WHERE id=$1",
            [order.id]
          );
          console.log(`⏰ Premium Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Premium Expiry tekshirishda xato:", e);
      }
    }, 20 * 60 * 1000);

    return res.json({ success: true, order });

  } catch (err) {
    console.error("❌ PREMIUM ORDER ERROR:", err);
    return res.status(500).json({ error: "Server xato", details: err.message });
  }
});
//-----------------------
// 💳 PREMIUM PAYMENT MATCH
//-----------------------
app.post("/api/premium/match", internalAuth, async (req, res) => {
  try {
    console.log("\n=============== 💳 PREMIUM PAYMENT MATCH ===============");
    console.log("📥 Keldi:", req.body);

    const { amount, card_last4 } = req.body;

    if (!amount) {
      console.log("❌ Amount yo‘q");
      return res.status(400).json({ error: "amount kerak" });
    }

    console.log("🔎 Pending order qidirilmoqda:", amount);

    // 🔐 ATOMIC UPDATE - race condition oldini olish
    const updated = await pool.query(
      `UPDATE transactions_premium 
       SET status='completed', card_last4=$1 
       WHERE id=(
         SELECT id FROM transactions_premium 
         WHERE amount=$2 AND status='pending' 
         ORDER BY id DESC LIMIT 1 
         FOR UPDATE SKIP LOCKED
       ) 
       RETURNING *`,
      [card_last4 || null, amount]
    );

    if (!updated.rows.length) {
      console.log("❌ Pending premium TOPILMADI");
      return res.status(404).json({ error: "Pending premium topilmadi" });
    }

    const order = updated.rows[0];
    console.log("🎯 Topildi va completed:", order);

    console.log("➡ Premium yuborish funksiyasi chaqirildi");

    const sendResult = await sendPremiumToUser(order.id, order.recipient, order.muddat_oy);

    console.log("📦 sendPremiumToUser javobi:", sendResult);

    // 🎁 REFERRAL BONUS CHECK
    if (sendResult.status === "premium_sent") {
      // Bonus goes to referrer of the BUYER (order.username)
      await processPremiumReferralBonus(order.username, order.id);
    }

    return res.json({
      success: true,
      ...sendResult,
      order_id: order.id
    });

  } catch (err) {
    console.error("❌ PREMIUM MATCH ERROR:", err);
    return res.status(500).json({ error: "Server xato", details: err.message });
  }
});


// ===============================
// 🔹 PREMIUMNI FOYDALANUVCHIGA YUBORISH-----------------------------------------------REAL? TEST
// ===============================  
async function sendPremiumToUser(orderId, recipientId, months) {
  try {
    console.log("\n=============== 🚀 PREMIUM YUBORILMOQDA ===============");
    console.log("📥 Parametrlar:", { orderId, recipientId, months });

    const check = await pool.query(
      "SELECT status FROM transactions_premium WHERE id=$1",
      [orderId]
    );

    console.log("🔎 Hozirgi status:", check.rows[0]);

    if (!check.rows.length)
      return { status: "error", reason: "order_not_found" };

    if (check.rows[0].status === "premium_sent")
      return { status: "premium_sent", reason: "already_sent" };

    const idempotencyKey = crypto.randomUUID();
    console.log("🧬 Idempotency Key:", idempotencyKey);

    const body = {
      product_type: "premium",
      recipient: recipientId,
      months: String(months),
      idempotency_key: idempotencyKey
    };

    console.log("🌐 Providerga so‘rov yuborilmoqda:", body);

    const resp = await fetch("https://robynhood.parssms.info/api/purchase", {   // real
    //const resp = await fetch("https://robynhood.parssms.info/api/test/purchase", {    //test
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.ROB_API_KEY,
        accept: "application/json",
      },
      body: JSON.stringify(body)
    });

    const text = await resp.text();
    console.log("📦 Provider RAW:", text);

    let data;
    try { data = JSON.parse(text); }
    catch {
      console.log("❌ JSON parse xato!");
      await pool.query(
        "UPDATE transactions_premium SET status='failed' WHERE id=$1",
        [orderId]
      );
      return { status: "failed", reason: "invalid_api_response" };
    }

    console.log("📡 Provider JSON:", data);

    if (data.transaction_id) {
      console.log("✅ Premium success, bazaga yozilmoqda...");
      await pool.query(
        "UPDATE transactions_premium SET status='premium_sent', transaction_id=$1 WHERE id=$2",
        [data.transaction_id, orderId]
      );

      // 📢 Kanalga xabar
      sendChannelNotification(orderId, 'premium').catch(err => console.error("Notification error:", err));

      return { status: "premium_sent", transaction_id: data.transaction_id };
    }

    console.log("❌ Provider error:", data.error);

    await pool.query(
      "UPDATE transactions_premium SET status='failed' WHERE id=$1",
      [orderId]
    );

    return { status: "failed", reason: data.error || "unknown" };

  } catch (err) {
    console.log("💥 PREMIUM SEND ERROR:", err);

    await pool.query(
      "UPDATE transactions_premium SET status='error' WHERE id=$1",
      [orderId]
    );

    return { status: "error", reason: err.message };
  }
}


//-----------------------
// 🔍 PREMIUM TRANSACTION HOLATI
//-----------------------
app.get("/api/premium/transactions/:id", telegramAuth, async (req, res) => {
  try {
    console.log("\n=============== 🔍 PREMIUM STATUS CHECK ===============");

    const id = Number(req.params.id);
    console.log("📥 ID:", id);

    const result = await pool.query(
      "SELECT * FROM transactions_premium WHERE id=$1",
      [id]
    );

    if (!result.rows.length) {
      console.log("❌ Order topilmadi");
      return res.status(404).json({ error: "Order topilmadi" });
    }

    console.log("📦 Javob:", result.rows[0]);

    return res.json(result.rows[0]);

  } catch (err) {
    console.log("❌ STATUS ERROR:", err);
    return res.status(500).json({ error: "Server xato" });
  }
});

// ===============================
// 🔹 ADMIN — PREMIUM LIST   admin panel-------------------------------------------------------------------
// ===============================
app.get("/api/admin/premium/list", adminAuth, async (req, res) => {
  try {
    const { status, search } = req.query;

    let query = "SELECT * FROM transactions_premium WHERE 1=1";
    const params = [];

    // filter: status
    if (status && status !== "all") {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }

    // filter: search (username, recipient)
    if (search) {
      params.push(`%${search}%`);
      params.push(`%${search}%`);
      query += ` AND (username ILIKE $${params.length - 1} OR recipient ILIKE $${params.length})`;
    }

    query += " ORDER BY id DESC";

    const result = await pool.query(query, params);

    res.json({ success: true, orders: result.rows });

  } catch (err) {
    console.error("❌ /api/admin/premium/list ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// 🔹 ADMIN — PREMIUM GET ONE
// ===============================
app.get("/api/admin/premium/get/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto‘g‘ri" });

    const result = await pool.query(
      "SELECT * FROM transactions_premium WHERE id=$1",
      [id]
    );

    if (!result.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });

    res.json({ success: true, order: result.rows[0] });

  } catch (err) {
    console.error("❌ /api/admin/premium/get ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// 🔹 ADMIN — PREMIUM UPDATE (status)
// ===============================
app.patch("/api/admin/premium/update/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body;

    if (!id || !status)
      return res.status(400).json({ error: "ID va status kerak" });

    const result = await pool.query(
      `UPDATE transactions_premium
       SET status=$1
       WHERE id=$2
       RETURNING *`,
      [status, id]
    );

    if (!result.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });

    res.json({ success: true, updated: result.rows[0] });

  } catch (err) {
    console.error("❌ /api/admin/premium/update ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// 🔹 ADMIN — RESEND PREMIUM
// ===============================
app.post("/api/admin/premium/resend/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto‘g‘ri" });

    const orderResult = await pool.query(
      "SELECT * FROM transactions_premium WHERE id=$1",
      [id]
    );

    if (!orderResult.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });

    const order = orderResult.rows[0];

    // Premium yuborish funksiyasini chaqiramiz
    const sendResult = await sendPremiumToUser(order.id, order.username, order.muddat_oy);

    res.json({ success: true, ...sendResult });

  } catch (err) {
    console.error("❌ /api/admin/premium/resend ERROR:", err);
    return res.status(500).json({ error: "Server xatosi" });
  }
});


// ===============================
// � ADMIN — GET ALL USERS
// ===============================
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error("❌ /api/admin/users ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// �🔐 SECRET INFORMATIONS — GET-------------------------------------------------------------------
// ===============================
app.get("/api/admin/secret", adminAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM secret_informations");

    if (result.rows.length === 0) {
      const insert = await pool.query(`
        INSERT INTO secret_informations 
        (card_number, card_name, fragment_api, telegram_session, tg_api_id, tg_api_hash, bot_token)
        VALUES ('', '', '', '', '', '', '')
        RETURNING *;
      `);

      return res.json({ success: true, data: insert.rows[0] });
    }

    res.json({ success: true, data: result.rows[0] });

  } catch (err) {
    console.error("❌ /api/admin/secret ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ===============================
// 🔐 SECRET INFORMATIONS — UPDATE
// ===============================
app.patch("/api/admin/secret/update", adminAuth, async (req, res) => {
  try {
    const {
      card_number,
      card_name,
      fragment_api,
      telegram_session,
      tg_api_id,
      tg_api_hash,
      bot_token
    } = req.body;

    const result = await pool.query(
      `
      UPDATE secret_informations
      SET 
        card_number = $1,
        card_name = $2,
        fragment_api = $3,
        telegram_session = $4,
        tg_api_id = $5,
        tg_api_hash = $6,
        bot_token = $7
      RETURNING *;
      `,
      [
        card_number,
        card_name,
        fragment_api,
        telegram_session,
        tg_api_id,
        tg_api_hash,
        bot_token
      ]
    );

    res.json({ success: true, updated: result.rows[0] });

  } catch (err) {
    console.error("❌ /api/admin/secret/update ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});




// ======================
//      callback
// ======================

app.post("/api/interview/callback", (req, res) => {
  console.log("2-qism:", req.body);

  res.json({ received: true });
});



// ===============================
// 📊 LEADERBOARD STATISTICS
// ===============================
app.get("/api/stats/leaderboard", telegramAuth, async (req, res) => {
  try {
    const { username, period } = req.query;
    
    const clean = username && username.startsWith("@")
      ? username.slice(1)
      : username;

    // Period filter: daily, weekly, monthly, all (default)
    let dateFilter = "";
    if (period === "daily") {
      dateFilter = "AND created_at >= NOW() - INTERVAL '1 day'";
    } else if (period === "weekly") {
      dateFilter = "AND created_at >= NOW() - INTERVAL '7 days'";
    } else if (period === "monthly") {
      dateFilter = "AND created_at >= NOW() - INTERVAL '30 days'";
    }

    const query = `
      WITH combined AS (
        SELECT username, amount
        FROM transactions
        WHERE status = 'stars_sent'
        ${dateFilter}

        UNION ALL

        SELECT username, amount
        FROM transactions_premium
        WHERE status = 'premium_sent'
        ${dateFilter}
      ),
      summed AS (
        SELECT
          username,
          SUM(amount)::BIGINT AS total
        FROM combined
        GROUP BY username
      ),
      ranked AS (
        SELECT
          username,
          total,
          RANK() OVER (ORDER BY total DESC) AS rank
        FROM summed
      )
      SELECT * FROM ranked
      ORDER BY rank;
    `;

    const result = await pool.query(query);
    const rows = result.rows;

    const top10 = rows.slice(0, 10);

    const me = clean
      ? rows.find(
          (r) => r.username.toLowerCase() === clean.toLowerCase()
        ) || null
      : null;

    res.json({
      top10,
      me,
    });
  } catch (err) {
    console.error("❌ LEADERBOARD ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ===============================
// 👤 USER HISTORY
// ===============================
app.get("/api/user/history/:username", telegramAuth, async (req, res) => {
  try {
    let { username } = req.params;
    if (!username)
      return res.status(400).json({ error: "username kerak" });

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    const query = `
      SELECT
        id,
        username,
        stars,
        amount,
        status,
        created_at,
        'stars' AS kind
      FROM transactions
      WHERE username = $1

      UNION ALL

      SELECT
        id,
        username,
        muddat_oy AS stars,
        amount,
        status,
        created_at,
        'premium' AS kind
      FROM transactions_premium
      WHERE username = $1

      ORDER BY created_at DESC;
    `;

    const result = await pool.query(query, [clean]);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ USER HISTORY ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ===============================
// 🎁 REFERRAL SYSTEM ENDPOINTS
// ===============================

// 1️⃣ Referral code bilan user ro'yxatdan o'tish yoki kirish
app.post("/api/referral/register", authLimiter, telegramAuth, async (req, res) => {
  try {
    const { username, referral_code, language } = req.body;

    if (!username)
      return res.status(400).json({ error: "username kerak" });

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    // User mavjudligini tekshirish
    let user = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [clean]
    );

    // Telegram user_id ni olish
    const tgUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;

    if (user.rows.length === 0) {
      // Yangi user
      let referrer_username = null;

      // Referral code mavjudligini tekshirish
      if (referral_code) {
        const referrer = await pool.query(
          "SELECT username FROM users WHERE referral_code = $1",
          [referral_code]
        );
        if (referrer.rows.length === 0) {
          return res.status(400).json({ error: "Referral code noto'g'ri" });
        }
        referrer_username = referrer.rows[0].username;
      }

      // Yangi referral code generate qilish
      const new_code = crypto.randomBytes(6).toString("hex");

      // Yangi user qo'shish (user_id bilan)
      const newUser = await pool.query(
        `INSERT INTO users (username, user_id, referral_code, referrer_username, language)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING *`,
        [clean, tgUserId, new_code, referrer_username, language || 'uz']
      );

      console.log(
        `👤 Yangi user ro'yxatdan o'tdi: ${clean} (user_id: ${tgUserId}, referrer: ${referrer_username || "yo'q"}, language: ${language || 'uz'})`
      );
      return res.json(newUser.rows[0]);
    }

    // User allaqachon mavjud — user_id ni yangilash (agar hali yozilmagan bo'lsa)
    if (tgUserId && !user.rows[0].user_id) {
      await pool.query(
        "UPDATE users SET user_id = $1 WHERE username = $2",
        [tgUserId, clean]
      );
      user.rows[0].user_id = tgUserId;
      console.log(`🔄 ${clean} ga user_id yozildi: ${tgUserId}`);
    }

    res.json(user.rows[0]);
  } catch (err) {
    console.error("❌ /api/referral/register ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 2️⃣ Referral link (personal code bilan)
app.get("/api/referral/link/:username", telegramAuth, async (req, res) => {
  try {
    const { username } = req.params;

    if (!username)
      return res.status(400).json({ error: "username kerak" });

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    const user = await pool.query(
      "SELECT referral_code, referral_balance, total_referrals FROM users WHERE username = $1",
      [clean]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }

    const userData = user.rows[0];
    // const APP_URL = process.env.WEBAPP_URL || "https://vitahealth.uz";
    // const referralLink = `${APP_URL}?ref=${userData.referral_code}`;
    
    // Telegram Mini App Link
    const referralLink = `https://t.me/StarsjoyBot/starsjoy?startapp=${userData.referral_code}`;

    res.json({
      referral_code: userData.referral_code,
      referral_link: referralLink,
      referral_balance: userData.referral_balance,
      total_referrals: userData.total_referrals,
    });
  } catch (err) {
    console.error("❌ /api/referral/link ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 3️⃣ Referral statistics
app.get("/api/referral/stats/:username", telegramAuth, async (req, res) => {
  try {
    const { username } = req.params;

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    // User ma'lumotlari
    const user = await pool.query(
      `SELECT
        referral_balance,
        total_earnings,
        som_balance
       FROM users WHERE username = $1`,
      [clean]
    );

    // Real do'stlar soni - users jadvalidan referrer_username orqali
    const friendsCount = await pool.query(
      `SELECT COUNT(*) as count FROM users WHERE referrer_username = $1`,
      [clean]
    );

    if (user.rows.length === 0) {
      return res.json({
        referral_balance: 0,
        total_earnings: 0,
        som_balance: 0,
        total_referrals: parseInt(friendsCount.rows[0]?.count || 0),
      });
    }

    res.json({
      ...user.rows[0],
      total_referrals: parseInt(friendsCount.rows[0]?.count || 0),
    });
  } catch (err) {
    console.error("❌ /api/referral/stats ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 4️⃣ Referral earnings (qaysi referrallardan qancha earned)
app.get("/api/referral/earnings/:username", telegramAuth, async (req, res) => {
  try {
    const { username } = req.params;

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    const earnings = await pool.query(
      `SELECT 
        referee_username,
        earned_stars,
        created_at
       FROM referral_earnings
       WHERE referrer_username = $1
       ORDER BY created_at DESC`,
      [clean]
    );

    res.json({ earnings: earnings.rows });
  } catch (err) {
    console.error("❌ /api/referral/earnings ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 5️⃣ Referral balance claim request (Adminga notification yuborish)
app.post("/api/referral/claim-request", authLimiter, telegramAuth, async (req, res) => {
  try {
    const { username, amount } = req.body;

    if (!username || !amount)
      return res.status(400).json({ error: "username va amount kerak" });

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    // Check user existence
    const user = await pool.query(
      "SELECT referral_balance, stars FROM users WHERE username = $1",
      [clean]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }

    const balance = user.rows[0].referral_balance;

    if (balance < 50) {
      return res.status(400).json({
        error: "Yetarli balans yo'q (kamida 50 star kerak)",
        current_balance: balance,
      });
    }

    // Adminga telegram orqali xabar yuborish
    const ADMIN_IDS = (process.env.ADMIN_IDS || "7827901505").split(",");
    const BOT_TOKEN = process.env.BOT_TOKEN;

    const message = `🎁 <b>REFERRAL CLAIM REQUEST</b>\n\n` +
      `👤 User: @${clean}\n` +
      `💰 Referral Balance: ${balance} ⭐\n` +
      `✅ Claim Amount: ${amount} ⭐\n` +
      `⭐ User Stars: ${user.rows[0].stars}\n\n` +
      `<i>Admin, iltimos userni hisobiga ${amount} star qo'shing!</i>`;

    if (BOT_TOKEN) {
      for (const adminId of ADMIN_IDS) {
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            chat_id: adminId.trim(),
            text: message,
            parse_mode: "HTML"
          })
        });
      }
    }

    console.log(`📩 Claim request from @${clean}: ${amount} stars`);

    res.json({
      success: true,
      message: "So'rov adminga yuborildi",
      amount: amount
    });
  } catch (err) {
    console.error("❌ /api/referral/claim-request ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 2️⃣ Get user's withdrawal history
app.get("/api/referral/withdrawals/:username", telegramAuth, async (req, res) => {
  try {
    const { username } = req.params;
    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;

    const result = await pool.query(
      `SELECT * FROM referral_withdrawals 
       WHERE username = $1 
       ORDER BY created_at DESC 
       LIMIT 20`,
      [cleanUsername]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("❌ Get withdrawals ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 3️⃣ Admin: Get all withdrawal requests
app.get("/api/admin/referral-withdrawals", adminAuth, async (req, res) => {
  try {
    const { status } = req.query;
    
    let query = `SELECT * FROM referral_withdrawals ORDER BY created_at DESC LIMIT 100`;
    if (status && status !== "all") {
      query = `SELECT * FROM referral_withdrawals WHERE status = $1 ORDER BY created_at DESC LIMIT 100`;
    }

    const result = status && status !== "all" 
      ? await pool.query(query, [status])
      : await pool.query(query);

    res.json(result.rows);
  } catch (err) {
    console.error("❌ Admin withdrawals ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 4️⃣ Admin: Approve withdrawal (mark as stars_sent)
app.post("/api/admin/referral-withdrawals/:id/approve", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE referral_withdrawals 
       SET status = 'stars_sent' 
       WHERE id = $1 AND status = 'pending'
       RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "So'rov topilmadi yoki allaqachon ko'rib chiqilgan" });
    }

    console.log(`✅ Withdrawal #${id} approved`);
    res.json({ success: true, withdrawal: result.rows[0] });
  } catch (err) {
    console.error("❌ Approve withdrawal ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 5️⃣ Admin: Reject withdrawal (return balance)
app.post("/api/admin/referral-withdrawals/:id/reject", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;

    // Get withdrawal info first
    const withdrawal = await pool.query(
      `SELECT * FROM referral_withdrawals WHERE id = $1 AND status = 'pending'`,
      [id]
    );

    if (withdrawal.rows.length === 0) {
      return res.status(404).json({ error: "So'rov topilmadi yoki allaqachon ko'rib chiqilgan" });
    }

    const { amount, username } = withdrawal.rows[0];

    // Return balance to user
    await pool.query(
      `UPDATE users SET referral_balance = referral_balance + $1 WHERE username = $2`,
      [amount, username]
    );

    // Update status to failed
    const result = await pool.query(
      `UPDATE referral_withdrawals 
       SET status = 'failed' 
       WHERE id = $1
       RETURNING *`,
      [id]
    );

    console.log(`❌ Withdrawal #${id} rejected, ${amount} stars returned to @${username}`);
    res.json({ success: true, withdrawal: result.rows[0] });
  } catch (err) {
    console.error("❌ Reject withdrawal ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 6️⃣ Admin: Manually adjust user referral balance
app.post("/api/admin/users/:username/balance", adminAuth, async (req, res) => {
  try {
    const { username } = req.params;
    const { amount, action } = req.body;

    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;

    if (!amount || !action) {
      return res.status(400).json({ error: "amount va action kerak" });
    }

    const numAmount = parseInt(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: "Noto'g'ri miqdor" });
    }

    // Check if user exists
    const userCheck = await pool.query(
      "SELECT referral_balance FROM users WHERE username = $1",
      [cleanUsername]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }

    const currentBalance = userCheck.rows[0].referral_balance || 0;

    let newBalance;
    if (action === "add") {
      newBalance = currentBalance + numAmount;
    } else if (action === "subtract") {
      newBalance = Math.max(0, currentBalance - numAmount); // Don't go below 0
    } else {
      return res.status(400).json({ error: "action 'add' yoki 'subtract' bo'lishi kerak" });
    }

    // Update balance
    const result = await pool.query(
      `UPDATE users SET referral_balance = $1 WHERE username = $2 RETURNING username, referral_balance`,
      [newBalance, cleanUsername]
    );

    console.log(`💰 Admin: @${cleanUsername} balance ${action === 'add' ? '+' : '-'}${numAmount} ⭐ (${currentBalance} → ${newBalance})`);
    
    res.json({ 
      success: true, 
      user: result.rows[0],
      previousBalance: currentBalance,
      newBalance: newBalance,
      change: action === 'add' ? numAmount : -numAmount
    });
  } catch (err) {
    console.error("❌ Admin balance adjust ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 6.5️⃣ Admin: Manually adjust user som balance
app.post("/api/admin/users/:username/som-balance", adminAuth, async (req, res) => {
  try {
    const { username } = req.params;
    const { amount, action } = req.body;

    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;

    if (!amount || !action) {
      return res.status(400).json({ error: "amount va action kerak" });
    }

    const numAmount = parseInt(amount);
    if (isNaN(numAmount) || numAmount <= 0) {
      return res.status(400).json({ error: "Noto'g'ri miqdor" });
    }

    const userCheck = await pool.query(
      "SELECT som_balance FROM users WHERE username = $1",
      [cleanUsername]
    );

    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: "Foydalanuvchi topilmadi" });
    }

    const currentBalance = userCheck.rows[0].som_balance || 0;

    let newBalance;
    if (action === "add") {
      newBalance = currentBalance + numAmount;
    } else if (action === "subtract") {
      newBalance = Math.max(0, currentBalance - numAmount);
    } else {
      return res.status(400).json({ error: "action 'add' yoki 'subtract' bo'lishi kerak" });
    }

    const result = await pool.query(
      `UPDATE users SET som_balance = $1 WHERE username = $2 RETURNING username, som_balance`,
      [newBalance, cleanUsername]
    );

    console.log(`💰 Admin: @${cleanUsername} som_balance ${action === 'add' ? '+' : '-'}${numAmount} so'm (${currentBalance} → ${newBalance})`);

    res.json({
      success: true,
      user: result.rows[0],
      previousBalance: currentBalance,
      newBalance: newBalance,
      change: action === 'add' ? numAmount : -numAmount
    });
  } catch (err) {
    console.error("❌ Admin som balance adjust ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// 7️⃣ Original claim endpoint (Admin uchun)
app.post("/api/referral/claim", authLimiter, telegramAuth, async (req, res) => {
  try {
    const { username } = req.body;

    if (!username)
      return res.status(400).json({ error: "username kerak" });

    const clean = username.startsWith("@")
      ? username.slice(1)
      : username;

    // Check user existence
    const user = await pool.query(
      "SELECT referral_balance FROM users WHERE username = $1",
      [clean]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }

    const balance = user.rows[0].referral_balance;

    if (balance < 50) {
      return res.status(400).json({
        error: "Yetarli balans yo'q (kamida 50 star kerak)",
        current_balance: balance,
      });
    }

    // 50 star yechish
    const claimedAmount = Math.floor(balance / 50) * 50;
    const remaining = balance - claimedAmount;

    await pool.query(
      `UPDATE users 
       SET referral_balance = $1
       WHERE username = $2`,
      [remaining, clean]
    );

    console.log(
      `✅ ${clean} referral balansdan ${claimedAmount} star yechdi. Qolgan: ${remaining}`
    );

    res.json({
      success: true,
      claimed_amount: claimedAmount,
      remaining_balance: remaining,
    });
  } catch (err) {
    console.error("❌ /api/referral/claim ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ======================
// 🆕 USER LANGUAGE ENDPOINT
// ======================
app.post("/api/user/language", telegramAuth, async (req, res) => {
  try {
    const { username, language } = req.body;

    if (!username || !language) {
      return res.status(400).json({ error: "username va language kerak" });
    }

    // Validate language
    const validLanguages = ['uz', 'en', 'ru'];
    if (!validLanguages.includes(language)) {
      return res.status(400).json({ error: "Notog'ri language" });
    }

    const clean = username.startsWith("@") ? username.slice(1) : username;

    // Update user language
    const result = await pool.query(
      `UPDATE users SET language = $1 WHERE username = $2 RETURNING *`,
      [language, clean]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }

    console.log(`🌐 ${clean} language o'zgartirildi: ${language}`);
    res.json({ success: true, user: result.rows[0] });
  } catch (err) {
    console.error("❌ /api/user/language ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});

// ===============================
// 📢 CHANNEL NOTIFICATION
// ===============================
async function sendChannelNotification(orderId, type) {
  try {
    const tableMap = { stars: 'transactions', premium: 'transactions_premium', gift: 'transactions_gift' };
    const table = tableMap[type] || 'transactions';
    const res = await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [orderId]);
    const order = res.rows[0];

    if (!order) return;

    const channelId = -1003752422150; // Orders channel ID
    const botToken = process.env.BOT_TOKEN;
    
    if (!botToken) {
        console.error("❌ BOT_TOKEN topilmadi (.env)");
        return;
    }

    const date = new Date().toLocaleString("en-US", { timeZone: "Asia/Tashkent" });
    let message = "";

    if (type === 'stars') {
      message = `
#${order.id}
✨ STARS YUBORILDI

👤 Username: @${order.username.replace('@', '')}


⭐ Yuborilgan: ${order.stars}
💰 To'lov summasi: ${order.amount} so'm

📦 Transaction ID: ${order.transaction_id}
🕒 ${date}
`;
    } else if (type === 'premium') {
      message = `
💎 PREMIUM YUBORILDI
#${order.id}

👤 Username: @${order.username.replace('@', '')}

🕒 Muddat: ${order.muddat_oy} oy
💰 To‘lov summasi: ${order.amount} so‘m

📦 Transaction ID: ${order.transaction_id}
🕒 ${date}
`;
    } else if (type === 'gift') {
      const anonLabel = order.anonymous ? ' (anonim)' : '';
      message = `
🎁 GIFT YUBORILDI
#${order.id}

👤 Yuboruvchi: @${order.username.replace('@', '')}${anonLabel}
👤 Qabul qiluvchi: @${order.recipient_username.replace('@', '')}
⭐ Gift: ${order.stars}⭐
💰 To'lov summasi: ${order.amount} so'm
${order.comment ? `💬 Izoh: ${order.comment}` : ''}
🕒 ${date}
`;
    }

    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: channelId,
        text: message.trim()
      })
    });
    
    console.log(`📢 Kanalga xabar yuborildi: #${order.id} (${type})`);

  } catch (err) {
    console.error("❌ Channel notification error:", err);
  }
}

// ======================
// 🎁 GIFT — Ruxsat etilgan gift IDlar va narxlar
// ======================
const ALLOWED_GIFT_IDS = [
  "5170145012310081615", "5170233102089322756",
  "5170250947678437525", "5168103777563050263",
  "5170144170496491616", "5170314324215857265",
  "5170564780938756245", "5168043875654172773",
  "5170690322832818290", "5170521118301225164",
  "6028601630662853006", "5922558454332916696",
  "5801108895304779062", "5800655655995968830",
];

const GIFT_PRICE_MAP = { 15: 3500, 25: 5500, 50: 11000, 100: 22000 };
const GIFT_STARS_MAP = {
  "5170145012310081615": 15, "5170233102089322756": 15,
  "5170250947678437525": 25, "5168103777563050263": 25,
  "5170144170496491616": 50, "5170314324215857265": 50,
  "5170564780938756245": 50, "6028601630662853006": 50,
  "5922558454332916696": 50, "5801108895304779062": 50,
  "5800655655995968830": 50, "5168043875654172773": 100,
  "5170690322832818290": 100, "5170521118301225164": 100,
};

// ======================
// 🎁 GIFT ORDER — Order yaratish (to'lov kutish)
// ======================
app.post("/api/gift/order", orderLimiter, telegramAuth, async (req, res) => {
  try {
    const { recipientUsername, giftId, anonymous, comment } = req.body;

    if (!recipientUsername || !giftId) {
      return res.status(400).json({ error: "recipientUsername va giftId kerak" });
    }

    if (!ALLOWED_GIFT_IDS.includes(giftId)) {
      return res.status(400).json({ error: "Noto'g'ri gift ID" });
    }

    // Stars miqdorini server tekshiradi
    const serverStars = GIFT_STARS_MAP[giftId];
    if (!serverStars) {
      return res.status(400).json({ error: "Gift ID uchun narx topilmadi" });
    }

    const amount = GIFT_PRICE_MAP[serverStars];
    if (!amount) {
      return res.status(400).json({ error: "Gift narxi topilmadi" });
    }

    if (comment && comment.length > 128) {
      return res.status(400).json({ error: "Izoh 128 belgidan oshmasligi kerak" });
    }

    const cleanUsername = recipientUsername.startsWith("@")
      ? recipientUsername.slice(1)
      : recipientUsername;

    // Unique amount (stars orderlardagi kabi)
    const client = await pool.connect();
    let order;

    try {
      await client.query('BEGIN');

      // Advisory lock — faqat amount generation ni serialize qiladi,
      // row-level lock yo'q, match/send endpointlar bloklanmaydi
      await client.query('SELECT pg_advisory_xact_lock(1001)');

      const pendingAmounts = await client.query(
        "SELECT amount FROM transactions_gift WHERE status = 'pending'"
      );
      const usedAmounts = new Set(pendingAmounts.rows.map(r => r.amount));

      // Pending stars orderlardan ham tekshiramiz (karta bitta)
      const pendingStarsAmounts = await client.query(
        "SELECT amount FROM transactions WHERE status = 'pending'"
      );
      pendingStarsAmounts.rows.forEach(r => usedAmounts.add(r.amount));

      // Pending premium orderlardan ham tekshiramiz
      const pendingPremiumAmounts = await client.query(
        "SELECT amount FROM transactions_premium WHERE status = 'pending'"
      );
      pendingPremiumAmounts.rows.forEach(r => usedAmounts.add(r.amount));

      let uniqueAmount = amount;
      let attempts = 0;
      const maxAttempts = 200;

      while (usedAmounts.has(uniqueAmount) && attempts < maxAttempts) {
        const offset = Math.floor(Math.random() * 101) - 50;
        uniqueAmount = amount + offset;
        attempts++;
      }

      if (attempts >= maxAttempts) {
        throw new Error("Unique amount topilmadi, keyinroq urinib ko'ring");
      }

      const result = await client.query(
        `INSERT INTO transactions_gift
         (username, recipient_username, gift_id, stars, amount, anonymous, comment, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', NOW())
         RETURNING *`,
        [
          req.telegramUser?.username || 'unknown',
          cleanUsername,
          giftId,
          serverStars,
          uniqueAmount,
          anonymous === true,
          comment && comment.trim() ? comment.trim() : null,
        ]
      );

      await client.query('COMMIT');
      order = result.rows[0];

    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    console.log(`🎁 Gift order yaratildi: #${order.id} | @${order.username} → @${cleanUsername} | ${serverStars}⭐ | ${order.amount} so'm`);

    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status FROM transactions_gift WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE transactions_gift SET status='expired' WHERE id=$1",
            [order.id]
          );
          console.log(`⏰ Gift Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Gift expiry xatosi:", e);
      }
    }, 20 * 60 * 1000);

    res.json(order);

  } catch (err) {
    console.error("❌ /api/gift/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ======================
// 🎁 GIFT STATUS — Order holatini olish
// ======================
app.get("/api/gift/status/:id", telegramAuth, async (req, res) => {
  let { id } = req.params;

  if (!id || isNaN(id)) {
    return res.status(400).json({ error: "ID noto'g'ri" });
  }

  id = Number(id);

  try {
    const result = await pool.query(
      "SELECT * FROM transactions_gift WHERE id = $1",
      [id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Gift order topilmadi" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ /api/gift/status error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ======================
// 🎁 GIFT MATCH — SMS to'lov tasdiqlash (internal)
// ======================
app.post("/api/gift/match", internalAuth, async (req, res) => {
  try {
    const { card_last4, amount } = req.body;
    if (!card_last4 || !amount) {
      return res.status(400).json({ error: "card_last4 va amount kerak" });
    }

    const updated = await pool.query(
      `UPDATE transactions_gift
       SET status = 'completed',
           card_last4 = $1
       WHERE id = (
         SELECT id FROM transactions_gift
         WHERE amount = $2 AND status = 'pending'
         ORDER BY id DESC
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [card_last4, amount]
    );

    if (!updated.rows.length) {
      return res.status(404).json({ message: "Pending gift payment not found" });
    }

    const order = updated.rows[0];
    console.log(`🎉 Gift to'lov tasdiqlandi: #${order.id} | @${order.username} → @${order.recipient_username} | ${order.amount} so'm`);

    // Userbot orqali gift yuborish
    sendGiftToUser(order)
      .then(() => {
        console.log(`🎁 Gift yuborildi: #${order.id} → @${order.recipient_username}`);
      })
      .catch(err => {
        console.error(`❌ Gift yuborishda xato #${order.id}:`, err.message);
      });

    res.json(updated.rows[0]);

  } catch (err) {
    console.error("❌ /api/gift/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// ======================
// 🎁 GIFT SEND — Userbot (GramJS) orqali gift yuborish
// ======================
async function sendGiftToUser(order) {
  try {
    console.log(`🎁 sendGiftToUser: #${order.id} → @${order.recipient_username} | gift: ${order.gift_id}`);

    // balanceChecker.js dagi userbot orqali gift yuborish
    const giftRes = await fetch('http://localhost:5002/api/gift/send-userbot', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': INTERNAL_SECRET,
      },
      body: JSON.stringify({
        recipientUsername: order.recipient_username,
        giftId: order.gift_id,
        message: order.comment || undefined,
        anonymous: order.anonymous || false,
      }),
    });

    const giftData = await giftRes.json();

    if (!giftData.success) {
      await pool.query(
        "UPDATE transactions_gift SET status = 'error' WHERE id = $1",
        [order.id]
      );
      throw new Error(giftData.error || "Gift yuborishda xato");
    }

    // Muvaffaqiyatli — statusni yangilash
    await pool.query(
      "UPDATE transactions_gift SET status = 'gift_sent' WHERE id = $1",
      [order.id]
    );

    console.log(`✅ Gift muvaffaqiyatli yuborildi: #${order.id}`);

    // 📢 Kanalga xabar
    sendChannelNotification(order.id, 'gift').catch(err => console.error("Gift notification error:", err));

  } catch (err) {
    console.error(`❌ sendGiftToUser error #${order.id}:`, err);
    await pool.query(
      "UPDATE transactions_gift SET status = 'error' WHERE id = $1",
      [order.id]
    );
    throw err;
  }
}

// ======================
// 🎁 ADMIN — Gift buyurtmalar ro'yxati
// ======================
app.get("/api/admin/gift/list", adminAuth, async (req, res) => {
  try {
    const { status, search } = req.query;

    let query = "SELECT * FROM transactions_gift WHERE 1=1";
    const params = [];

    if (status && status !== "all") {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }

    if (search) {
      params.push(`%${search}%`);
      params.push(`%${search}%`);
      query += ` AND (username ILIKE $${params.length - 1} OR recipient_username ILIKE $${params.length})`;
    }

    query += " ORDER BY id DESC";

    const result = await pool.query(query, params);
    res.json({ success: true, orders: result.rows });

  } catch (err) {
    console.error("❌ /api/admin/gift/list ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ======================
// 🎁 ADMIN — Gift status o'zgartirish
// ======================
app.patch("/api/admin/gift/update/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { status } = req.body;

    if (!id || !status)
      return res.status(400).json({ error: "ID va status kerak" });

    const result = await pool.query(
      `UPDATE transactions_gift
       SET status=$1
       WHERE id=$2
       RETURNING *`,
      [status, id]
    );

    if (!result.rows.length)
      return res.status(404).json({ error: "Gift order topilmadi" });

    res.json({ success: true, updated: result.rows[0] });

  } catch (err) {
    console.error("❌ /api/admin/gift/update ERROR:", err);
    res.status(500).json({ error: "Server xatosi" });
  }
});

// ======================
// 🎁 ADMIN — Gift qayta yuborish
// ======================
app.post("/api/admin/gift/send/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!id) return res.status(400).json({ error: "ID noto'g'ri" });

    const q = await pool.query("SELECT * FROM transactions_gift WHERE id = $1", [id]);
    if (!q.rows.length) return res.status(404).json({ error: "Gift order topilmadi" });

    const order = q.rows[0];
    if (order.status === "gift_sent") {
      return res.status(400).json({ error: "Gift allaqachon yuborilgan" });
    }

    await sendGiftToUser(order);
    res.json({ success: true, message: "Gift yuborildi" });

  } catch (err) {
    console.error("❌ ADMIN GIFT SEND ERROR:", err);
    res.status(500).json({ error: "Server xatosi", details: err.message });
  }
});

// ======================
// run server
// ======================
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));



