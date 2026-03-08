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
const SUBSCRIPTION_CHANNEL = "@starsjoyuz"; // Obuna bo'lish kerak bo'lgan kanal
const WEBAPP_URL = process.env.WEBAPP_URL || "https://vitahealth.uz";
let bot = null;
if (BOT_TOKEN) {
  bot = new Telegraf(BOT_TOKEN);
  console.log('✅ Telegram bot initialized for order notifications');
} else {
  console.warn('⚠️ BOT_TOKEN .env da topilmadi - orders channel xabarlar yuborilmaydi');
}

// 🎉 Yangi foydalanuvchiga xush kelibsiz xabari yuborish
async function sendWelcomeMessage(userId, userName) {
  if (!bot || !userId) {
    console.log('❌ Bot ishga tushmagan yoki userId yo\'q, xabar yuborilmadi');
    return;
  }
  try {
    const welcomeText = `🎉 <b>Xush kelibsiz, ${userName || 'do\'stim'}!</b>

✨ <b>StarsJoy</b> — Telegram Stars va Premium xarid qilishning eng qulay va ishonchli platformasi!

📢 Kanalimizga obuna bo'ling va barcha yangiliklar, chegirmalar va maxsus takliflardan xabardor bo'ling!

Stars xarid qilish
Premium sotib olish
Do'stlaringizga Gift yuborish

Barchasi bir joyda — <b>StarsJoy</b>!`;

    await bot.telegram.sendMessage(userId, welcomeText, {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [
            { text: '�Start', url: 'https://t.me/StarsjoyBot?start=welcome' }
          ],
          
        ]
      }
    });
    console.log(`✅ Xush kelibsiz xabari yuborildi: ${userId} (${userName})`);
  } catch (err) {
    console.error('❌ Xush kelibsiz xabari yuborishda xato:', err.message);
  }
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
// 📢 BROADCAST — Barcha foydalanuvchilarga xabar yuborish (Bot API)
// ======================
app.post("/api/admin/broadcast", adminAuth, async (req, res) => {
  try {
    const { message, parseMode } = req.body;
    
    if (!message || !message.trim()) {
      return res.status(400).json({ error: "Xabar matni kerak" });
    }
    
    // Barcha user_id larni olish
    const usersResult = await pool.query(
      "SELECT DISTINCT user_id FROM users WHERE user_id IS NOT NULL AND user_id != ''"
    );
    
    const users = usersResult.rows;
    const totalUsers = users.length;
    
    if (totalUsers === 0) {
      return res.json({ success: true, sent: 0, failed: 0, total: 0 });
    }
    
    console.log(`📢 Broadcast boshlanmoqda: ${totalUsers} ta foydalanuvchiga`);
    
    let sent = 0;
    let failed = 0;
    const errors = [];
    
    // Bot token orqali yuborish (Telegraf bot ishlamasa ham ishlaydi)
    const botToken = process.env.BOT_TOKEN;
    if (!botToken) {
      return res.status(500).json({ error: "BOT_TOKEN topilmadi" });
    }
    
    // Har bir foydalanuvchiga xabar yuborish
    const BATCH_SIZE = 25;
    const DELAY_MS = 50;
    
    for (let i = 0; i < users.length; i += BATCH_SIZE) {
      const batch = users.slice(i, i + BATCH_SIZE);
      
      const promises = batch.map(async (user) => {
        try {
          const response = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              chat_id: user.user_id,
              text: message.trim(),
              parse_mode: parseMode || 'HTML',
              disable_web_page_preview: true
            })
          });
          
          const data = await response.json();
          
          if (data.ok) {
            sent++;
            return { success: true, user_id: user.user_id };
          } else {
            failed++;
            // Blocked yoki deleted users
            if (!data.description?.includes('blocked') && !data.description?.includes('deactivated')) {
              errors.push({ user_id: user.user_id, error: data.description });
            }
            return { success: false, user_id: user.user_id, error: data.description };
          }
        } catch (err) {
          failed++;
          return { success: false, user_id: user.user_id, error: err.message };
        }
      });
      
      await Promise.all(promises);
      
      // Rate limit uchun kutish
      if (i + BATCH_SIZE < users.length) {
        await new Promise(resolve => setTimeout(resolve, DELAY_MS));
      }
    }
    
    console.log(`📢 Broadcast tugadi: ${sent}/${totalUsers} yuborildi, ${failed} xato`);
    
    res.json({
      success: true,
      sent,
      failed,
      total: totalUsers,
      errors: errors.slice(0, 10)
    });
    
  } catch (err) {
    console.error("❌ /api/admin/broadcast ERROR:", err);
    res.status(500).json({ error: "Server xatosi", details: err.message });
  }
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
// 📦 UNIFIED ORDERS TABLE (yangi optimallashtirilgan jadval)
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      order_id TEXT NOT NULL,
      owner_user_id TEXT,
      recipient_username TEXT,
      recipient TEXT,
      order_type VARCHAR(32) NOT NULL,
      type_amount INTEGER NOT NULL,
      summ INTEGER NOT NULL,
      payment_method VARCHAR(32),
      payment_status VARCHAR(32) DEFAULT 'pending',
      status VARCHAR(32) DEFAULT 'pending',
      transaction_id TEXT,
      gift_id TEXT,
      gift_anonymous BOOLEAN DEFAULT false,
      gift_comment TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'orders' ready (unified)");
})();
// ======================
// 🆕 REFERRAL SYSTEM TABLES
// ======================
(async () => {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT,
      username TEXT UNIQUE NOT NULL,
      user_id TEXT UNIQUE,
      referral_code TEXT UNIQUE,
      referrer_user_id TEXT,
      referral_balance INTEGER DEFAULT 0,
      total_earnings INTEGER DEFAULT 0, 
      total_referrals INTEGER DEFAULT 0,
      subscribe_user BOOLEAN DEFAULT false,
      language VARCHAR(5) DEFAULT 'uz',
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);

  console.log("✅ Table 'users' ready (yangi tuzilma)");
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
// ======================
// 🏷️ DISCOUNT PACKAGES TABLE
// ======================
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discount_packages (
      id SERIAL PRIMARY KEY,
      stars INTEGER NOT NULL,
      discount_percent INTEGER NOT NULL,
      discounted_price INTEGER NOT NULL,
      is_active BOOLEAN DEFAULT true,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent'),
      updated_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')
    );
  `);
  console.log("✅ Table 'discount_packages' ready");
})();
// ======================
// 📊 REFERRAL LEADERBOARD (referrer_user_id orqali sanash - faqat subscribe_user = true)
// ======================
app.get("/api/referral/leaderboard", telegramAuth, async (req, res) => {
  try {
    const { user_id, period } = req.query;
    
    // Period filter: daily, weekly, monthly, all (default)
    // Do'stning ro'yxatdan o'tgan sanasi (created_at) bo'yicha filter
    let dateFilter = "";
    if (period === "daily") {
      dateFilter = "AND u1.created_at >= NOW() - INTERVAL '1 day'";
    } else if (period === "weekly") {
      dateFilter = "AND u1.created_at >= NOW() - INTERVAL '7 days'";
    } else if (period === "monthly") {
      dateFilter = "AND u1.created_at >= NOW() - INTERVAL '30 days'";
    }
    
    // Top 10 users by referral count (faqat kanalga obuna bo'lgan do'stlarni sanash)
    const top10 = (await pool.query(
      `WITH referral_counts AS (
        SELECT 
          u2.username,
          u2.name,
          u2.user_id,
          COALESCE(u2.name, u2.username, 'Foydalanuvchi') AS nickname,
          COUNT(*) as referrals
        FROM users u1
        JOIN users u2 ON u1.referrer_user_id = u2.user_id
        WHERE u1.referrer_user_id IS NOT NULL
          AND u1.subscribe_user = true
          ${dateFilter}
        GROUP BY u2.user_id, u2.username, u2.name
      )
      SELECT 
        username,
        name,
        user_id,
        nickname,
        referrals,
        ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
      FROM referral_counts
      ORDER BY referrals DESC
      LIMIT 10`
    )).rows;
    let me = null;
    if (user_id) {
      const userRow = (await pool.query(
        `WITH referral_counts AS (
          SELECT 
            u2.user_id,
            u2.username,
            u2.name,
            COALESCE(u2.name, u2.username, 'Foydalanuvchi') AS nickname,
            COUNT(*) as referrals
          FROM users u1
          JOIN users u2 ON u1.referrer_user_id = u2.user_id
          WHERE u1.referrer_user_id IS NOT NULL
            AND u1.subscribe_user = true
            ${dateFilter}
          GROUP BY u2.user_id, u2.username, u2.name
        ),
        ranked AS (
          SELECT 
            user_id,
            username,
            name,
            nickname,
            referrals,
            ROW_NUMBER() OVER (ORDER BY referrals DESC) as rank
          FROM referral_counts
        )
        SELECT * FROM ranked WHERE user_id = $1`, [user_id]
      )).rows[0];
      
      if (userRow) {
        me = userRow;
      } else {
        // User hech kimni taklif qilmagan (yoki do'stlari hali obuna bo'lmagan)
        const userData = (await pool.query('SELECT username, name FROM users WHERE user_id = $1', [user_id])).rows[0];
        me = { user_id, username: userData?.username, name: userData?.name, nickname: userData?.name || userData?.username || 'Foydalanuvchi', referrals: 0, rank: null };
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
app.get("/api/referral/my-friends/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id) return res.status(400).json({ error: "user_id kerak" });
    
    // Barcha do'stlarni olish (aktiv va inaktiv)
    const friends = await pool.query(
      `SELECT 
        name,
        username,
        user_id,
        subscribe_user,
        created_at
       FROM users
       WHERE referrer_user_id = $1
       ORDER BY subscribe_user DESC, created_at DESC`,
      [user_id]
    );
    
    // Kutilayotgan (hali obuna bo'lmagan) do'stlar soni
    const pendingCount = await pool.query(
      `SELECT COUNT(*) as count FROM users
       WHERE referrer_user_id = $1 AND subscribe_user = false`,
      [user_id]
    );
    
    res.json({ 
      friends: friends.rows,
      pending_count: parseInt(pendingCount.rows[0].count) || 0
    });
  } catch (err) {
    console.error("❌ MY FRIENDS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// 📊 REFERRAL STATS (referrer_user_id orqali do'stlar sonini sanash)
// ======================
app.get("/api/referral/friends-count/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id) return res.status(400).json({ error: "user_id kerak" });
    // Faqat kanalga obuna bo'lgan (aktiv) do'stlar sonini sanash
    const result = await pool.query(
      `SELECT COUNT(*) as friends_count
       FROM users
       WHERE referrer_user_id = $1
         AND subscribe_user = true`,
      [user_id]
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
// 6️⃣ Admin panel - barcha transactionlarni olish (faqat stars)
// ======================
app.get("/api/transactions/all", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        o.id,
        o.order_id,
        o.owner_user_id,
        u.username AS sender_username,
        o.recipient_username AS username,
        o.recipient,
        o.type_amount AS stars,
        o.summ AS amount,
        o.status,
        o.payment_status,
        o.transaction_id,
        o.created_at,
        o.order_type
      FROM orders o
      LEFT JOIN users u ON o.owner_user_id = u.user_id
      WHERE o.order_type = 'stars'
      ORDER BY o.id DESC
    `);
    
    // Status mapping: completed → stars_sent
    const mapped = result.rows.map(row => ({
      ...row,
      status: row.status === 'completed' ? 'stars_sent' : row.status
    }));
    
    res.json(mapped);
  } catch (err) {
    console.error("❌ /api/transactions/all ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 2️⃣ Status bo‘yicha filter
// ======================
app.get("/api/transactions/status/:status", adminAuth, async (req, res) => {
  let { status } = req.params;
  
  // Legacy status mapping: frontend "stars_sent" yuborsa, DB da "completed" qidiramiz
  const dbStatus = status === 'stars_sent' ? 'completed' : status;
  
  try {
    const result = await pool.query(
      `SELECT 
        o.id,
        o.order_id,
        o.owner_user_id,
        u.username AS sender_username,
        o.recipient_username AS username,
        o.recipient,
        o.type_amount AS stars,
        o.summ AS amount,
        o.status,
        o.payment_status,
        o.transaction_id,
        o.created_at,
        o.order_type
      FROM orders o
      LEFT JOIN users u ON o.owner_user_id = u.user_id
      WHERE o.status = $1 AND o.order_type = 'stars'
      ORDER BY o.id DESC`,
      [dbStatus]
    );
    
    // Status mapping: completed → stars_sent
    const mapped = result.rows.map(row => ({
      ...row,
      status: row.status === 'completed' ? 'stars_sent' : row.status
    }));
    
    res.json(mapped);
  } catch (err) {
    console.error("❌ /api/transactions/status ERROR:", err);
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
      "UPDATE orders SET status=$1 WHERE id=$2 RETURNING *",
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
// 2️⃣ Order yaratish — YANGI orders jadvaliga yozadi
// ======================
app.post("/api/order", orderLimiter, telegramAuth, async (req, res) => {
  try {
    const { username, recipient, stars, amount: requestedAmount } = req.body;
    // ⚠️ Endi recipient majburiy!
    if (!username || !recipient || !stars) {
      return res.status(400).json({
        error: "username, recipient, stars kerak"
      });
    }
    // 🛡️ SECURITY: Stars miqdorini tekshirish (integer, 50-10000)
    const starsNum = parseInt(stars);
    if (!Number.isInteger(starsNum) || starsNum < 50 || starsNum > 10000) {
      return res.status(400).json({
        error: "Stars miqdori 50 dan 10000 gacha bo'lishi kerak"
      });
    }
    // Telegram user_id olish
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;
    // 🛡️ SECURITY: Chegirma paketi yoki oddiy narxni tekshirish
    let amount;
    
    if (requestedAmount) {
      // Chegirma paketi orqali buyurtma - narxni tekshiramiz
      const discountCheck = await pool.query(
        "SELECT * FROM discount_packages WHERE stars = $1 AND discounted_price = $2 AND is_active = true",
        [starsNum, requestedAmount]
      );
      
      if (discountCheck.rows.length > 0) {
        amount = requestedAmount;
        console.log(`🏷️ Chegirma paketi: ${starsNum} stars = ${amount} so'm`);
      } else {
        const normalPrice = starsNum * STARS_PRICE_PER_UNIT;
        if (requestedAmount === normalPrice) {
          amount = normalPrice;
        } else {
          return res.status(400).json({
            error: "Noto'g'ri narx. Iltimos, qaytadan urinib ko'ring."
          });
        }
      }
    } else {
      amount = starsNum * STARS_PRICE_PER_UNIT;
    }
    const cleanUsername = username.startsWith("@")
      ? username.slice(1)
      : username;
    // 🔢 Unique summ generatsiya
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1002)');
      
      const uniqueSum = await generateUniqueOrderSum(amount, client);
      const orderId = crypto.randomUUID();
      // 🟦 YANGI orders jadvaliga yozish
      const result = await client.query(
        `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, created_at)
         VALUES ($1, $2, $3, $4, 'stars', $5, $6, 'card', 'pending', 'pending', NOW())
         RETURNING *`,
        [orderId, ownerUserId, cleanUsername, recipient, starsNum, uniqueSum]
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
      `🧾 Stars Order yaratildi: #${order.id} | ${cleanUsername} | ${order.summ} so'm | ${order.type_amount}⭐`
    );
    // BALANCE CHECKER GA SIGNAL
    try {
      fetch('http://localhost:5001/api/balance/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'unified' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }
    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          console.log(`⏰ Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Expiry tekshirishda xato:", e);
      }
    }, 20 * 60 * 1000);
    // Backward compatible response
    res.json({
      id: order.id,
      username: cleanUsername,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: order.status,
      created_at: order.created_at
    });
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
      "SELECT * FROM orders WHERE id = $1",
      [id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ message: "Order not found" });
    }
    const order = result.rows[0];
    // Backward compatible status mapping
    let legacyStatus = order.status;
    if (order.status === 'processing') {
      // To'lov qabul qilindi, yuborilmoqda
      legacyStatus = 'payment_received';
    } else if (order.status === 'completed') {
      if (order.order_type === 'stars') legacyStatus = 'stars_sent';
      else if (order.order_type === 'premium') legacyStatus = 'premium_sent';
      else if (order.order_type === 'gift') legacyStatus = 'gift_sent';
    }
    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: legacyStatus,
      payment_status: order.payment_status,
      created_at: order.created_at,
      order_type: order.order_type,
      transaction_id: order.transaction_id
    });
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
    // 🔐 ATOMIC UPDATE - orders jadvalidan
    const updated = await pool.query(
      `UPDATE orders
       SET payment_status = 'paid',
           status = CASE WHEN status = 'pending' THEN 'processing' ELSE status END
       WHERE id = (
         SELECT id FROM orders 
         WHERE summ = $1 AND payment_status = 'pending' 
         ORDER BY id DESC 
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [amount]
    );
    if (!updated.rows.length)
      return res.status(404).json({ message: "Pending payment not found" });
    const order = updated.rows[0];
    console.log(`🎉 To'lov tasdiqlandi: #${order.id} | ${order.summ} so'm | ${order.order_type}`);
    // 🎁 Turga qarab delivery
    if (order.order_type === 'stars') {
      processReferralBonus(order.recipient_username, order.type_amount, order.id)
        .catch(err => console.error("❌ Referral bonus error:", err.message));
      sendStarsToUser(order.id, order.recipient, order.type_amount)
        .then(tx => {
          console.log(`🌟 ${order.recipient_username} ga ${order.type_amount}⭐ yuborildi! TxID: ${tx}`);
        })
        .catch(err => {
          console.error("❌ Yulduz yuborishda xato:", err.message);
        });
    } else if (order.order_type === 'premium') {
      deliverPremiumOrder(order)
        .catch(err => console.error("❌ Premium delivery error:", err.message));
    } else if (order.order_type === 'gift') {
      sendGiftToUser(order)
        .catch(err => console.error("❌ Gift delivery error:", err.message));
    }
    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: order.status,
      payment_status: order.payment_status,
      order_type: order.order_type
    });
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
    // Orderni topamiz (orders jadvalidan)
    const q = await pool.query(
      "SELECT * FROM orders WHERE id=$1",
      [id]
    );
    if (!q.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });
    const order = q.rows[0];
    if (order.status === "completed")
      return res.status(400).json({ error: "Yulduzlar allaqachon yuborilgan" });
    if (!order.recipient)
      return res.status(400).json({ error: "Recipient ID topilmadi" });
    // Yulduz yuborish funksiyasi
    const result = await sendStarsToUser(order.id, order.recipient, order.type_amount);
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
        "UPDATE orders SET status = 'failed' WHERE id = $1",
        [orderId]
      );
      throw new Error("Purchase error: " + JSON.stringify(data));
    }
    const txId = data.transaction_id;
    await pool.query(
      `UPDATE orders
       SET status='completed',
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
    await pool.query("UPDATE orders SET status='error' WHERE id=$1", [orderId]);
    throw err;
  }
}
// ===============================
// 🎁 REFERRAL BONUS FUNCTION
// ===============================
async function processReferralBonus(username, stars, transactionId) {
  try {
    const clean = username.startsWith("@") ? username.slice(1) : username;
    // Foydalanuvchini topish va referrer user_id olish
    const userResult = await pool.query(
      "SELECT user_id, referrer_user_id FROM users WHERE username = $1",
      [clean]
    );
    if (userResult.rows.length === 0) {
      // User database-da yo'q, skip
      return;
    }
    const referrerUserId = userResult.rows[0].referrer_user_id;
    const userUserId = userResult.rows[0].user_id;
    if (!referrerUserId) {
      // Referrer yo'q, bonus yo'q
      return;
    }
    // Referrer ma'lumotlarini olish
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    if (referrerResult.rows.length === 0) {
      return;
    }
    const referrerUsername = referrerResult.rows[0].username;
    // Bonus calculation: har 50 star uchun 5 star
    const bonusStars = Math.floor(stars / 50) * 5;
    if (bonusStars <= 0) {
      return;
    }
    // Referrer balance-ga qo'shish (user_id orqali)
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    // Referral earnings log-ga qo'shish
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, clean, bonusStars, transactionId]
    );
    // Referrals count update
    await pool.query(
      `UPDATE users 
       SET total_referrals = total_referrals + 1
       WHERE user_id = $1 AND total_earnings > 0`,
      [referrerUserId]
    );
    console.log(
      `🎁 REFERRAL BONUS: ${referrerUsername} (${referrerUserId}) ga ${bonusStars}⭐ bonus qo'shildi (${clean} tomonidan ${stars} star)`
    );
    // === INFLUENCER BONUS ===
    async function processInfluencerBonus(userId) {
      try {
        // Check if user already got influencer bonus
        const check = await pool.query(
          `SELECT influencer_bonus FROM users WHERE user_id = $1`, [userId]
        );
        if (check.rows[0] && check.rows[0].influencer_bonus) return; // already given
        // Check referrals count
        const user = await pool.query(
          `SELECT total_referrals, username FROM users WHERE user_id = $1`, [userId]
        );
        if (user.rows[0] && user.rows[0].total_referrals >= 10) {
          // Give bonus and mark as given
          await pool.query(
            `UPDATE users SET referral_balance = referral_balance + 15, influencer_bonus = true WHERE user_id = $1`, [userId]
          );
          await pool.query(
            `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
             VALUES ($1, $1, 15, NULL)`, [user.rows[0].username]
          );
          console.log(`🎉 Influencer bonus: ${user.rows[0].username} ga 15⭐ berildi`);
        }
      } catch (err) {
        console.error("❌ Influencer bonus error:", err.message);
      }
    }
    // Check influencer bonus
    await processInfluencerBonus(referrerUserId);
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
      "SELECT user_id, referrer_user_id FROM users WHERE username = $1",
      [clean]
    );
    if (userResult.rows.length === 0) return;
    const referrerUserId = userResult.rows[0].referrer_user_id;
    if (!referrerUserId) return;
    // Referrer ma'lumotlarini olish
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    if (referrerResult.rows.length === 0) return;
    const referrerUsername = referrerResult.rows[0].username;
    const bonusStars = 15;
    // Referrer balance-ga qo'shish (user_id orqali)
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    // Referral earnings log-ga qo'shish
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, clean, bonusStars, transactionId]
    );
    console.log(
      `🎁 PREMIUM REFERRAL BONUS: ${referrerUsername} (${referrerUserId}) ga ${bonusStars}⭐ bonus qo'shildi (${clean} premium oldi)`
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

    // Telegram user_id olish
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;

    // 🔐 Unique summ generatsiya
    console.log("🔄 Takrorlanmas unique summ yaratilyapti...");
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1002)');
      
      const uniqueSum = await generateUniqueOrderSum(baseAmount, client);
      const orderId = crypto.randomUUID();
      
      console.log("✅ Unique summ topildi:", uniqueSum);
      console.log("📝 Bazaga yozilmoqda...");

      // 🟦 YANGI orders jadvaliga yozish
      const result = await client.query(
        `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, created_at)
         VALUES ($1, $2, $3, $4, 'premium', $5, $6, 'card', 'pending', 'pending', NOW())
         RETURNING *`,
        [orderId, ownerUserId, clean, recipient, months, uniqueSum]
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
          "SELECT status FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          console.log(`⏰ Premium Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Premium Expiry tekshirishda xato:", e);
      }
    }, 20 * 60 * 1000);
    // Backward compatible response
    return res.json({ 
      success: true, 
      order: {
        id: order.id,
        username: clean,
        recipient: order.recipient,
        muddat_oy: order.type_amount,
        amount: order.summ,
        status: order.status,
        created_at: order.created_at
      }
    });
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
    console.log("🔎 Pending premium order qidirilmoqda:", amount);
    // 🔐 ATOMIC UPDATE - orders jadvalidan
    const updated = await pool.query(
      `UPDATE orders 
       SET payment_status='paid', status='processing'
       WHERE id=(
         SELECT id FROM orders 
         WHERE summ=$1 AND payment_status='pending' AND order_type='premium'
         ORDER BY id DESC LIMIT 1 
         FOR UPDATE SKIP LOCKED
       ) 
       RETURNING *`,
      [amount]
    );
    if (!updated.rows.length) {
      console.log("❌ Pending premium TOPILMADI");
      return res.status(404).json({ error: "Pending premium topilmadi" });
    }
    const order = updated.rows[0];
    console.log("🎯 Topildi va processing:", order);
    
    // Premium yuborish
    deliverPremiumOrder(order)
      .then(result => {
        console.log("📦 deliverPremiumOrder javobi:", result);
        if (result.status === "completed") {
          processPremiumReferralBonus(order.recipient_username, order.id)
            .catch(err => console.error("❌ Premium referral bonus error:", err.message));
        }
      })
      .catch(err => console.error("❌ Premium delivery error:", err.message));
    
    return res.json({
      success: true,
      status: "processing",
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
      "SELECT status FROM orders WHERE id=$1",
      [orderId]
    );
    console.log("🔎 Hozirgi status:", check.rows[0]);
    if (!check.rows.length)
      return { status: "error", reason: "order_not_found" };
    if (check.rows[0].status === "completed")
      return { status: "completed", reason: "already_sent" };
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
        "UPDATE orders SET status='failed' WHERE id=$1",
        [orderId]
      );
      return { status: "failed", reason: "invalid_api_response" };
    }
    console.log("📡 Provider JSON:", data);
    if (data.transaction_id) {
      console.log("✅ Premium success, bazaga yozilmoqda...");
      await pool.query(
        "UPDATE orders SET status='completed', transaction_id=$1 WHERE id=$2",
        [data.transaction_id, orderId]
      );
      // 📢 Kanalga xabar
      sendChannelNotification(orderId, 'premium').catch(err => console.error("Notification error:", err));
      return { status: "completed", transaction_id: data.transaction_id };
    }
    console.log("❌ Provider error:", data.error);
    await pool.query(
      "UPDATE orders SET status='failed' WHERE id=$1",
      [orderId]
    );
    return { status: "failed", reason: data.error || "unknown" };
  } catch (err) {
    console.log("💥 PREMIUM SEND ERROR:", err);
    await pool.query(
      "UPDATE orders SET status='error' WHERE id=$1",
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
      "SELECT * FROM orders WHERE id=$1 AND order_type='premium'",
      [id]
    );
    if (!result.rows.length) {
      console.log("❌ Order topilmadi");
      return res.status(404).json({ error: "Order topilmadi" });
    }
    const order = result.rows[0];
    console.log("📦 Javob:", order);
    // Backward compatible status mapping
    const legacyStatus = order.status === 'completed' ? 'premium_sent' : order.status;
    // Backward compatible response
    return res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      muddat_oy: order.type_amount,
      amount: order.summ,
      status: legacyStatus,
      payment_status: order.payment_status,
      transaction_id: order.transaction_id,
      created_at: order.created_at
    });
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
    let query = `
      SELECT 
        o.id, o.order_id, o.owner_user_id, 
        u.username AS sender_username,
        o.recipient_username AS username,
        o.recipient,
        o.order_type,
        o.type_amount AS months,
        o.summ AS amount,
        o.payment_method, o.payment_status, o.status, o.transaction_id,
        o.created_at
      FROM orders o
      LEFT JOIN users u ON o.owner_user_id = u.user_id
      WHERE o.order_type='premium'
    `;
    const params = [];
    // filter: status
    if (status && status !== "all") {
      params.push(status);
      query += ` AND o.status = $${params.length}`;
    }
    // filter: search (recipient_username, recipient)
    if (search) {
      params.push(`%${search}%`);
      params.push(`%${search}%`);
      query += ` AND (o.recipient_username ILIKE $${params.length - 1} OR o.recipient ILIKE $${params.length})`;
    }
    query += " ORDER BY o.id DESC";
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
      "SELECT * FROM orders WHERE id=$1 AND order_type='premium'",
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
      `UPDATE orders
       SET status=$1
       WHERE id=$2 AND order_type='premium'
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
      "SELECT * FROM orders WHERE id=$1 AND order_type='premium'",
      [id]
    );
    if (!orderResult.rows.length)
      return res.status(404).json({ error: "Order topilmadi" });
    const order = orderResult.rows[0];
    // Premium yuborish funksiyasini chaqiramiz
    const sendResult = await sendPremiumToUser(order.id, order.recipient_username, order.type_amount);
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

    // Get user_id from username for "me" lookup
    let myUserId = null;
    if (clean) {
      const userRes = await pool.query("SELECT user_id FROM users WHERE username = $1", [clean]);
      if (userRes.rows.length > 0) {
        myUserId = userRes.rows[0].user_id;
      }
    }

    // Period filter: daily, weekly, monthly, all (default)
    let dateFilter = "";
    if (period === "daily") {
      dateFilter = "AND o.created_at >= NOW() - INTERVAL '1 day'";
    } else if (period === "weekly") {
      dateFilter = "AND o.created_at >= NOW() - INTERVAL '7 days'";
    } else if (period === "monthly") {
      dateFilter = "AND o.created_at >= NOW() - INTERVAL '30 days'";
    }
    const query = `
      WITH order_totals AS (
        SELECT 
          o.owner_user_id,
          SUM(o.summ)::BIGINT AS total
        FROM orders o
        WHERE o.status = 'completed' 
          AND o.order_type IN ('stars', 'premium', 'gift')
          AND o.owner_user_id IS NOT NULL
          ${dateFilter}
        GROUP BY o.owner_user_id
      ),
      ranked AS (
        SELECT
          ot.owner_user_id,
          COALESCE(u.name, u.username, 'Foydalanuvchi') AS nickname,
          ot.total,
          RANK() OVER (ORDER BY ot.total DESC) AS rank
        FROM order_totals ot
        LEFT JOIN users u ON u.user_id = ot.owner_user_id
      )
      SELECT owner_user_id, nickname, total, rank FROM ranked
      ORDER BY rank;
    `;
    const result = await pool.query(query);
    const rows = result.rows;
    const top10 = rows.slice(0, 10);
    const me = myUserId
      ? rows.find((r) => r.owner_user_id === myUserId) || null
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
app.get("/api/user/history/:userId", telegramAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    if (!userId)
      return res.status(400).json({ error: "userId kerak" });
    const query = `
      SELECT
        id,
        recipient_username AS username,
        type_amount AS stars,
        summ AS amount,
        CASE 
          WHEN status = 'completed' AND order_type = 'stars' THEN 'stars_sent'
          WHEN status = 'completed' AND order_type = 'premium' THEN 'premium_sent'
          WHEN status = 'completed' AND order_type = 'gift' THEN 'gift_sent'
          ELSE status
        END AS status,
        created_at,
        order_type AS kind
      FROM orders
      WHERE owner_user_id = $1
      ORDER BY created_at DESC;
    `;
    const result = await pool.query(query, [userId]);
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
    // Telegram ma'lumotlarini olish
    const tgUser = req.telegramUser;
    const tgUserId = tgUser?.id ? String(tgUser.id) : null;
    const tgName = tgUser?.first_name 
      ? `${tgUser.first_name}${tgUser.last_name ? ' ' + tgUser.last_name : ''}`
      : null;
    const tgUsername = tgUser?.username || (username?.startsWith("@") ? username.slice(1) : username);
    if (!tgUserId) {
      return res.status(400).json({ error: "Telegram user_id kerak" });
    }
    // User mavjudligini tekshirish (user_id orqali)
    let user = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [tgUserId]
    );
    if (user.rows.length === 0) {
      // Yangi user
      let referrer_user_id = null;
      // Referral code mavjudligini tekshirish
      if (referral_code) {
        const referrer = await pool.query(
          "SELECT user_id FROM users WHERE referral_code = $1",
          [referral_code]
        );
        if (referrer.rows.length === 0) {
          return res.status(400).json({ error: "Referral code noto'g'ri" });
        }
        referrer_user_id = referrer.rows[0].user_id;
      }
      // Yangi referral code generate qilish
      const new_code = crypto.randomBytes(6).toString("hex");
      // Yangi user qo'shish
      const newUser = await pool.query(
        `INSERT INTO users (name, username, user_id, referral_code, referrer_user_id, language)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [tgName, tgUsername, tgUserId, new_code, referrer_user_id, language || 'uz']
      );
      console.log(
        `👤 Yangi user ro'yxatdan o'tdi: ${tgUsername} (name: ${tgName}, user_id: ${tgUserId}, referrer_user_id: ${referrer_user_id || "yo'q"}, language: ${language || 'uz'})`
      );
      
      // 🎉 Yangi foydalanuvchiga xush kelibsiz xabari yuborish
      sendWelcomeMessage(tgUserId, tgName || tgUsername).catch(err => {
        console.error("❌ Welcome message error:", err.message);
      });
      
      return res.json(newUser.rows[0]);
    }
    // User allaqachon mavjud — name va username ni yangilash (agar o'zgargan bo'lsa)
    const existingUser = user.rows[0];
    let needsUpdate = false;
    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;
    if (tgName && existingUser.name !== tgName) {
      updateFields.push(`name = $${paramIndex++}`);
      updateValues.push(tgName);
      needsUpdate = true;
    }
    if (tgUsername && existingUser.username !== tgUsername) {
      updateFields.push(`username = $${paramIndex++}`);
      updateValues.push(tgUsername);
      needsUpdate = true;
    }
    if (needsUpdate) {
      updateValues.push(tgUserId);
      await pool.query(
        `UPDATE users SET ${updateFields.join(', ')} WHERE user_id = $${paramIndex}`,
        updateValues
      );
      console.log(`🔄 ${tgUserId} ma'lumotlari yangilandi`);
      
      // Yangilangan ma'lumotlarni qaytarish
      user = await pool.query("SELECT * FROM users WHERE user_id = $1", [tgUserId]);
    }
    res.json(user.rows[0]);
  } catch (err) {
    console.error("❌ /api/referral/register ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🔔 SUBSCRIBE CHECK - Kanalga obuna bo'lganda subscribe_user ni true qilish
// Bu vaqtda referral ham aktivlashadi (agar referrer_user_id mavjud bo'lsa)
app.post("/api/user/subscribe-check", authLimiter, telegramAuth, async (req, res) => {
  try {
    const tgUser = req.telegramUser;
    const tgUserId = tgUser?.id ? String(tgUser.id) : null;
    if (!tgUserId) {
      return res.status(400).json({ error: "Telegram user_id kerak" });
    }
    // User mavjudligini tekshirish
    const user = await pool.query(
      "SELECT * FROM users WHERE user_id = $1",
      [tgUserId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi. Avval ro'yxatdan o'ting." });
    }
    // Agar allaqachon subscribe bo'lgan bo'lsa
    if (user.rows[0].subscribe_user === true) {
      return res.json({ 
        success: true, 
        message: "Allaqachon obuna bo'lgansiz",
        subscribe_user: true 
      });
    }
    // subscribe_user ni true qilish
    await pool.query(
      "UPDATE users SET subscribe_user = true WHERE user_id = $1",
      [tgUserId]
    );
    
    // Agar bu user referrer orqali kelgan bo'lsa - referral aktivlashdi va +2 bonus
    const referrerUserId = user.rows[0].referrer_user_id;
    if (referrerUserId) {
      console.log(`🎉 REFERRAL AKTIVLASHDI: User ${tgUserId} kanalga obuna bo'ldi. Referrer: ${referrerUserId}`);
      
      // +2 stars bonus referrer ga
      try {
        // Referrer ma'lumotlarini olish
        const referrerResult = await pool.query(
          "SELECT username FROM users WHERE user_id = $1",
          [referrerUserId]
        );
        if (referrerResult.rows.length > 0) {
          const referrerUsername = referrerResult.rows[0].username;
          const userName = user.rows[0].username || tgUserId;
          const bonusStars = 2;
          
          // Referrer balance-ga qo'shish
          await pool.query(
            `UPDATE users 
             SET referral_balance = referral_balance + $1,
                 total_earnings = total_earnings + $1,
                 total_referrals = total_referrals + 1
             WHERE user_id = $2`,
            [bonusStars, referrerUserId]
          );
          
          // Referral earnings log-ga qo'shish
          await pool.query(
            `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
             VALUES ($1, $2, $3, $4)`,
            [referrerUsername, userName, bonusStars, null]
          );
          
          console.log(`🎁 SUBSCRIBE BONUS: ${referrerUsername} (${referrerUserId}) ga ${bonusStars}⭐ bonus qo'shildi (${userName} kanalga obuna bo'ldi)`);
        }
      } catch (bonusErr) {
        console.error("❌ Subscribe bonus error:", bonusErr.message);
      }
    } else {
      console.log(`📢 User ${tgUserId} kanalga obuna bo'ldi`);
    }
    
    res.json({ 
      success: true, 
      message: "Obuna tasdiqlandi!",
      subscribe_user: true 
    });
  } catch (err) {
    console.error("❌ /api/user/subscribe-check ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 👤 USER INFO - Foydalanuvchi ma'lumotlarini olish
app.get("/api/user/info/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id) {
      return res.status(400).json({ error: "user_id kerak" });
    }
    const user = await pool.query(
      "SELECT id, name, username, user_id, referral_code, referrer_user_id, referral_balance, total_referrals, subscribe_user, language, created_at FROM users WHERE user_id = $1",
      [user_id]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    res.json(user.rows[0]);
  } catch (err) {
    console.error("❌ /api/user/info ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 2️⃣ Referral link (personal code bilan)
app.get("/api/referral/link/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id)
      return res.status(400).json({ error: "user_id kerak" });
    const user = await pool.query(
      "SELECT name, username, referral_code, referral_balance, total_referrals FROM users WHERE user_id = $1",
      [user_id]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    const userData = user.rows[0];
    
    // Telegram Mini App Link
    const referralLink = `https://t.me/StarsjoyBot/starsjoy?startapp=${userData.referral_code}`;
    res.json({
      name: userData.name,
      username: userData.username,
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
app.get("/api/referral/stats/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id)
      return res.status(400).json({ error: "user_id kerak" });
    // User ma'lumotlari
    const user = await pool.query(
      `SELECT
        name,
        username,
        referral_balance,
        total_earnings,
        subscribe_user
       FROM users WHERE user_id = $1`,
      [user_id]
    );
    // Real do'stlar soni - users jadvalidan referrer_user_id orqali
    const friendsCount = await pool.query(
      `SELECT COUNT(*) as count FROM users WHERE referrer_user_id = $1`,
      [user_id]
    );
    if (user.rows.length === 0) {
      return res.json({
        name: null,
        username: null,
        referral_balance: 0,
        total_earnings: 0,
        subscribe_user: false,
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
app.get("/api/referral/earnings/:user_id", telegramAuth, async (req, res) => {
  try {
    const { user_id } = req.params;
    if (!user_id)
      return res.status(400).json({ error: "user_id kerak" });
    // Username ni user_id dan olish
    const userResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [user_id]
    );
    if (userResult.rows.length === 0) {
      return res.json({ earnings: [] });
    }
    const username = userResult.rows[0].username;
    const earnings = await pool.query(
      `SELECT 
        re.referee_username,
        u.name as referee_name,
        re.earned_stars,
        re.created_at
       FROM referral_earnings re
       LEFT JOIN users u ON re.referee_username = u.username
       WHERE re.referrer_username = $1
       ORDER BY re.created_at DESC`,
      [username]
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
    const tgUser = req.telegramUser;
    const tgUserId = tgUser?.id ? String(tgUser.id) : null;
    const { amount } = req.body;
    if (!tgUserId || !amount)
      return res.status(400).json({ error: "user_id va amount kerak" });
    // Check user existence
    const user = await pool.query(
      "SELECT name, username, referral_balance FROM users WHERE user_id = $1",
      [tgUserId]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ error: "User topilmadi" });
    }
    const balance = user.rows[0].referral_balance;
    const userName = user.rows[0].name || user.rows[0].username;
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
      `👤 User: ${userName} (@${user.rows[0].username})\n` +
      `🆔 User ID: ${tgUserId}\n` +
      `💰 Referral Balance: ${balance} ⭐\n` +
      `✅ Claim Amount: ${amount} ⭐\n\n` +
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
    console.log(`📩 Claim request from ${tgUserId}: ${amount} stars`);
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
// ======================
// 🏷️ DISCOUNT PACKAGES API
// ======================
// Get all active discount packages (public)
app.get("/api/discount-packages", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM discount_packages WHERE is_active = true ORDER BY stars ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Get all discount packages (admin)
app.get("/api/admin/discount-packages", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM discount_packages ORDER BY stars ASC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("❌ GET admin discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Create discount package (admin)
app.post("/api/admin/discount-packages", adminAuth, async (req, res) => {
  try {
    const { stars, discount_percent, discounted_price } = req.body;
    if (!stars || !discount_percent || !discounted_price) {
      return res.status(400).json({ error: "stars, discount_percent, discounted_price kerak" });
    }
    const result = await pool.query(
      `INSERT INTO discount_packages (stars, discount_percent, discounted_price) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [stars, discount_percent, discounted_price]
    );
    console.log(`🏷️ Admin: Yangi chegirma paketi qo'shildi - ${stars} stars, ${discount_percent}%, ${discounted_price} so'm`);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ POST discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Update discount package (admin)
app.patch("/api/admin/discount-packages/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { stars, discount_percent, discounted_price, is_active } = req.body;
    const result = await pool.query(
      `UPDATE discount_packages 
       SET stars = COALESCE($1, stars),
           discount_percent = COALESCE($2, discount_percent),
           discounted_price = COALESCE($3, discounted_price),
           is_active = COALESCE($4, is_active),
           updated_at = NOW() AT TIME ZONE 'Asia/Tashkent'
       WHERE id = $5
       RETURNING *`,
      [stars, discount_percent, discounted_price, is_active, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Paket topilmadi" });
    }
    console.log(`🏷️ Admin: Chegirma paketi yangilandi - ID: ${id}`);
    res.json(result.rows[0]);
  } catch (err) {
    console.error("❌ PATCH discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Delete discount package (admin)
app.delete("/api/admin/discount-packages/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "DELETE FROM discount_packages WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Paket topilmadi" });
    }
    console.log(`🏷️ Admin: Chegirma paketi o'chirildi - ID: ${id}`);
    res.json({ success: true, deleted: result.rows[0] });
  } catch (err) {
    console.error("❌ DELETE discount-packages ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// Validate discount package price (used during order creation)
app.post("/api/validate-discount-price", async (req, res) => {
  try {
    const { stars, amount } = req.body;
    if (!stars || !amount) {
      return res.status(400).json({ valid: false, error: "stars va amount kerak" });
    }
    // Check if this is a valid discount package
    const result = await pool.query(
      "SELECT * FROM discount_packages WHERE stars = $1 AND discounted_price = $2 AND is_active = true",
      [stars, amount]
    );
    if (result.rows.length > 0) {
      res.json({ valid: true, package: result.rows[0] });
    } else {
      res.json({ valid: false, error: "Noto'g'ri chegirma paketi" });
    }
  } catch (err) {
    console.error("❌ Validate discount price ERROR:", err);
    res.status(500).json({ valid: false, error: "Server xato" });
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
    const res = await pool.query(`SELECT * FROM orders WHERE id = $1`, [orderId]);
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
👤 Username: @${(order.recipient_username || '').replace('@', '')}
⭐ Yuborilgan: ${order.type_amount}
💰 To'lov summasi: ${order.summ} so'm
📦 Transaction ID: ${order.transaction_id}
🕒 ${date}
`;
    } else if (type === 'premium') {
      message = `
💎 PREMIUM YUBORILDI
#${order.id}
👤 Username: @${(order.recipient_username || '').replace('@', '')}
🕒 Muddat: ${order.type_amount} oy
💰 To‘lov summasi: ${order.summ} so‘m
📦 Transaction ID: ${order.transaction_id}
🕒 ${date}
`;
    } else if (type === 'gift') {
      const anonLabel = order.gift_anonymous ? ' (anonim)' : '';
      message = `
🎁 GIFT YUBORILDI
#${order.id}
👤 Yuboruvchi: @${(order.owner_user_id || '').toString().replace('@', '')}${anonLabel}
👤 Qabul qiluvchi: @${(order.recipient_username || '').replace('@', '')}
⭐ Gift: ${order.type_amount}⭐
💰 To'lov summasi: ${order.summ} so'm
${order.gift_comment ? `💬 Izoh: ${order.gift_comment}` : ''}
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
  "5170564780938756245", "6028601630662853006",
  "5922558454332916696", "5801108895304779062",
  "5800655655995968830", "5866352046986232958",
  "5956217000635139069", "5168043875654172773",
  "5170690322832818290", "5170521118301225164",
];
const GIFT_PRICE_MAP = { 15: 3500, 25: 5500, 50: 11000, 100: 22000 };
const GIFT_STARS_MAP = {
  "5170145012310081615": 15, "5170233102089322756": 15,
  "5170250947678437525": 25, "5168103777563050263": 25,
  "5170144170496491616": 50, "5170314324215857265": 50,
  "5170564780938756245": 50, "6028601630662853006": 50,
  "5922558454332916696": 50, "5801108895304779062": 50,
  "5800655655995968830": 50, "5866352046986232958": 50,
  "5956217000635139069": 50, "5168043875654172773": 100,
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

    // Telegram user_id olish
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;

    // Unique summ (orders jadvaliga yozamiz)
    const client = await pool.connect();
    let order;
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1002)');
      
      const uniqueSum = await generateUniqueOrderSum(amount, client);
      
      const orderId = crypto.randomUUID();
      const result = await client.query(
        `INSERT INTO orders
         (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, gift_id, gift_anonymous, gift_comment, created_at)
         VALUES ($1, $2, $3, $4, 'gift', $5, $6, 'card', 'pending', 'pending', $7, $8, $9, NOW())
         RETURNING *`,
        [
          orderId,
          ownerUserId,
          tgUser?.username || 'unknown',
          cleanUsername,
          serverStars,
          uniqueSum,
          giftId,
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
    console.log(`🎁 Gift order yaratildi: #${order.id} | ${ownerUserId} → @${cleanUsername} | ${serverStars}⭐ | ${order.summ} so'm`);

    // BALANCE CHECKER GA SIGNAL
    try {
      fetch('http://localhost:5001/api/balance/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'unified' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }

    // 5 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          console.log(`⏰ Gift Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Gift expiry xatosi:", e);
      }
    }, 5 * 60 * 1000);

    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient_username: cleanUsername,
      gift_id: order.gift_id,
      stars: order.type_amount,
      amount: order.summ,
      anonymous: order.gift_anonymous,
      comment: order.gift_comment,
      status: order.status,
      created_at: order.created_at
    });
  } catch (err) {
    console.error("❌ /api/gift/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 🎁 GIFT STATUS — Order holatini olish (orders jadvalidan)
// ======================
app.get("/api/gift/status/:id", telegramAuth, async (req, res) => {
  let { id } = req.params;
  if (!id || isNaN(id)) {
    return res.status(400).json({ error: "ID noto'g'ri" });
  }
  id = Number(id);
  try {
    const result = await pool.query(
      "SELECT * FROM orders WHERE id = $1 AND order_type = 'gift'",
      [id]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: "Gift order topilmadi" });
    }
    const order = result.rows[0];
    // Backward compatible status mapping
    const legacyStatus = order.status === 'completed' ? 'gift_sent' : order.status;
    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient_username: order.recipient,
      gift_id: order.gift_id,
      stars: order.type_amount,
      amount: order.summ,
      anonymous: order.gift_anonymous,
      comment: order.gift_comment,
      status: legacyStatus,
      created_at: order.created_at
    });
  } catch (err) {
    console.error("❌ /api/gift/status error:", err);
    res.status(500).json({ error: "Server error" });
  }
});
// ======================
// 🎁 GIFT MATCH — SMS to'lov tasdiqlash (orders jadvalidan)
// ======================
app.post("/api/gift/match", internalAuth, async (req, res) => {
  try {
    const { card_last4, amount } = req.body;
    if (!card_last4 || !amount) {
      return res.status(400).json({ error: "card_last4 va amount kerak" });
    }
    const updated = await pool.query(
      `UPDATE orders
       SET payment_status = 'paid',
           status = 'processing'
       WHERE id = (
         SELECT id FROM orders
         WHERE summ = $1 AND payment_status = 'pending' AND order_type = 'gift'
         ORDER BY id DESC
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [amount]
    );
    if (!updated.rows.length) {
      return res.status(404).json({ message: "Pending gift payment not found" });
    }
    const order = updated.rows[0];
    console.log(`🎉 Gift to'lov tasdiqlandi: #${order.id} | ${order.recipient_username} → @${order.recipient} | ${order.summ} so'm`);
    
    // Gift yuborish
    sendGiftToUser(order)
      .then(() => {
        console.log(`🎁 Gift yuborildi: #${order.id} → @${order.recipient}`);
      })
      .catch(err => {
        console.error(`❌ Gift yuborishda xato #${order.id}:`, err.message);
      });
    
    // Backward compatible response
    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient_username: order.recipient,
      gift_id: order.gift_id,
      amount: order.summ,
      status: order.status,
      payment_status: order.payment_status
    });
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
    // order.recipient = qabul qiluvchi username, order.recipient_username = yuboruvchi
    console.log(`🎁 sendGiftToUser: #${order.id} → @${order.recipient} | gift: ${order.gift_id}`);
    // balanceChecker.js dagi userbot orqali gift yuborish
    const giftRes = await fetch('http://localhost:5002/api/gift/send-userbot', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': INTERNAL_SECRET,
      },
      body: JSON.stringify({
        recipientUsername: order.recipient, // TO'G'RILANDI: recipient (qabul qiluvchi)
        giftId: order.gift_id,
        message: order.gift_comment || undefined,
        anonymous: order.gift_anonymous || false,
      }),
    });
    const giftData = await giftRes.json();
    if (!giftData.success) {
      await pool.query(
        "UPDATE orders SET status = 'error' WHERE id = $1",
        [order.id]
      );
      throw new Error(giftData.error || "Gift yuborishda xato");
    }
    // Muvaffaqiyatli — statusni yangilash
    await pool.query(
      "UPDATE orders SET status = 'gift_sent' WHERE id = $1",
      [order.id]
    );
    console.log(`✅ Gift muvaffaqiyatli yuborildi: #${order.id} → @${order.recipient}`);
    // 📢 Kanalga xabar
    sendUnifiedChannelNotification(order, 'gift').catch(err => console.error("Gift notification error:", err));
    return { status: 'delivered', message: 'Gift muvaffaqiyatli yuborildi' };
  } catch (err) {
    console.error(`❌ sendGiftToUser error #${order.id}:`, err);
    await pool.query(
      "UPDATE orders SET status = 'error' WHERE id = $1",
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
    let query = `
      SELECT 
        o.id, o.order_id, o.owner_user_id, 
        u.username AS sender_username,
        o.recipient_username,
        o.recipient_username AS username,
        o.recipient,
        o.order_type,
        o.type_amount AS stars,
        o.summ AS amount,
        o.payment_method, o.payment_status, o.status, o.transaction_id,
        o.gift_id, o.gift_anonymous, o.gift_comment,
        o.created_at
      FROM orders o
      LEFT JOIN users u ON u.user_id = o.owner_user_id
      WHERE o.order_type='gift'
    `;
    const params = [];
    if (status && status !== "all") {
      params.push(status);
      query += ` AND o.status = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      params.push(`%${search}%`);
      query += ` AND (o.owner_user_id::text ILIKE $${params.length - 1} OR o.recipient_username ILIKE $${params.length})`;
    }
    query += " ORDER BY o.id DESC";
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
      `UPDATE orders
       SET status=$1
       WHERE id=$2 AND order_type='gift'
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
    const q = await pool.query("SELECT * FROM orders WHERE id = $1 AND order_type='gift'", [id]);
    if (!q.rows.length) return res.status(404).json({ error: "Gift order topilmadi" });
    const order = q.rows[0];
    if (order.status === "completed") {
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
// 📊 ADMIN — Wallet Info (TON Balance & Stars Price)
// ======================
const ROBYNHOOD_API_KEY = process.env.ROB_API_KEY;
app.get("/api/admin/wallet-info", adminAuth, async (req, res) => {
  try {
    // Fetch TON balance
    const balanceRes = await fetch("https://robynhood.parssms.info/api/balance", {
      headers: {
        "accept": "application/json",
        "X-API-Key": ROBYNHOOD_API_KEY
      }
    });
    const balanceData = await balanceRes.json();
    // Fetch stars price (50 stars as reference)
    const priceRes = await fetch("https://robynhood.parssms.info/api/prices?product_type=stars&quantity=50", {
      headers: {
        "accept": "application/json",
        "X-API-Key": ROBYNHOOD_API_KEY
      }
    });
    const priceData = await priceRes.json();
    // Calculate available stars
    const mainnetBalance = parseFloat(balanceData.mainnet_balance) || 0;
    const testnetBalance = parseFloat(balanceData.testnet_balance) || 0;
    const priceFor50Stars = parseFloat(priceData.price) || 0;
    const pricePerStar = priceFor50Stars / 50;
    const availableStars = pricePerStar > 0 ? Math.floor(mainnetBalance / pricePerStar) : 0;
    res.json({
      success: true,
      wallet: {
        mainnet_balance: mainnetBalance,
        testnet_balance: testnetBalance
      },
      stars_price: {
        price_for_50: priceFor50Stars,
        price_per_star: pricePerStar,
        currency: priceData.currency || "TON"
      },
      available_stars: availableStars
    });
  } catch (err) {
    console.error("❌ /api/admin/wallet-info ERROR:", err);
    res.status(500).json({ error: "Failed to fetch wallet info" });
  }
});

// ======================
// ⭐ ADMIN — User Stars Balance (Userbot GramJS orqali)
// ======================
const BALANCE_CHECKER_URL = process.env.BALANCE_CHECKER_URL || 'http://localhost:5002';

app.get("/api/admin/bot-stars-balance", adminAuth, async (req, res) => {
  try {
    // Userbot orqali stars balance olish
    const response = await fetch(`${BALANCE_CHECKER_URL}/api/userbot/stars-balance`, {
      method: 'GET',
      headers: {
        'X-Internal-Key': INTERNAL_SECRET
      }
    });
    
    const data = await response.json();
    
    if (!data.success) {
      console.log("⚠️ Userbot stars balance xato:", data.error);
      return res.json({
        success: true,
        bot_stars_balance: 0,
        transactions_available: false,
        message: data.error || "Stars balance olishda xato"
      });
    }

    // Natijani qaytarish
    res.json({
      success: true,
      bot_stars_balance: data.stars_balance || 0,
      transactions_available: true
    });

  } catch (err) {
    console.error("❌ /api/admin/bot-stars-balance ERROR:", err);
    res.json({
      success: true,
      bot_stars_balance: 0,
      transactions_available: false,
      message: "Userbot ulanmagan"
    });
  }
});
// ==============================================
// 📦 UNIFIED ORDER SYSTEM — Yangi optimallashtirilgan tizim
// ==============================================
// 🔧 Unique summ generatsiya qiluvchi funksiya
async function generateUniqueOrderSum(baseAmount, client) {
  // Barcha pending orderlardan amountlarni olish
  const pendingAmounts = await client.query(
    "SELECT summ FROM orders WHERE status = 'pending' OR payment_status = 'pending'"
  );
  const usedAmounts = new Set(pendingAmounts.rows.map(r => r.summ));
  
  // Unique amount topamiz
  let uniqueSum = baseAmount;
  let attempts = 0;
  const maxAttempts = 200;
  
  while (usedAmounts.has(uniqueSum) && attempts < maxAttempts) {
    const offset = Math.floor(Math.random() * 101) - 50;
    uniqueSum = baseAmount + offset;
    attempts++;
  }
  
  if (attempts >= maxAttempts) {
    throw new Error("Unique summ topilmadi, keyinroq urinib ko'ring");
  }
  
  return uniqueSum;
}
// 📦 UNIFIED ORDER CREATE — Stars, Premium, Gift uchun yagona endpoint
app.post("/api/v2/order/create", orderLimiter, telegramAuth, async (req, res) => {
  try {
    console.log("\n=============== 📦 UNIFIED ORDER CREATE ===============");
    console.log("📥 Keldi:", req.body);
    
    const {
      order_type,       // 'stars', 'premium', 'gift'
      recipient_username,
      recipient,        // provider recipient ID
      type_amount,      // stars soni, oy soni, yoki gift stars soni
      payment_method,   // 'card', 'click', 'payme'
      gift_id,          // gift order uchun
      gift_anonymous,   // gift order uchun
      gift_comment      // gift order uchun
    } = req.body;
    
    // Telegram user ma'lumotlari
    const tgUser = req.telegramUser;
    const ownerUserId = tgUser?.id ? String(tgUser.id) : null;
    
    // Validatsiya
    if (!order_type || !['stars', 'premium', 'gift'].includes(order_type)) {
      return res.status(400).json({ error: "order_type kerak: 'stars', 'premium', yoki 'gift'" });
    }
    
    if (!recipient) {
      return res.status(400).json({ error: "recipient kerak" });
    }
    
    if (!type_amount || type_amount <= 0) {
      return res.status(400).json({ error: "type_amount kerak va 0 dan katta bo'lishi kerak" });
    }
    
    // Narxni hisoblash
    let baseSum = 0;
    
    if (order_type === 'stars') {
      // Stars miqdorini tekshirish (50-10000)
      if (type_amount < 50 || type_amount > 10000) {
        return res.status(400).json({ error: "Stars miqdori 50 dan 10000 gacha bo'lishi kerak" });
      }
      
      // Chegirma paketi tekshirish
      const discountCheck = await pool.query(
        "SELECT * FROM discount_packages WHERE stars = $1 AND is_active = true",
        [type_amount]
      );
      
      if (discountCheck.rows.length > 0) {
        baseSum = discountCheck.rows[0].discounted_price;
        console.log(`🏷️ Chegirma paketi: ${type_amount} stars = ${baseSum} so'm`);
      } else {
        baseSum = type_amount * STARS_PRICE_PER_UNIT;
      }
      
    } else if (order_type === 'premium') {
      // Premium oy tekshirish
      if (![3, 6, 12].includes(type_amount)) {
        return res.status(400).json({ error: "Premium muddat 3, 6, yoki 12 oy bo'lishi kerak" });
      }
      
      const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };
      baseSum = priceMap[type_amount];
      
      if (!baseSum) {
        return res.status(400).json({ error: "Premium narxi topilmadi" });
      }
      
    } else if (order_type === 'gift') {
      // Gift stars tekshirish
      if (!gift_id) {
        return res.status(400).json({ error: "gift_id kerak" });
      }
      
      // Gift narxini stars asosida hisoblash
      baseSum = type_amount * STARS_PRICE_PER_UNIT;
    }
    
    console.log(`💰 Hisoblangan narx: ${baseSum} so'm`);
    
    // Transaction bilan unique sum generatsiya
    const client = await pool.connect();
    let order;
    
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(1002)'); // orders uchun alohida lock
      
      const uniqueSum = await generateUniqueOrderSum(baseSum, client);
      console.log(`✅ Unique summ: ${uniqueSum} so'm`);
      
      // Orderni yaratish
      const orderId = crypto.randomUUID();
      const result = await client.query(
        `INSERT INTO orders (
          order_id, owner_user_id, recipient_username, recipient, order_type, 
          type_amount, summ, payment_method, payment_status, status,
          gift_id, gift_anonymous, gift_comment, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 'pending', $9, $10, $11, NOW())
        RETURNING *`,
        [
          orderId,
          ownerUserId,
          recipient_username || null,
          recipient,
          order_type,
          type_amount,
          uniqueSum,
          payment_method || 'card',
          gift_id || null,
          gift_anonymous || false,
          gift_comment || null
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
    
    console.log(`🎉 Order yaratildi: #${order.id} | ${order.order_type} | ${order.summ} so'm`);
    
    // Balance checker ga signal
    try {
      fetch('http://localhost:5001/api/balance/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ order_id: order.id, type: 'unified' })
      }).catch(err => console.log('⚠️ Balance checker signal xatosi:', err.message));
    } catch (e) {
      console.log('⚠️ Balance checker ga ulanib bo\'lmadi');
    }
    
    // 20 daqiqadan keyin expired
    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status FROM orders WHERE id = $1",
          [order.id]
        );
        
        if (check.rows[0]?.status === 'pending') {
          await pool.query(
            "UPDATE orders SET status = 'expired', payment_status = 'expired' WHERE id = $1",
            [order.id]
          );
          console.log(`⏰ Order #${order.id} expired`);
        }
      } catch (e) {
        console.error("❌ Order expiry tekshirishda xato:", e);
      }
    }, 20 * 60 * 1000);
    
    res.json({ success: true, order });
    
  } catch (err) {
    console.error("❌ UNIFIED ORDER CREATE ERROR:", err);
    res.status(500).json({ error: "Server xato", details: err.message });
  }
});
// 📋 ORDER STATUS — Order holatini olish
app.get("/api/v2/order/:id", telegramAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: "ID noto'g'ri" });
    }
    
    const result = await pool.query(
      "SELECT * FROM orders WHERE id = $1",
      [Number(id)]
    );
    
    if (!result.rows.length) {
      return res.status(404).json({ error: "Order topilmadi" });
    }
    
    res.json(result.rows[0]);
    
  } catch (err) {
    console.error("❌ ORDER GET ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 💳 UNIFIED PAYMENT MATCH — To'lov tasdiqlanishi
app.post("/api/v2/payments/match", internalAuth, async (req, res) => {
  try {
    console.log("\n=============== 💳 UNIFIED PAYMENT MATCH ===============");
    console.log("📥 Keldi:", req.body);
    
    const { amount, card_last4 } = req.body;
    
    if (!amount) {
      return res.status(400).json({ error: "amount kerak" });
    }
    
    // Atomic update — race condition oldini olish
    const updated = await pool.query(
      `UPDATE orders 
       SET payment_status = 'completed'
       WHERE id = (
         SELECT id FROM orders 
         WHERE summ = $1 AND payment_status = 'pending' 
         ORDER BY id DESC 
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [amount]
    );
    
    if (!updated.rows.length) {
      console.log("❌ Pending order TOPILMADI summ:", amount);
      return res.status(404).json({ error: "Pending order topilmadi" });
    }
    
    const order = updated.rows[0];
    console.log(`🎯 Order topildi: #${order.id} | ${order.order_type}`);
    
    // Order turига qarab yetkazish
    let deliveryResult;
    
    try {
      if (order.order_type === 'stars') {
        deliveryResult = await deliverStarsOrder(order);
      } else if (order.order_type === 'premium') {
        deliveryResult = await deliverPremiumOrder(order);
      } else if (order.order_type === 'gift') {
        deliveryResult = await sendGiftToUser(order);
      }
      
      console.log("📦 Delivery natijasi:", deliveryResult);
      
    } catch (deliveryErr) {
      console.error("❌ Delivery xatosi:", deliveryErr.message);
      await pool.query(
        "UPDATE orders SET status = 'error' WHERE id = $1",
        [order.id]
      );
      return res.json({ 
        success: false, 
        order_id: order.id, 
        error: deliveryErr.message 
      });
    }
    
    res.json({ 
      success: true, 
      order_id: order.id,
      order_type: order.order_type,
      delivery: deliveryResult 
    });
    
  } catch (err) {
    console.error("❌ UNIFIED PAYMENT MATCH ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🌟 Stars yetkazish funksiyasi
async function deliverStarsOrder(order) {
  console.log(`🌟 Stars yetkazilmoqda: Order #${order.id}`);
  
  const idempotencyKey = crypto.randomUUID();
  
  const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "accept": "application/json",
      "X-API-Key": process.env.ROB_API_KEY,
    },
    body: JSON.stringify({
      product_type: "stars",
      recipient: order.recipient,
      quantity: String(order.type_amount),
      idempotency_key: idempotencyKey,
    }),
  });
  
  const text = await purchaseRes.text();
  let data;
  
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error("Stars API noto'g'ri format qaytardi: " + text);
  }
  
  console.log("📦 Stars API javob:", data);
  
  if (!data.transaction_id) {
    await pool.query(
      "UPDATE orders SET status = 'failed' WHERE id = $1",
      [order.id]
    );
    throw new Error("Stars yuborishda xato: " + JSON.stringify(data));
  }
  
  // Muvaffaqiyatli — statusni yangilash
  await pool.query(
    "UPDATE orders SET status = 'delivered', transaction_id = $1 WHERE id = $2",
    [data.transaction_id, order.id]
  );
  
  console.log(`✅ Stars yuborildi: Order #${order.id} -> TxID: ${data.transaction_id}`);
  
  // Referral bonus
  if (order.owner_user_id) {
    processReferralBonusByUserId(order.owner_user_id, order.type_amount, order.id)
      .catch(err => console.error("❌ Referral bonus error:", err.message));
  }
  
  // Kanalga xabar
  sendUnifiedChannelNotification(order, 'stars').catch(err => console.error("Notification error:", err));
  
  return { status: "delivered", transaction_id: data.transaction_id };
}
// 👑 Premium yetkazish funksiyasi
async function deliverPremiumOrder(order) {
  console.log(`👑 Premium yetkazilmoqda: Order #${order.id}`);
  
  const idempotencyKey = crypto.randomUUID();
  
  const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "accept": "application/json",
      "X-API-Key": process.env.ROB_API_KEY,
    },
    body: JSON.stringify({
      product_type: "premium",
      recipient: order.recipient,
      months: String(order.type_amount),
      idempotency_key: idempotencyKey,
    }),
  });
  
  const text = await purchaseRes.text();
  let data;
  
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error("Premium API noto'g'ri format qaytardi: " + text);
  }
  
  console.log("📦 Premium API javob:", data);
  
  if (!data.transaction_id) {
    await pool.query(
      "UPDATE orders SET status = 'failed' WHERE id = $1",
      [order.id]
    );
    throw new Error("Premium yuborishda xato: " + JSON.stringify(data));
  }
  
  // Muvaffaqiyatli
  await pool.query(
    "UPDATE orders SET status = 'delivered', transaction_id = $1 WHERE id = $2",
    [data.transaction_id, order.id]
  );
  
  console.log(`✅ Premium yuborildi: Order #${order.id} -> TxID: ${data.transaction_id}`);
  
  // Premium referral bonus
  if (order.owner_user_id) {
    processPremiumReferralBonusByUserId(order.owner_user_id, order.id)
      .catch(err => console.error("❌ Premium referral bonus error:", err.message));
  }
  
  // Kanalga xabar
  sendUnifiedChannelNotification(order, 'premium').catch(err => console.error("Notification error:", err));
  
  return { status: "delivered", transaction_id: data.transaction_id };
}
// 🎁 Gift yetkazish funksiyasi
async function deliverGiftOrder(order) {
  console.log(`🎁 Gift yetkazilmoqda: Order #${order.id}`);
  
  const idempotencyKey = crypto.randomUUID();
  
  const purchaseRes = await fetch("https://robynhood.parssms.info/api/purchase", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "accept": "application/json",
      "X-API-Key": process.env.ROB_API_KEY,
    },
    body: JSON.stringify({
      product_type: "gift",
      recipient: order.recipient,
      gift_id: order.gift_id,
      quantity: String(order.type_amount),
      idempotency_key: idempotencyKey,
    }),
  });
  
  const text = await purchaseRes.text();
  let data;
  
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error("Gift API noto'g'ri format qaytardi: " + text);
  }
  
  console.log("📦 Gift API javob:", data);
  
  if (!data.transaction_id) {
    await pool.query(
      "UPDATE orders SET status = 'failed' WHERE id = $1",
      [order.id]
    );
    throw new Error("Gift yuborishda xato: " + JSON.stringify(data));
  }
  
  // Muvaffaqiyatli
  await pool.query(
    "UPDATE orders SET status = 'delivered', transaction_id = $1 WHERE id = $2",
    [data.transaction_id, order.id]
  );
  
  console.log(`✅ Gift yuborildi: Order #${order.id} -> TxID: ${data.transaction_id}`);
  
  // Kanalga xabar
  sendUnifiedChannelNotification(order, 'gift').catch(err => console.error("Notification error:", err));
  
  return { status: "delivered", transaction_id: data.transaction_id };
}
// 📢 Unified kanal xabari
async function sendUnifiedChannelNotification(order, type) {
  if (!bot) return;
  
  let emoji = '🌟';
  let typeName = 'Stars';
  
  if (type === 'premium') {
    emoji = '👑';
    typeName = 'Premium';
  } else if (type === 'gift') {
    emoji = '🎁';
    typeName = 'Gift';
  }
  
  const message = `${emoji} <b>Yangi ${typeName} sotildi!</b>\n\n` +
    `📦 Order: #${order.id}\n` +
    `👤 Oluvchi: ${order.recipient_username || order.recipient}\n` +
    `💫 Miqdor: ${order.type_amount} ${type === 'premium' ? 'oy' : 'stars'}\n` +
    `💰 Summa: ${order.summ.toLocaleString()} so'm\n` +
    `✅ Status: Yetkazildi`;
  
  try {
    await bot.telegram.sendMessage(ORDERS_CHANNEL, message, { parse_mode: 'HTML' });
  } catch (err) {
    console.error("❌ Channel notification error:", err.message);
  }
}
// 🎁 Referral bonus user_id orqali
async function processReferralBonusByUserId(userId, stars, orderId) {
  try {
    // User ma'lumotlarini olish
    const userResult = await pool.query(
      "SELECT username, referrer_user_id FROM users WHERE user_id = $1",
      [userId]
    );
    
    if (userResult.rows.length === 0) return;
    
    const username = userResult.rows[0].username;
    const referrerUserId = userResult.rows[0].referrer_user_id;
    
    if (!referrerUserId) return;
    
    // Referrer username olish
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    
    if (referrerResult.rows.length === 0) return;
    
    const referrerUsername = referrerResult.rows[0].username;
    
    // Bonus hisoblash: har 50 star uchun 5 star
    const bonusStars = Math.floor(stars / 50) * 5;
    if (bonusStars <= 0) return;
    
    // Referrer balance yangilash
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    
    // Referral earnings log
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, username, bonusStars, orderId]
    );
    
    console.log(`🎁 REFERRAL BONUS: ${referrerUsername} ga ${bonusStars}⭐ (order #${orderId})`);
    
  } catch (err) {
    console.error("❌ processReferralBonusByUserId error:", err.message);
  }
}
// 👑 Premium referral bonus user_id orqali
async function processPremiumReferralBonusByUserId(userId, orderId) {
  try {
    const userResult = await pool.query(
      "SELECT username, referrer_user_id FROM users WHERE user_id = $1",
      [userId]
    );
    
    if (userResult.rows.length === 0) return;
    
    const username = userResult.rows[0].username;
    const referrerUserId = userResult.rows[0].referrer_user_id;
    
    if (!referrerUserId) return;
    
    const referrerResult = await pool.query(
      "SELECT username FROM users WHERE user_id = $1",
      [referrerUserId]
    );
    
    if (referrerResult.rows.length === 0) return;
    
    const referrerUsername = referrerResult.rows[0].username;
    const bonusStars = 15;
    
    await pool.query(
      `UPDATE users 
       SET referral_balance = referral_balance + $1,
           total_earnings = total_earnings + $1
       WHERE user_id = $2`,
      [bonusStars, referrerUserId]
    );
    
    await pool.query(
      `INSERT INTO referral_earnings (referrer_username, referee_username, earned_stars, triggered_by_transaction_id)
       VALUES ($1, $2, $3, $4)`,
      [referrerUsername, username, bonusStars, orderId]
    );
    
    console.log(`🎁 PREMIUM REFERRAL BONUS: ${referrerUsername} ga ${bonusStars}⭐ (order #${orderId})`);
    
  } catch (err) {
    console.error("❌ processPremiumReferralBonusByUserId error:", err.message);
  }
}
// 📋 ADMIN: Barcha orderlarni olish
app.get("/api/v2/admin/orders", adminAuth, async (req, res) => {
  try {
    const { status, order_type, limit = 100 } = req.query;
    
    let query = "SELECT * FROM orders WHERE 1=1";
    const params = [];
    
    if (status && status !== 'all') {
      params.push(status);
      query += ` AND status = $${params.length}`;
    }
    
    if (order_type && order_type !== 'all') {
      params.push(order_type);
      query += ` AND order_type = $${params.length}`;
    }
    
    params.push(Number(limit));
    query += ` ORDER BY id DESC LIMIT $${params.length}`;
    
    const result = await pool.query(query, params);
    
    res.json({ success: true, orders: result.rows });
    
  } catch (err) {
    console.error("❌ ADMIN ORDERS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🔄 ADMIN: Order status yangilash
app.patch("/api/v2/admin/orders/:id", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, payment_status } = req.body;
    
    if (!id) {
      return res.status(400).json({ error: "ID kerak" });
    }
    
    const updates = [];
    const params = [];
    
    if (status) {
      params.push(status);
      updates.push(`status = $${params.length}`);
    }
    
    if (payment_status) {
      params.push(payment_status);
      updates.push(`payment_status = $${params.length}`);
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: "Yangilanadigan ma'lumot kerak" });
    }
    
    params.push(Number(id));
    const query = `UPDATE orders SET ${updates.join(', ')} WHERE id = $${params.length} RETURNING *`;
    
    const result = await pool.query(query, params);
    
    if (!result.rows.length) {
      return res.status(404).json({ error: "Order topilmadi" });
    }
    
    res.json({ success: true, order: result.rows[0] });
    
  } catch (err) {
    console.error("❌ ADMIN ORDER UPDATE ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// 🔄 ADMIN: Orderni qayta yetkazish
app.post("/api/v2/admin/orders/:id/redeliver", adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    
    const orderResult = await pool.query(
      "SELECT * FROM orders WHERE id = $1",
      [Number(id)]
    );
    
    if (!orderResult.rows.length) {
      return res.status(404).json({ error: "Order topilmadi" });
    }
    
    const order = orderResult.rows[0];
    
    if (order.status === 'delivered') {
      return res.status(400).json({ error: "Order allaqachon yetkazilgan" });
    }
    
    let deliveryResult;
    
    if (order.order_type === 'stars') {
      deliveryResult = await deliverStarsOrder(order);
    } else if (order.order_type === 'premium') {
      deliveryResult = await deliverPremiumOrder(order);
    } else if (order.order_type === 'gift') {
      deliveryResult = await sendGiftToUser(order);
    }
    
    res.json({ success: true, delivery: deliveryResult });
    
  } catch (err) {
    console.error("❌ ADMIN REDELIVER ERROR:", err);
    res.status(500).json({ error: "Server xato", details: err.message });
  }
});
// 📊 ADMIN: Order statistikasi
app.get("/api/v2/admin/orders/stats", adminAuth, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        order_type,
        status,
        COUNT(*) as count,
        SUM(summ) as total_sum
      FROM orders
      GROUP BY order_type, status
      ORDER BY order_type, status
    `);
    
    const todayStats = await pool.query(`
      SELECT 
        order_type,
        COUNT(*) as count,
        SUM(summ) as total_sum
      FROM orders
      WHERE created_at >= CURRENT_DATE
      GROUP BY order_type
    `);
    
    res.json({
      success: true,
      all_time: stats.rows,
      today: todayStats.rows
    });
    
  } catch (err) {
    console.error("❌ ADMIN STATS ERROR:", err);
    res.status(500).json({ error: "Server xato" });
  }
});
// ======================
// run server
// ======================
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
