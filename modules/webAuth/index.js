/**
 * Brauzer versiyasi (app.starsjoy.uz) uchun kirish.
 *
 * Telegram qoidasi: bot / Mini App ichida raqamli mahsulot faqat Telegram Stars evaziga sotiladi.
 * Shuning uchun xarid brauzerdagi saytda bo'ladi, Mini App esa mijozni tanib saytga o'tkazadi:
 *
 *   1) Mini App (initData bilan)  → POST /api/web-auth/handoff  → bir martalik havola (5 daqiqa)
 *   2) Brauzer                    → POST /api/web-auth/exchange → httpOnly sessiya cookie (30 kun)
 *   3) Keyingi so'rovlar: initData yo'q bo'lsa, foydalanuvchi cookie'dagi sessiyadan olinadi.
 *
 * Saytga to'g'ridan-to'g'ri kirganlar uchun Telegram Login Widget ham qo'llab-quvvatlanadi
 * (BotFather'da /setdomain app.starsjoy.uz qilingan bo'lishi kerak).
 *
 * Sessiya va kodlarning o'zi bazada saqlanmaydi — faqat SHA-256 xeshi.
 */
import crypto from "crypto";

const COOKIE = "sj_web";
const SESSION_DAYS = 30;
const CODE_TTL_MIN = 5;
const LOGIN_MAX_AGE_SEC = 24 * 3600;
const CACHE_MS = 60_000;

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const randomToken = () => crypto.randomBytes(32).toString("base64url");

function readCookie(req, name) {
  const raw = req.headers.cookie || "";
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

/** Telegram user obyektidan faqat kerakli maydonlar (initData'dagi bilan bir xil shakl) */
function pickUser(u) {
  if (!u || !u.id) return null;
  const out = { id: Number(u.id) };
  for (const k of ["first_name", "last_name", "username", "language_code", "photo_url", "is_premium"]) {
    if (u[k] !== undefined && u[k] !== null && u[k] !== "") out[k] = u[k];
  }
  return out;
}

export function createWebAuth({ pool, validateInitData, botToken, webUrl, logIdentity, isHandoffOn, adminIds = [] }) {
  const sessionCache = new Map(); // token_hash -> { user, at }

  pool
    .query(
      `CREATE TABLE IF NOT EXISTS web_auth_codes (
        code_hash TEXT PRIMARY KEY,
        user_id BIGINT NOT NULL,
        user_json JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
      )`
    )
    .then(() =>
      pool.query(`CREATE TABLE IF NOT EXISTS web_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id BIGINT NOT NULL,
        user_json JSONB NOT NULL,
        source TEXT NOT NULL DEFAULT 'handoff',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMPTZ,
        user_agent TEXT
      )`)
    )
    .then(() => pool.query(`CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id)`))
    .catch((e) => console.error("❌ web_auth jadvallar:", e.message));

  // Eskirgan kod va sessiyalarni vaqti-vaqti bilan tozalash
  setInterval(() => {
    pool.query(`DELETE FROM web_auth_codes WHERE expires_at < NOW() - INTERVAL '1 day'`).catch(() => {});
    pool.query(`DELETE FROM web_sessions WHERE expires_at < NOW() - INTERVAL '7 days'`).catch(() => {});
  }, 6 * 3600_000).unref?.();

  async function userFromSession(req) {
    const token = readCookie(req, COOKIE);
    if (!token || token.length < 40 || token.length > 100) return null;
    const h = sha256(token);
    const c = sessionCache.get(h);
    if (c && Date.now() - c.at < CACHE_MS) return c.user;
    const r = await pool.query(
      `UPDATE web_sessions SET last_seen_at = NOW()
        WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
        RETURNING user_json`,
      [h]
    );
    const user = r.rows[0]?.user_json || null;
    if (user) sessionCache.set(h, { user, at: Date.now() });
    else sessionCache.delete(h);
    return user;
  }

  /**
   * So'rov egasi: avval Telegram initData (Mini App), bo'lmasa brauzer sessiyasi.
   * initData yuborilgan, lekin noto'g'ri bo'lsa — sessiyaga o'tilmaydi (null).
   */
  async function resolveUser(req) {
    const initData = req.headers["x-telegram-init-data"];
    if (initData) return validateInitData(initData);
    try {
      return await userFromSession(req);
    } catch (e) {
      console.error("⚠️ web sessiya:", e.message);
      return null;
    }
  }

  async function createSession(req, res, user, source) {
    const token = randomToken();
    await pool.query(
      `INSERT INTO web_sessions (token_hash, user_id, user_json, source, expires_at, user_agent)
       VALUES ($1, $2, $3, $4, NOW() + ($5 || ' days')::interval, $6)`,
      [sha256(token), user.id, JSON.stringify(user), source, String(SESSION_DAYS), String(req.headers["user-agent"] || "").slice(0, 300)]
    );
    // Shu foydalanuvchining eski sessiyalaridagi username/ismni ham yangilaymiz
    pool
      .query(`UPDATE web_sessions SET user_json = $2 WHERE user_id = $1 AND revoked_at IS NULL`, [user.id, JSON.stringify(user)])
      .then(() => sessionCache.clear())
      .catch(() => {});
    res.setHeader(
      "Set-Cookie",
      `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_DAYS * 86400}`
    );
    try { logIdentity?.(pool, user); } catch { /* ixtiyoriy */ }
  }

  function verifyLoginWidget(data) {
    if (!botToken || !data || typeof data !== "object" || !data.hash || !data.id) return null;
    const fields = Object.keys(data)
      .filter((k) => k !== "hash" && data[k] !== undefined && data[k] !== null)
      .sort()
      .map((k) => `${k}=${data[k]}`)
      .join("\n");
    const secret = crypto.createHash("sha256").update(botToken).digest();
    const check = crypto.createHmac("sha256", secret).update(fields).digest("hex");
    const a = Buffer.from(check);
    const b = Buffer.from(String(data.hash));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const age = Math.floor(Date.now() / 1000) - Number(data.auth_date || 0);
    if (!(age >= 0 && age < LOGIN_MAX_AGE_SEC)) return null;
    return pickUser(data);
  }

  function register(app, { authLimiter }) {
    const limit = authLimiter ? [authLimiter] : [];

    // 1) Mini App → bir martalik havola (faqat Telegram initData bilan)
    app.post("/api/web-auth/handoff", ...limit, async (req, res) => {
      try {
        const user = pickUser(validateInitData(req.headers["x-telegram-init-data"]));
        if (!user) return res.status(401).json({ error: "Telegram autentifikatsiya muvaffaqiyatsiz" });
        // Saytdan "Telegram orqali kirish" bosilgan bo'lsa (startapp=web) — har doim o'tkazamiz.
        // Aks holda: sozlama o'chiq yoki admin bo'lsa Mini App avvalgidek ishlaydi.
        const force = req.body?.force === true;
        if (!force) {
          const on = isHandoffOn ? await isHandoffOn() : true;
          if (!on || adminIds.includes(Number(user.id))) return res.json({ ok: true, skip: true });
        }
        const code = randomToken();
        await pool.query(
          `INSERT INTO web_auth_codes (code_hash, user_id, user_json, expires_at)
           VALUES ($1, $2, $3, NOW() + ($4 || ' minutes')::interval)`,
          [sha256(code), user.id, JSON.stringify(user), String(CODE_TTL_MIN)]
        );
        const rawPath = typeof req.body?.path === "string" ? req.body.path : "/";
        const path = /^\/[A-Za-z0-9/_-]{0,60}$/.test(rawPath) ? rawPath : "/";
        const url = `${webUrl}/auth?c=${encodeURIComponent(code)}${path !== "/" ? `&next=${encodeURIComponent(path)}` : ""}`;
        res.json({ ok: true, url });
      } catch (e) {
        console.error("❌ /api/web-auth/handoff:", e.message);
        res.status(500).json({ error: "Server xatosi" });
      }
    });

    // 2) Brauzer: kodni sessiyaga almashtirish (kod bir marta ishlaydi)
    app.post("/api/web-auth/exchange", ...limit, async (req, res) => {
      try {
        const code = String(req.body?.code || "");
        if (code.length < 40 || code.length > 100) return res.status(400).json({ error: "Havola noto'g'ri" });
        const r = await pool.query(
          `UPDATE web_auth_codes SET used_at = NOW()
            WHERE code_hash = $1 AND used_at IS NULL AND expires_at > NOW()
            RETURNING user_json`,
          [sha256(code)]
        );
        const user = r.rows[0]?.user_json;
        if (!user) return res.status(401).json({ error: "Havola eskirgan yoki ishlatilgan", code: "LINK_EXPIRED" });
        await createSession(req, res, user, "handoff");
        res.json({ ok: true, user });
      } catch (e) {
        console.error("❌ /api/web-auth/exchange:", e.message);
        res.status(500).json({ error: "Server xatosi" });
      }
    });

    // 3) Telegram Login Widget (saytga to'g'ridan-to'g'ri kirganlar)
    app.post("/api/web-auth/telegram-login", ...limit, async (req, res) => {
      try {
        const user = verifyLoginWidget(req.body);
        if (!user) return res.status(401).json({ error: "Telegram kirish tasdiqlanmadi" });
        await createSession(req, res, user, "widget");
        res.json({ ok: true, user });
      } catch (e) {
        console.error("❌ /api/web-auth/telegram-login:", e.message);
        res.status(500).json({ error: "Server xatosi" });
      }
    });

    app.get("/api/web-auth/me", async (req, res) => {
      res.setHeader("Cache-Control", "no-store");
      const user = await resolveUser(req);
      if (!user) return res.status(401).json({ error: "Kirish kerak" });
      res.json({ ok: true, user });
    });

    app.post("/api/web-auth/logout", async (req, res) => {
      const token = readCookie(req, COOKIE);
      if (token) {
        const h = sha256(token);
        sessionCache.delete(h);
        await pool.query(`UPDATE web_sessions SET revoked_at = NOW() WHERE token_hash = $1`, [h]).catch(() => {});
      }
      res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
      res.json({ ok: true });
    });
  }

  return { resolveUser, register };
}
