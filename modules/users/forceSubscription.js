/**
 * 📢 Majburiy kanal obunasi — admin switch: settings.force_subscription.
 *
 * Uch joyda ishlaydi:
 *   • buyurtma yaratish — orderLimiter ichidagi subscriptionGate (aylanib o'tib bo'lmaydi),
 *   • Mini App — GET /api/subscription-status (ekranni ko'rsatish uchun),
 *   • bot /start — token.js (alohida jarayon, o'z tekshiruvi bilan).
 *
 * Xavfsizlik qoidalari:
 *   • Telegram javob bermasa (getChatMember xatosi) — user O'TKAZILADI, savdo to'xtamaydi.
 *   • "Obuna" natijasi 30 daqiqa keshlanadi; "obuna emas" keshlanmaydi (obuna bo'lgan zahoti o'tadi).
 *   • Adminlar tekshirilmaydi.
 */
import { loadSettings } from "../settings/settingsDb.js";

const OK_CACHE_MS = 30 * 60 * 1000;
const okCache = new Map(); // userId -> vaqt

let deps = {
  pool: null,
  getBot: () => null,
  channel: null,
  validateInitData: null,
  /** Mini App initData yoki brauzer sessiyasi (modules/webAuth) */
  resolveUser: null,
  adminIds: [],
};

export function configureForceSubscription(d) {
  deps = { ...deps, ...d };
}

export function channelUrl() {
  return `https://t.me/${String(deps.channel || "").replace(/^@/, "")}`;
}

export async function isForceSubscriptionOn() {
  try {
    return Boolean((await loadSettings(deps.pool)).force_subscription);
  } catch {
    return false;
  }
}

function isAdminUser(id) {
  return deps.adminIds.map(Number).includes(Number(id));
}

/** true — obuna, false — obuna emas, null — aniqlab bo'lmadi (o'tkaziladi) */
export async function checkSubscribed(userId) {
  const uid = String(userId);
  const t = okCache.get(uid);
  if (t && Date.now() - t < OK_CACHE_MS) return true;
  const bot = deps.getBot();
  if (!bot || !deps.channel) return null;
  try {
    const m = await bot.telegram.getChatMember(deps.channel, Number(uid));
    const ok =
      ["member", "administrator", "creator"].includes(m?.status) ||
      (m?.status === "restricted" && m?.is_member === true);
    if (ok) okCache.set(uid, Date.now());
    else okCache.delete(uid);
    return ok;
  } catch (err) {
    console.error(`⚠️ Obuna tekshiruvi (${uid}):`, err?.message || err);
    return null;
  }
}

/** Buyurtma yaratish yo'llari uchun (orderLimiter tarkibida) */
export async function subscriptionGate(req, res, next) {
  try {
    if (req.method !== "POST") return next();
    if (!(await isForceSubscriptionOn())) return next();
    const user = deps.resolveUser
      ? await deps.resolveUser(req)
      : deps.validateInitData?.(req.headers["x-telegram-init-data"]);
    if (!user?.id || isAdminUser(user.id)) return next(); // auth xatosini telegramAuth hal qiladi
    if ((await checkSubscribed(user.id)) === false) {
      return res.status(403).json({
        error: "Buyurtma berish uchun rasmiy kanalimizga obuna bo'ling",
        code: "SUBSCRIPTION_REQUIRED",
        channel_url: channelUrl(),
      });
    }
    return next();
  } catch (err) {
    console.error("⚠️ subscriptionGate:", err?.message || err);
    return next();
  }
}

export function registerSubscriptionRoutes(app, { telegramAuth }) {
  app.get("/api/subscription-status", telegramAuth, async (req, res) => {
    res.set("Cache-Control", "no-store");
    const required = await isForceSubscriptionOn();
    const uid = req.telegramUser?.id;
    if (!required || !uid || isAdminUser(uid)) {
      return res.json({ required, subscribed: true, channel_url: channelUrl() });
    }
    const s = await checkSubscribed(uid);
    res.json({ required, subscribed: s !== false, channel_url: channelUrl() });
  });
}
