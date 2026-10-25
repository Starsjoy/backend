/**
 * Bonuslar (rewards) qoidalari va almashtirish katalogi.
 *
 * ⚠️ env FUNKSIYA ICHIDA o'qiladi (server.js da dotenv.config() importlardan keyin).
 */

/** Bonus yoziladigan buyurtma turlari → necha ⭐ bonus */
export function rewardForOrder(order) {
  const type = String(order?.order_type || "").toLowerCase();
  const amount = Number(order?.type_amount) || 0;
  if (amount <= 0) return 0;

  if (type === "gift") {
    if (amount <= 25) return 1;
    if (amount <= 50) return 2;
    return 3;
  }
  // Premium: 3 oy → 3⭐, 6 oy → 6⭐, 12 oy → 12⭐
  if (type.includes("premium")) return amount;
  // Stars: har to'liq 50⭐ uchun 2⭐ (70⭐ → 2, 150⭐ → 6)
  if (type.includes("stars")) return Math.floor(amount / 50) * 2;
  return 0;
}

/** Referal: do'st Stars olsa — har to'liq 50⭐ uchun */
export const REFERRAL_REWARD_PER_50 = 3;

/**
 * Taklif qilingan do'stning xaridi uchun taklif qilganga bonus:
 *   Stars   — har to'liq 50⭐ uchun +3 (100⭐ → 6)
 *   Premium — har oy uchun +1 (3/6/12 oy → 3/6/12)
 *   Gift    — yo'q
 */
export function referralRewardForOrder(order) {
  const type = String(order?.order_type || "").toLowerCase();
  const amount = Number(order?.type_amount) || 0;
  if (amount <= 0 || type === "gift") return 0;
  if (type.includes("premium")) return amount;
  if (type.includes("stars")) return Math.floor(amount / 50) * REFERRAL_REWARD_PER_50;
  return 0;
}

/**
 * Faqat YANGI foydalanuvchi referal hisoblanadi: akkaunti shu sanadan keyin ochilgan bo'lishi kerak.
 * StarsJoy'ni avvaldan ishlatayotgan odam birovning havolasi orqali kirsa ham bonus bermaydi.
 */
export function getReferralSince() {
  const d = new Date(process.env.BONUS_REFERRAL_SINCE || "2026-10-25T00:00:00+05:00");
  return Number.isNaN(d.getTime()) ? new Date("2026-10-25T00:00:00+05:00") : d;
}

/** Telegram username formati (5–32, harf/raqam/_) — sovg'a qabul qiluvchisi uchun */
export function normalizeRecipientUsername(raw) {
  const u = String(raw || "").trim().replace(/^@/, "");
  return /^[A-Za-z][A-Za-z0-9_]{4,31}$/.test(u) ? u : null;
}

/** Bonus balansdan olish mumkin bo'lgan narsalar. gift_id lar GIFT_STARS_MAP da bo'lishi shart. */
export const REWARD_CATALOG = [
  { id: "gift15", kind: "gift", cost: 15, stars: 15, gift_id: "5170233102089322756" },
  { id: "gift25", kind: "gift", cost: 25, stars: 25, gift_id: "5168103777563050263" },
  { id: "stars50", kind: "stars", cost: 50, stars: 50 },
  { id: "stars100", kind: "stars", cost: 100, stars: 100 },
];

export function getCatalogItem(id) {
  return REWARD_CATALOG.find((i) => i.id === id) || null;
}

/** Bonus buyurtmalarini missiya sovg'alaridan ajratuvchi order_id prefiksi */
export const REWARD_ORDER_PREFIX = "reward-";

export function isRewardOrder(order) {
  return String(order?.order_id || "").startsWith(REWARD_ORDER_PREFIX);
}

/**
 * BONUS_ENABLED=true bo'lmaguncha tizim faqat ADMIN_IDS uchun ishlaydi (prod'da sinash).
 */
export function isRewardsEnabledFor(userId) {
  if (String(process.env.BONUS_ENABLED || "").toLowerCase() === "true") return true;
  const admins = String(process.env.ADMIN_IDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return admins.includes(String(userId));
}

/** Bir kunda barcha userlar yechib olishi mumkin bo'lgan jami ⭐ (favqulodda himoya) */
export function getDailyRedeemCapStars() {
  const n = Number(process.env.BONUS_DAILY_CAP_STARS ?? 3000);
  return Number.isFinite(n) && n > 0 ? n : 3000;
}

/** Bir user bir kunda nechta marta yechib olishi mumkin */
export function getUserDailyRedeemLimit() {
  const n = Number(process.env.BONUS_USER_DAILY_LIMIT ?? 3);
  return Number.isFinite(n) && n > 0 ? n : 3;
}
