/**
 * Bonus missiya konfiguratsiyasi.
 *
 * ⚠️ env FUNKSIYA ICHIDA o'qiladi: server.js da `dotenv.config()` importlardan
 * keyin chaqiriladi, shuning uchun modul yuklanish paytida process.env hali bo'sh.
 *
 * gift_id — Telegram rasmiy gift katalogi IDsi (getAvailableGifts qaytaradi).
 * Frontend xuddi shu ID nomli `.tgs` faylni src/assets/ dan oladi, shuning uchun
 * .env orqali gift_id ni o'zgartirsangiz mos `.tgs` faylni ham qo'shish kerak.
 */

const DEFAULTS = [
  { level: 1, gift_id: "5170233102089322756", stars: 15, required: 5,  label: "Ayiqcha 🧸",  comment: "1-missiya: 5 do'st bonus sovg'asi 🎁" },
  { level: 2, gift_id: "5168103777563050263", stars: 25, required: 7,  label: "Atirgul 🌹",  comment: "2-missiya: 7 do'st sovg'asi 🎁" },
  { level: 3, gift_id: "5170144170496491616", stars: 50, required: 15, label: "Tort 🎂",     comment: "3-missiya: 15 do'st sovg'asi 🎂" },
  { level: 4, gift_id: "5170314324215857265", stars: 50, required: 17, label: "Guldasta 💐", comment: "4-missiya: 17 do'st noyob sovg'asi 💐" },
  { level: 5, gift_id: "6028601630662853006", stars: 50, required: 20, label: "Shampan 🍾",  comment: "5-missiya: 20 do'st premium sovg'asi 🍾" },
];

let cachedMissions = null;
let cachedVerifyMs = null;

/** Missiyalar ro'yxati (birinchi chaqiruvda env'dan o'qib keshlanadi). */
export function getMissions() {
  if (!cachedMissions) {
    cachedMissions = DEFAULTS.map((m) => ({
      ...m,
      gift_id: String(process.env[`MISSION${m.level}_GIFT_ID`] || m.gift_id),
    }));
  }
  return cachedMissions;
}

export function getMissionByLevel(level) {
  return getMissions().find((m) => m.level === level) || null;
}

/** Do'stlar kanalda turishi kerak bo'lgan oyna. Test uchun MISSION_VERIFY_HOURS=0.01 qo'ying. */
export function getMissionVerifyMs() {
  if (cachedVerifyMs === null) {
    const hours = Number(process.env.MISSION_VERIFY_HOURS ?? 24);
    cachedVerifyMs = Math.max(0, Number.isFinite(hours) ? hours : 24) * 60 * 60 * 1000;
  }
  return cachedVerifyMs;
}

/** Faqat testlar uchun — env o'zgartirilgach keshni tozalash. */
export function resetMissionConfigCache() {
  cachedMissions = null;
  cachedVerifyMs = null;
}
