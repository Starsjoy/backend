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
  { level: 1, gift_id: "5170233102089322756", stars: 15, required: 5,  label: "Ayiqcha 🧸",       comment: "1-missiya: 5 do'st bonus sovg'asi 🎁" },
  { level: 2, gift_id: "5168103777563050263", stars: 25, required: 7,  label: "Sovg'a 🎁",        comment: "2-missiya: 7 do'st sovg'asi 🎁" },
  { level: 3, gift_id: "5800655655995968830", stars: 50, required: 15, label: "Maxsus stiker ✨", comment: "3-missiya: 15 do'st stiker sovg'asi ✨" },
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

/**
 * Missiya gift'larini ilova sotadigan (userbot yubora oladigan) katalog bilan solishtiradi.
 * Noma'lum gift claim paytida yetkazilmaydi — buni ishga tushishda ko'rish yaxshiroq.
 *
 * @param {Record<string, number>} giftStarsMap  gift_id → stars (server.js GIFT_STARS_MAP)
 */
export function validateMissionGifts(giftStarsMap = {}) {
  const problems = [];
  for (const m of getMissions()) {
    const catalogStars = giftStarsMap[String(m.gift_id)];
    if (catalogStars === undefined) {
      problems.push(`missiya ${m.level}: gift ${m.gift_id} katalogda YO'Q — yetkazib bo'lmasligi mumkin`);
    } else if (catalogStars !== m.stars) {
      problems.push(`missiya ${m.level}: gift ${m.gift_id} narxi ${catalogStars}⭐, configda ${m.stars}⭐`);
    }
  }
  if (problems.length) {
    console.warn("⚠️ Missiya gift tekshiruvi:");
    problems.forEach((p) => console.warn("   • " + p));
  } else {
    console.log("✅ Missiya gift'lari katalog bilan mos");
  }
  return problems;
}
