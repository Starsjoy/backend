/**
 * To'lov kartalari registri — 3 slot: uzcard1, uzcard2 (zaxira), humo1
 *
 * Admin panel switch orqali qaysi karta mijozga ko'rsatilishi DB da saqlanadi
 * (settings.payment_system).
 *
 * MUHIM (SMS listener): karta almashtirilganda ham to'lovlar yo'qolmasligi uchun
 * listener FAQAT aktiv kartani emas, sozlangan BARCHA kartalarni qabul qiladi.
 * Sababi: admin kartani almashtirgan payt mijozning ekranida hali eski karta
 * turgan bo'lishi mumkin — u eski kartaga to'laydi va buyurtma baribir yopiladi.
 *
 * Barcha qiymatlar process.env dan HAR CHAQIRUVDA o'qiladi — ya'ni .env
 * o'zgarsa restartdan keyin darhol qo'llanadi.
 */

/** @typedef {"uzcard1"|"uzcard2"|"humo1"} CardSlot */

export const CARD_SLOTS = ["uzcard1", "uzcard2", "humo1"];

/** Eski qiymatlar bilan moslik (DB da "uzcard"/"humo" turgan bo'lishi mumkin) */
const LEGACY_SLOT_ALIASES = { uzcard: "uzcard1", humo: "humo1" };

const SLOT_DEFS = [
  {
    slot: "uzcard1",
    brand: "uzcard",
    label: "UZCARD",
    title: "UZCARD",
    // StarsJoy'da karta tarixan VITE_CARD_NUMBER da turgan — u oxirgi zaxira
    numberKeys: ["TOPUP_CARD_NUMBER_UZCARD", "TOPUP_CARD_NUMBER", "VITE_CARD_NUMBER"],
    nameKeys: ["TOPUP_CARD_NAME_UZCARD", "TOPUP_CARD_NAME", "VITE_CARD_NAME"],
    suffixKeys: ["TARGET_CARD_SUFFIX_UZCARD", "TARGET_CARD_SUFFIX"],
    chatKeys: ["UZCARD_CHAT_ID"],
  },
  {
    // Zaxira UZCARD: birinchisining limiti tugasa admin paneldan yoqiladi
    slot: "uzcard2",
    brand: "uzcard",
    label: "UZCARD",
    title: "UZCARD",
    numberKeys: ["TOPUP_CARD_NUMBER_UZCARD2"],
    nameKeys: ["TOPUP_CARD_NAME_UZCARD2"],
    suffixKeys: ["TARGET_CARD_SUFFIX_UZCARD2"],
    chatKeys: ["UZCARD_CHAT_ID"],
  },
  {
    slot: "humo1",
    brand: "humo",
    label: "HUMO",
    title: "HUMO",
    numberKeys: ["TOPUP_CARD_NUMBER_HUMO", "VITE_CARD_NUMBER_HUMO"],
    nameKeys: ["TOPUP_CARD_NAME_HUMO", "TOPUP_CARD_NAME", "VITE_CARD_NAME"],
    suffixKeys: ["TARGET_CARD_SUFFIX_HUMO"],
    chatKeys: ["HUMO_CHAT_ID"],
  },
];

const DEF_BY_SLOT = new Map(SLOT_DEFS.map((d) => [d.slot, d]));

function envFirst(keys) {
  for (const k of keys) {
    const v = process.env[k];
    if (v !== undefined && String(v).trim() !== "") return String(v).trim();
  }
  return "";
}

function digitsOnly(v) {
  return String(v ?? "").replace(/\D/g, "");
}

function formatCardGroups(digits) {
  const d = digitsOnly(digits);
  if (!d) return "";
  return d.replace(/(\d{4})(?=\d)/g, "$1 ").trim();
}

/** Karta raqamini yopiq formatda: 9860 **** **** 4466 */
export function maskCardNumber(digits) {
  const d = digitsOnly(digits);
  if (d.length < 8) return d ? `****${d.slice(-4)}` : "";
  return `${d.slice(0, 4)} **** **** ${d.slice(-4)}`;
}

function resolveSlot(def) {
  const number = digitsOnly(envFirst(def.numberKeys));
  // Suffiks .env da ko'rsatilmagan bo'lsa — karta raqamining oxirgi 4 tasi
  const suffix = (digitsOnly(envFirst(def.suffixKeys)) || number).slice(-4);
  const chat_id = envFirst(def.chatKeys);

  return {
    slot: def.slot,
    brand: def.brand,
    label: def.label,
    title: def.title,
    number,
    display: formatCardGroups(number),
    masked: maskCardNumber(number) || (suffix ? `****${suffix}` : ""),
    name: envFirst(def.nameKeys),
    suffix,
    chat_id,
    // configured → SMS ni tanay oladi; payable → mijozga ko'rsata oladi
    configured: Boolean(suffix && chat_id),
    payable: Boolean(number),
  };
}

/** Berilgan qiymatni yaroqli slotga keltiradi (eski "uzcard"/"humo" ham tushunadi) */
export function normalizeCardSlot(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (DEF_BY_SLOT.has(raw)) return raw;
  if (LEGACY_SLOT_ALIASES[raw]) return LEGACY_SLOT_ALIASES[raw];
  return "uzcard1";
}

/** Slot nomidan brend: "humo1" → "humo" */
export function brandOfSlot(slot) {
  return DEF_BY_SLOT.get(normalizeCardSlot(slot))?.brand || "uzcard";
}

/** Barcha slotlar (sozlanmaganlari ham — admin panel ro'yxati uchun) */
export function listCards() {
  return SLOT_DEFS.map(resolveSlot);
}

/** Faqat SMS tanay oladigan kartalar (suffiks + chat bor) */
export function listConfiguredCards() {
  return listCards().filter((c) => c.configured);
}

/** Mijozga ko'rsatish mumkin bo'lgan kartalar (raqami bor) */
export function listPayableCards() {
  return listCards().filter((c) => c.payable);
}

export function getCard(slot) {
  const def = DEF_BY_SLOT.get(normalizeCardSlot(slot));
  return def ? resolveSlot(def) : null;
}

// ===================== RUNTIME (aktiv karta) =====================

let activeSlot = "uzcard1";

export function setPaymentSystemRuntime(slot) {
  activeSlot = normalizeCardSlot(slot);
}

export function getPaymentSystemRuntime() {
  return activeSlot;
}

/** Aktiv karta. Tanlangan slot sozlanmagan bo'lsa — birinchi ishlaydiganiga tushadi. */
export function getActiveCard() {
  const chosen = getCard(activeSlot);
  if (chosen?.payable) return chosen;
  const fallback = listPayableCards()[0];
  if (fallback) {
    console.warn(
      `⚠️ To'lov kartasi ${activeSlot} sozlanmagan (.env da raqami yo'q) — ${fallback.slot} ishlatilmoqda`
    );
    return fallback;
  }
  return chosen || resolveSlot(SLOT_DEFS[0]);
}

// ===================== PAYLOADLAR =====================

/** Frontend va buyurtma xabarlari uchun */
export function getPublicPaymentInfo() {
  const card = getActiveCard();
  return {
    payment_system: card.slot,
    payment_brand: card.brand,
    payment_card_slot: card.slot,
    payment_card_title: card.title,
    payment_card_number: card.number,
    payment_card_name: card.name,
    payment_card_type: card.label,
    payment_card_display: card.display,
  };
}

/** SMS listener uchun (internal) */
export function getInternalPaymentInfo() {
  const active = getActiveCard();
  const cards = listCards().map((c) => ({
    slot: c.slot,
    brand: c.brand,
    label: c.label,
    title: c.title,
    suffix: c.suffix,
    chat_id: c.chat_id,
    configured: c.configured,
    payable: c.payable,
    masked: c.masked,
    active: c.slot === active.slot,
  }));

  return {
    system: active.slot,
    brand: active.brand,
    card_number: active.number,
    card_name: active.name,
    card_suffix: active.suffix,
    chat_id: active.chat_id,
    label: active.label,
    cards,
  };
}

// ===================== SMS: chat va karta topish =====================

export function normalizeChatId(id) {
  return String(id ?? "").replace(/^-100/, "").replace(/^-/, "").trim();
}

export function chatIdMatches(peerId, chatId) {
  if (!chatId) return false;
  return normalizeChatId(peerId) === normalizeChatId(chatId);
}

/** Shu chatga SMS yuboradigan sozlangan kartalar */
export function cardsForChat(peerId) {
  const norm = normalizeChatId(peerId);
  return listConfiguredCards().filter((c) => c.chat_id && normalizeChatId(c.chat_id) === norm);
}

/** SMS dagi oxirgi 4 raqam bo'yicha kartani topish (aktiv bo'lishi SHART EMAS) */
export function findCardForSms(peerId, last4) {
  const suffix = digitsOnly(last4).slice(-4);
  if (!suffix) return null;
  return cardsForChat(peerId).find((c) => c.suffix === suffix) || null;
}

/** Kuzatiladigan barcha chat idlari (dublikatsiz) */
export function monitoredChatIds() {
  const set = new Set();
  for (const c of listConfiguredCards()) {
    if (c.chat_id) set.add(normalizeChatId(c.chat_id));
  }
  return [...set];
}

/** Startupda loglash uchun qisqa hisobot */
export function describeCards() {
  return listCards().map((c) => {
    if (!c.configured) {
      const why = !c.chat_id ? "chat yo'q" : "suffiks yo'q";
      return `${c.title}: — (sozlanmagan: ${why})`;
    }
    const num = c.payable ? c.masked : `***${c.suffix} (raqam yo'q)`;
    return `${c.title}: ${num} | chat ${c.chat_id}`;
  });
}

// ===================== SMS PARSERLAR =====================

function parseUzsAmount(raw) {
  if (!raw) return NaN;
  let s = String(raw).replace(/[\s ]/g, "").trim();
  if (/^\d{1,3}(\.\d{3})+,\d{1,2}$/.test(s)) {
    s = s.replace(/\./g, "").replace(",", ".");
  } else if (/^\d+,\d{1,2}$/.test(s)) {
    s = s.replace(",", ".");
  } else {
    s = s.replace(/,/g, "");
  }
  const n = parseFloat(s);
  return Number.isFinite(n) ? Math.round(n) : NaN;
}

/** HUMO SMS matnini parse qilish */
export function parseHumoPayment(text) {
  if (!text) return null;

  const isHumoIncoming =
    /To['’ʻ`]ldirish/i.test(text) &&
    (/➕|HUMOCARD|Humo2Humo/i.test(text) || /\+\s*[\d.]/.test(text));
  if (!isHumoIncoming) return null;

  const cardMatch =
    text.match(/HUMOCARD\s*\*(\d{4})/i) ||
    text.match(/💳\s*(?:HUMOCARD\s*)?\*(\d{4})/i) ||
    text.match(/💳\s*\*{1,3}(\d{4})/) ||
    text.match(/\*{1,4}(\d{4})/);
  const card_last4 = cardMatch?.[1] ?? null;

  const amountMatch =
    text.match(/➕\s*([\d\s .]+(?:,\d{1,2})?)\s*UZS/i) ||
    text.match(/\+\s*([\d\s .]+(?:,\d{1,2})?)\s*UZS/i);

  if (!amountMatch) return null;
  const amount = parseUzsAmount(amountMatch[1]);
  if (!card_last4 || !amount || amount <= 0) return null;

  return { card_last4, amount, raw_text: text };
}

/** UZCARD SMS matnini parse qilish */
export function parseUzcardPayment(text) {
  if (!text) return null;

  // Kartaning oxirgi 4 raqami: 💳 ***2022 | ****2022 | *2022
  const cardMatch =
    text.match(/💳\s*\*{3}(\d{4})/) ||
    text.match(/\*{4}(\d{4})/) ||
    text.match(/\*{3}(\d{4})/);
  const card_last4 = cardMatch ? cardMatch[1] : null;

  // Kiruvchi summa: ➕ 22 000.00 UZS | +22 000 UZS | 22 000.00 so'm
  const amountMatch =
    text.match(/➕\s*([\d\s ]+(?:\.\d{2})?)\s*UZS/i) ||
    text.match(/\+\s*([\d\s ]+(?:\.\d{2})?)\s*UZS/i) ||
    text.match(
      /(?:Kirim|To['']lov|➕|\+)\s*[:\-]?\s*([\d\s ]+(?:\.\d{2})?)\s*(?:UZS|so['']m|sum)/i
    );

  if (!amountMatch) return null;

  const amount = Math.floor(parseFloat(amountMatch[1].replace(/[\s ]/g, "")));
  if (!card_last4 || !amount || amount <= 0) return null;

  return { card_last4, amount, raw_text: text };
}

/** Brend bo'yicha to'g'ri parserni tanlaydi */
export function parsePaymentForBrand(brand, text) {
  return brand === "humo" ? parseHumoPayment(text) : parseUzcardPayment(text);
}
