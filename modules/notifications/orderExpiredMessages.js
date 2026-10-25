import { normalizeLanguage } from "../users/userPreferences.js";

export const SUPPORT_HANDLE = "@StarsjoySupport";
export const SUPPORT_URL = "https://t.me/StarsjoySupport";
export const MINI_APP_URL = "https://t.me/StarsjoyBot/starsjoy";

const TEXTS = {
  uz: {
    currency: "so'm",
    body: " belgilangan vaqt ichida to'lov aniqlanmadi.",
    paid: `♻️ To'lagan bo'lsangiz chek skrinshotini va qabul qiluvchi usernameni ${SUPPORT_HANDLE} ga yuboring`,
    admin: "Admin",
    retry: "🔄 Qayta buyurtma berish",
    support: "💬 Support",
    premium: (m) => `Telegram Premium ${m} oy`,
    gift: (s) => `Gift (${s} ⭐)`,
  },
  ru: {
    currency: "сум",
    body: ": оплата не поступила в отведённое время.",
    paid: `♻️ Если вы оплатили, отправьте скриншот чека и username получателя в ${SUPPORT_HANDLE}`,
    admin: "Админ",
    retry: "🔄 Оформить заново",
    support: "💬 Поддержка",
    premium: (m) => `Telegram Premium ${m} мес.`,
    gift: (s) => `Подарок (${s} ⭐)`,
  },
  en: {
    currency: "UZS",
    body: ": payment was not detected within the allotted time.",
    paid: `♻️ If you have paid, send a screenshot of the receipt and the recipient's username to ${SUPPORT_HANDLE}`,
    admin: "Admin",
    retry: "🔄 Order again",
    support: "💬 Support",
    premium: (m) => `Telegram Premium ${m} ${Number(m) === 1 ? "month" : "months"}`,
    gift: (s) => `Gift (${s} ⭐)`,
  },
};

/** stars | stars_paymee | premium_usdt | gift … → stars | premium | gift */
function productKind(orderType) {
  const t = String(orderType || "").toLowerCase();
  if (t.includes("gift")) return "gift";
  if (t.includes("premium")) return "premium";
  return "stars";
}

function formatSum(summ, lang) {
  const sep = lang === "en" ? "," : " ";
  return String(Math.round(Number(summ) || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, sep);
}

function productLabel(order, tr) {
  const kind = productKind(order.order_type);
  if (kind === "premium") return tr.premium(order.type_amount);
  if (kind === "gift") return tr.gift(order.type_amount);
  return `${order.type_amount} Stars`;
}

/** "500 Stars" | "Telegram Premium 3 oy" | "Gift (50 ⭐)" — user tilida */
export function orderProductLabel(order, language) {
  return productLabel(order, TEXTS[normalizeLanguage(language)]);
}

/**
 * User Mini App'da tanlagan til (uz | ru | en). App'da tanlamagan bo'lsa — uz
 * (users.language da bot /start yozgan Telegram tili bo'lishi mumkin, u hisobga olinmaydi).
 */
export async function getUserAppLanguage(pool, userId) {
  const r = await pool.query(
    `SELECT language, language_selected FROM users WHERE user_id = $1`,
    [String(userId)]
  );
  const row = r.rows[0];
  return row?.language_selected ? normalizeLanguage(row.language) : "uz";
}

const flagColumnsReady = new Map();

/** orders jadvaliga "xabar yuborildi" belgisi ustunini (idempotent) qo'shadi — bir marta */
export function ensureOrderFlagColumn(pool, column) {
  if (!flagColumnsReady.has(column)) {
    const p = pool
      .query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS ${column} BOOLEAN DEFAULT false`)
      .catch((err) => {
        flagColumnsReady.delete(column);
        throw err;
      });
    flagColumnsReady.set(column, p);
  }
  return flagColumnsReady.get(column);
}

/** "104 950 so'm" | "104 950 сум" | "104,950 UZS" */
export function orderPriceLabel(summ, language) {
  const lang = normalizeLanguage(language);
  return `${formatSum(summ, lang)} ${TEXTS[lang].currency}`;
}

export function buildExpiredOrderMessage(order, language) {
  const lang = normalizeLanguage(language);
  const tr = TEXTS[lang];
  const text =
    `⚠️ ${productLabel(order, tr)} (${formatSum(order.summ, lang)} ${tr.currency})${tr.body}\n\n` +
    `${tr.paid}`;

  return {
    text,
    extra: {
      reply_markup: {
        inline_keyboard: [
          [{ text: tr.retry, url: MINI_APP_URL }],
          [{ text: tr.support, url: SUPPORT_URL }],
        ],
      },
    },
  };
}

export function shouldSendExpiredOrderNotify(orderType) {
  const t = String(orderType || "").toLowerCase();
  return t.includes("stars") || t.includes("premium") || t === "gift";
}

/**
 * Expired buyurtma egasiga "to'lov aniqlanmadi" xabarini uning tilida yuboradi.
 * expired_notified avval atomik band qilinadi — taymer va har daqiqalik
 * tekshiruv bir vaqtda ishlasa ham xabar faqat 1 marta boradi.
 */
export async function sendExpiredOrderNotify(pool, bot, orderId) {
  if (!bot) return false;

  const claim = await pool.query(
    `UPDATE orders SET expired_notified = true
     WHERE id = $1 AND status = 'expired'
       AND COALESCE(expired_notified, false) = false
       AND owner_user_id IS NOT NULL
     RETURNING id, owner_user_id, order_type, type_amount, summ`,
    [orderId]
  );
  const order = claim.rows[0];
  if (!order || !shouldSendExpiredOrderNotify(order.order_type)) return false;

  try {
    const lang = await getUserAppLanguage(pool, order.owner_user_id);
    const { text, extra } = buildExpiredOrderMessage(order, lang);
    await bot.telegram.sendMessage(order.owner_user_id, text, extra);
    console.log(
      `📩 Expired order xabari yuborildi: user=${order.owner_user_id}, order=#${order.id}, type=${order.order_type}`
    );
    return true;
  } catch (err) {
    console.error(
      `❌ Expired order xabari yuborishda xato (user=${order.owner_user_id}, order=#${order.id}):`,
      err.message
    );
    return false;
  }
}
