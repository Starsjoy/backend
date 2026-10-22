import { normalizeLanguage } from "../users/userPreferences.js";
import {
  MINI_APP_URL,
  SUPPORT_HANDLE,
  getUserAppLanguage,
  ensureOrderFlagColumn,
  orderPriceLabel,
  orderProductLabel,
} from "./orderExpiredMessages.js";

const TEXTS = {
  uz: {
    sent: (product, to) => `✅ ${product} ${to}'ga muvaffaqiyatli yuborildi!`,
    payment: "💰 To'lov",
    thanks: "Starsjoy'ni tanlaganingiz uchun rahmat! 💙",
    admin: "Admin",
  },
  ru: {
    sent: (product, to) => `✅ ${product} — успешно отправлено ${to}!`,
    payment: "💰 Оплата",
    thanks: "Спасибо, что выбрали Starsjoy! 💙",
    admin: "Админ",
  },
  en: {
    sent: (product, to) => `✅ ${product} successfully sent to ${to}!`,
    payment: "💰 Payment",
    thanks: "Thank you for choosing Starsjoy! 💙",
    admin: "Admin",
  },
};

export function buildDeliveredOrderMessage(order, language) {
  const lang = normalizeLanguage(language);
  const tr = TEXTS[lang];
  const recipient = String(order.recipient_username || order.recipient || "").replace(/^@/, "");
  const to = recipient ? `@${recipient}` : "";

  // Referral yechish kabi bepul buyurtmalarda (summ = 0) to'lov qatori chiqmaydi
  const paymentLine =
    Number(order.summ) > 0 ? `${tr.payment}: ${orderPriceLabel(order.summ, lang)}\n\n` : "";

  const text =
    `${tr.sent(orderProductLabel(order, lang), to)}\n\n` +
    paymentLine +
    `${tr.thanks}\n\n` +
    `${tr.admin}: ${SUPPORT_HANDLE}`;

  return {
    text,
    extra: {
      reply_markup: {
        inline_keyboard: [[{ text: "⭐️ START", url: MINI_APP_URL }]],
      },
    },
  };
}

/**
 * Yetkazilgan buyurtma egasiga "muvaffaqiyatli yuborildi" xabarini uning tilida yuboradi.
 * delivered_notified atomik band qilinadi — admin qayta yuborsa ham xabar 1 marta boradi.
 */
export async function sendDeliveredOrderNotify(pool, bot, orderId) {
  if (!bot || !orderId) return false;

  let order;
  try {
    await ensureOrderFlagColumn(pool, "delivered_notified");
    const claim = await pool.query(
      `UPDATE orders SET delivered_notified = true
       WHERE id = $1 AND status IN ('completed', 'delivered')
         AND COALESCE(delivered_notified, false) = false
         AND owner_user_id IS NOT NULL
       RETURNING id, owner_user_id, order_type, type_amount, summ, recipient_username, recipient`,
      [orderId]
    );
    order = claim.rows[0];
    if (!order) return false;

    const lang = await getUserAppLanguage(pool, order.owner_user_id);
    const { text, extra } = buildDeliveredOrderMessage(order, lang);
    await bot.telegram.sendMessage(order.owner_user_id, text, extra);
    console.log(
      `📩 Yetkazildi xabari yuborildi: user=${order.owner_user_id}, order=#${order.id}, type=${order.order_type}`
    );
    return true;
  } catch (err) {
    console.error(
      `❌ Yetkazildi xabarini yuborishda xato (order=#${order?.id || orderId}):`,
      err.message
    );
    return false;
  }
}
