import { normalizeLanguage } from "../users/userPreferences.js";
import {
  SUPPORT_HANDLE,
  getUserAppLanguage,
  SUPPORT_URL,
  ensureOrderFlagColumn,
  orderPriceLabel,
  orderProductLabel,
} from "./orderExpiredMessages.js";

const TEXTS = {
  uz: {
    received: (product, price) => `⏳ ${product} (${price}) uchun to'lovingiz qabul qilindi!`,
    body:
      "Yetkazishda texnik kechikish yuz berdi. Pulingiz xavfsiz, qayta to'lov qilish shart emas.\n" +
      "Admin buyurtmani tez orada yuboradi, yuborilgach sizga xabar keladi.",
    order: "Buyurtma",
    admin: "Admin",
    support: "💬 Support",
  },
  ru: {
    received: (product, price) => `⏳ ${product} (${price}): ваша оплата получена!`,
    body:
      "При отправке произошла техническая задержка. Ваши деньги в безопасности, повторно оплачивать не нужно.\n" +
      "Админ скоро отправит заказ, после отправки вы получите уведомление.",
    order: "Заказ",
    admin: "Админ",
    support: "💬 Поддержка",
  },
  en: {
    received: (product, price) => `⏳ ${product} (${price}): your payment has been received!`,
    body:
      "There was a technical delay in delivery. Your money is safe, no need to pay again.\n" +
      "The admin will send your order shortly, and you'll be notified once it's sent.",
    order: "Order",
    admin: "Admin",
    support: "💬 Support",
  },
};

export function buildDelayedOrderMessage(order, language) {
  const lang = normalizeLanguage(language);
  const tr = TEXTS[lang];
  const text =
    `${tr.received(orderProductLabel(order, lang), orderPriceLabel(order.summ, lang))}\n\n` +
    `${tr.body}\n\n` +
    `${tr.order}: #${order.id}\n` +
    `${tr.admin}: ${SUPPORT_HANDLE}`;

  return {
    text,
    extra: {
      reply_markup: {
        inline_keyboard: [[{ text: tr.support, url: SUPPORT_URL }]],
      },
    },
  };
}

/**
 * To'lov qabul qilingan, lekin yetkazilmagan buyurtma egasiga "kechikish" xabarini
 * uning tilida yuboradi. delay_notified atomik band qilinadi — bir nechta xato
 * joyi chaqirsa ham xabar 1 marta boradi. Bepul (summ = 0) buyurtmalarga bormaydi.
 */
export async function sendDelayedOrderNotify(pool, bot, orderId) {
  if (!bot || !orderId) return false;

  let order;
  try {
    await ensureOrderFlagColumn(pool, "delay_notified");
    const claim = await pool.query(
      `UPDATE orders SET delay_notified = true
       WHERE id = $1 AND status IN ('failed', 'error', 'processing')
         AND COALESCE(delay_notified, false) = false
         AND owner_user_id IS NOT NULL
         AND summ > 0
       RETURNING id, owner_user_id, order_type, type_amount, summ`,
      [orderId]
    );
    order = claim.rows[0];
    if (!order) return false;

    const lang = await getUserAppLanguage(pool, order.owner_user_id);
    const { text, extra } = buildDelayedOrderMessage(order, lang);
    await bot.telegram.sendMessage(order.owner_user_id, text, extra);
    console.log(
      `📩 Kechikish xabari yuborildi: user=${order.owner_user_id}, order=#${order.id}, type=${order.order_type}`
    );
    return true;
  } catch (err) {
    console.error(
      `❌ Kechikish xabarini yuborishda xato (order=#${order?.id || orderId}):`,
      err.message
    );
    return false;
  }
}
