import { normalizeLanguage } from "../users/userPreferences.js";
import {
  SUPPORT_HANDLE,
  getUserAppLanguage,
  SUPPORT_URL,
  ensureOrderFlagColumn,
  orderPriceLabel,
  orderProductLabel,
} from "./orderExpiredMessages.js";
import { loadSettings } from "../settings/settingsDb.js";

const TEXTS = {
  uz: {
    received: (product, price) => `⏳ ${product} (${price}) uchun to'lovingiz qabul qilindi!`,
    body:
      "Yetkazishda texnik kechikish yuz berdi. Pulingiz xavfsiz, qayta to'lov qilish shart emas.\n\n" +
      "Admin buyurtmani tez orada yuboradi, yuborilgach sizga xabar keladi.",
    // Admin "Kechikish ogohlantirishi" yoqilganda body o'rniga
    body12h:
      "Tarmoqdagi uzilishlar sababli buyurtmangiz 12 soatgacha kechikishi mumkin. " +
      "Pulingiz xavfsiz, qayta to'lov qilish shart emas.",
    order: "Buyurtma",
    admin: "Admin",
    support: "💬 Support",
  },
  ru: {
    received: (product, price) => `⏳ ${product} (${price}): ваша оплата получена!`,
    body:
      "При отправке произошла техническая задержка. Ваши деньги в безопасности, повторно оплачивать не нужно.\n\n" +
      "Админ скоро отправит заказ, после отправки вы получите уведомление.",
    body12h:
      "Из-за перебоев в сети ваш заказ может задержаться до 12 часов. " +
      "Ваши деньги в безопасности, повторно оплачивать не нужно.",
    order: "Заказ",
    admin: "Админ",
    support: "💬 Поддержка",
  },
  en: {
    received: (product, price) => `⏳ ${product} (${price}): your payment has been received!`,
    body:
      "There was a technical delay in delivery. Your money is safe, no need to pay again.\n\n" +
      "The admin will send your order shortly, and you'll be notified once it's sent.",
    body12h:
      "Due to network disruptions, your order may be delayed by up to 12 hours. " +
      "Your money is safe, no need to pay again.",
    order: "Order",
    admin: "Admin",
    support: "💬 Support",
  },
};

export function buildDelayedOrderMessage(order, language, { delay12h = false } = {}) {
  const lang = normalizeLanguage(language);
  const tr = TEXTS[lang];
  const text =
    `${tr.received(orderProductLabel(order, lang), orderPriceLabel(order.summ, lang))}\n\n` +
    `${delay12h ? tr.body12h : tr.body}\n\n` +
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
    let delay12h = false;
    try {
      delay12h = Boolean((await loadSettings(pool)).delay_notice);
    } catch {
      /* sozlama o'qilmasa — oddiy matn */
    }
    const { text, extra } = buildDelayedOrderMessage(order, lang, { delay12h });
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
