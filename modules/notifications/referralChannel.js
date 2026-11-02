import { escapeTelegramHtml } from "../telegram/channelNotify.js";

// Referal kanali: uch loyihaning referal va bonus yechish xabarlari shu yerda.
// Kanalda boshqa loyihalar ham bor: har xabar boshida loyiha nomi turadi.
const PROJECT_HEADER = "🟨 <b>StarsJoy</b>\n";

/* Telegram kanalga ~20 xabar/daqiqa ruxsat beradi: navbat + sekin yuborish.
   to'lsa eng eskisi tashlanadi (bu log, buyurtma/bonus jarayoniga ta'sir qilmaydi). */
const QUEUE_MAX = 300;
const GAP_MS = 3200;
const queue = [];
let timer = null;

function drain(bot) {
  if (timer || !queue.length) return;
  timer = setTimeout(async () => {
    timer = null;
    const text = queue.shift();
    try {
      await bot.telegram.sendMessage(process.env.REFERRAL_CHANNEL_ID, text, {
        parse_mode: "HTML",
        disable_web_page_preview: true,
      });
    } catch (err) {
      console.error("⚠️ Referal kanaliga xabar yuborilmadi:", err.message);
    }
    drain(bot);
  }, queue.length > 1 ? GAP_MS : 50);
}

function channelLog(bot, text) {
  if (!bot || !process.env.REFERRAL_CHANNEL_ID) return;
  if (queue.length >= QUEUE_MAX) queue.shift();
  queue.push(PROJECT_HEADER + text);
  drain(bot);
}

function userLine(username, userId) {
  const name = String(username || "").replace(/^@/, "");
  return name ? `@${escapeTelegramHtml(name)}` : `ID ${escapeTelegramHtml(userId)}`;
}

function orderLabel(order) {
  const label = String(order.order_type || "").includes("premium")
    ? `Premium ${order.type_amount} oy`
    : String(order.order_type || "").includes("gift")
      ? `Gift (${order.type_amount} ⭐)`
      : `${order.type_amount} Stars`;
  const sum = String(Math.round(Number(order.summ) || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
  return `${label} (${sum} so'm)`;
}

/** Yangi user referal havola bilan bog'landi */
export function notifyReferralStart(bot, { referrerUsername, referrerId, friendUsername, friendId }) {
  channelLog(
    bot,
    `👋 <b>Yangi referal start bosdi</b>\n\n` +
      `🙋 Taklif qilgan: ${userLine(referrerUsername, referrerId)}\n` +
      `🆕 Do'sti: ${userLine(friendUsername, friendId)}`
  );
}

/** Do'stning birinchi xaridi uchun referal bonus yozildi */
export function notifyReferralPurchase(bot, { referrerUsername, referrerId, friendUsername, friendId, order, points }) {
  channelLog(
    bot,
    `👥 <b>Referal bonus</b>\n\n` +
      `👤 Bonus oldi: ${userLine(referrerUsername, referrerId)} (taklif qilgani uchun)\n` +
      `🆕 Do'sti: ${userLine(friendUsername, friendId)}\n` +
      `🛒 Do'sti xaridi: ${escapeTelegramHtml(orderLabel(order))}\n` +
      `⭐ Bonus: +${points} ⭐\n` +
      `📦 Order: #${escapeTelegramHtml(order.id)}`
  );
}

/** Bonus yechildi. /modad zararni shu xabardan yozadi — format o'zgarsa webhook'ni ham yangilang */
export function notifyRedemption(bot, { owner, recipient, item, orderId, history = "" }) {
  channelLog(
    bot,
    `🎁 <b>User bonus oldi!</b>\n\n` +
      `👤 Yechdi: ${userLine(owner)}\n` +
      `📥 Oldi: ${userLine(recipient)}\n` +
      `💫 ${escapeTelegramHtml(item)} (bonus balansdan)\n` +
      `📦 Order: #${escapeTelegramHtml(orderId)}\n` +
      `✅ Status: Yetkazildi` +
      history
  );
}
