import { escapeTelegramHtml } from "../telegram/channelNotify.js";

/** Admin kuzatadigan referal kanali. env bo'lmasa xabar yuborilmaydi. */
function channelId() {
  return process.env.REFERRAL_CHANNEL_ID || "";
}

function userLine(username, userId) {
  const name = String(username || "").replace(/^@/, "");
  return name ? `@${escapeTelegramHtml(name)}` : `ID ${escapeTelegramHtml(userId)}`;
}

function orderLabel(order) {
  const label = String(order.order_type || "").includes("premium")
    ? `Premium ${order.type_amount} oy`
    : `${order.type_amount} Stars`;
  const sum = String(Math.round(Number(order.summ) || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
  return `${label} (${sum} so'm)`;
}

export function buildReferralStartText({ referrerUsername, referrerId, friendUsername, friendId }) {
  return (
    `👋 <b>StarsJoy: yangi referal start bosdi!</b>\n\n` +
    `🙋 Taklif qilgan: ${userLine(referrerUsername, referrerId)}\n` +
    `🆕 Do'sti: ${userLine(friendUsername, friendId)}`
  );
}

export function buildReferralPurchaseText({ referrerUsername, referrerId, friendUsername, friendId, order, points }) {
  return (
    `👥 <b>StarsJoy: referal ishladi!</b>\n\n` +
    `🙋 Taklif qilgan: ${userLine(referrerUsername, referrerId)}\n` +
    `🆕 Do'sti: ${userLine(friendUsername, friendId)}\n` +
    `🛒 Xarid: ${escapeTelegramHtml(orderLabel(order))}\n` +
    `🎁 Bonus: +${points} ⭐\n` +
    `📦 Order: #${escapeTelegramHtml(order.id)}`
  );
}

async function send(bot, text) {
  const chatId = channelId();
  if (!bot || !chatId) return false;
  try {
    await bot.telegram.sendMessage(chatId, text, { parse_mode: "HTML", disable_web_page_preview: true });
    return true;
  } catch (err) {
    console.error("⚠️ Referal kanaliga xabar yuborilmadi:", err.message);
    return false;
  }
}

/** Yangi user referal havola bilan bog'landi. Xato referal bog'lanishiga ta'sir qilmaydi. */
export function notifyReferralStart(bot, params) {
  return send(bot, buildReferralStartText(params));
}

/** Do'stning birinchi xaridi uchun referal bonus yozildi. */
export function notifyReferralPurchase(bot, params) {
  return send(bot, buildReferralPurchaseText(params));
}
