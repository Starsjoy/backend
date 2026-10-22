import { sendDelayedOrderNotify } from "../notifications/orderDelayedMessages.js";

/** Telegram HTML xabarlar uchun xavfsiz matn (traceback dagi <module> va h.k.) */
export function escapeTelegramHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export async function notifyFragmentDeliveryIssue(ctx, order, errMsg, kind = "stars") {
  const { bot } = ctx;
  const channelId = process.env.ERROR_LOG_CHANNEL_ID;
  const owner = order.owner_user_id;
  const isPremium = kind === "premium";
  const amountLabel = isPremium ? `${order.type_amount} oy` : `${order.type_amount}⭐`;
  const safeErr = escapeTelegramHtml(String(errMsg || "noma'lum xato").slice(0, 500));

  const text =
    `⚠️ <b>Fragment ${isPremium ? "Premium" : "Stars"} xatosi</b>\n` +
    `Buyurtma: #${order.id}\n` +
    `@${escapeTelegramHtml(order.recipient_username)} — ${amountLabel}\n` +
    `To'lov: ${order.summ} so'm (qabul qilingan)\n\n` +
    `<pre>${safeErr}</pre>\n\n` +
    `👉 Cookie yangilang: fragment.com → DevTools → Cookies (stel_ssid, stel_token, stel_ton_token). ` +
    `Admin 🍪 Fragment tab → saqlash → Cookie test OK → pm2 restart.`;

  if (bot && channelId) {
    try {
      await bot.telegram.sendMessage(channelId, text, { parse_mode: "HTML" });
    } catch (e) {
      console.error("❌ Fragment xato kanaliga yuborilmadi:", e.message);
    }
  }

  if (owner) {
    await sendDelayedOrderNotify(ctx.pool, bot, order.id);
  }
}
