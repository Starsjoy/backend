import { escapeTelegramHtml, sendOrdersChannelMessage } from "../telegram/channelNotify.js";

function formatUsdt(n) {
  const v = Number(n);
  if (!Number.isFinite(v)) return "?";
  return v.toFixed(2);
}

function productLabel(product) {
  return product === "premium" ? "Premium" : "Stars";
}

function quantityLabel(order, product) {
  const n = order?.type_amount ?? "?";
  return product === "premium" ? `${n} oy` : `${n} stars`;
}

/**
 * To'lov qabul qilingan, lekin Paymee API balansi yetarli emas — API chaqirilmaydi.
 * Buyurtma failed, error log kanaliga xabar.
 */
export async function failPaymeeOrderInsufficientBalance(order, ctx, details) {
  const {
    pool,
    releasePriceSlotByOrderId,
    releaseDiscountPriceSlotByOrderId,
    removePriceFromCacheByOrderId,
    bot,
  } = ctx;

  const orderId = order.id;
  const {
    product = "stars",
    notifyType,
    slotKey,
    balance_usdt,
    required_usdt,
    apiError,
  } = details;

  await pool.query(
    `UPDATE orders SET status = 'failed', payment_status = 'paid' WHERE id = $1`,
    [orderId]
  );

  if (slotKey) {
    releasePriceSlotByOrderId?.(orderId, slotKey);
  }
  releaseDiscountPriceSlotByOrderId?.(orderId);
  removePriceFromCacheByOrderId?.(orderId);

  const channelId = process.env.ERROR_LOG_CHANNEL_ID;
  const rawRecipient = order.recipient_username || order.recipient || "Noma'lum";
  const formattedRecipient = rawRecipient.startsWith("@")
    ? rawRecipient
    : `@${rawRecipient}`;

  const balanceLine =
    required_usdt != null && balance_usdt != null
      ? `\n💳 Paymee API: kerak <b>${formatUsdt(required_usdt)} USDT</b>, qolgan <b>${formatUsdt(balance_usdt)} USDT</b>`
      : "\n💳 Paymee API balansi yetarli emas";

  const extra =
    apiError && !balanceLine.includes("kerak")
      ? `\n<pre>${escapeTelegramHtml(String(apiError).slice(0, 400))}</pre>`
      : "";

  const text =
    `⚠️ <b>${productLabel(product)} — to'langan, yetkazilmadi</b>\n\n` +
    `📦 Buyurtma: #${orderId}\n` +
    `👤 Qabul qiluvchi: ${escapeTelegramHtml(formattedRecipient)}\n` +
    `💫 Miqdor: ${escapeTelegramHtml(quantityLabel(order, product))}\n` +
    `💰 Summa: ${(Number(order.summ) || 0).toLocaleString()} so'm\n` +
    `❌ Sabab: API balansi yetarli emas (Partner API chaqirilmadi)` +
    balanceLine +
    extra;

  if (channelId) {
    await sendOrdersChannelMessage({
      text,
      channelId,
      bot,
      botToken: process.env.BOT_TOKEN,
    }).catch(() => {});
  }

  console.log(
    `❌ Paymee #${orderId}: to'langan, yetkazilmadi — API balans yetarli emas` +
      (required_usdt != null ? ` (kerak ${formatUsdt(required_usdt)}, qolgan ${formatUsdt(balance_usdt)})` : "")
  );

  return {
    success: false,
    code: "PAYMEE_INSUFFICIENT_BALANCE",
    skipped_api: true,
    order_id: orderId,
  };
}
