import { buyStarsViaFragment, isFragmentCookieError } from "./fragmentDelivery.js";

async function notifyFragmentCookieIssue(ctx, order, errMsg) {
  const { bot } = ctx;
  const channelId = process.env.ERROR_LOG_CHANNEL_ID;
  const owner = order.owner_user_id;

  const text =
    `⚠️ <b>Fragment cookie xatosi</b>\n` +
    `Buyurtma: #${order.id}\n` +
    `@${order.recipient_username} — ${order.type_amount}⭐\n` +
    `To'lov: ${order.summ} so'm (qabul qilingan)\n\n` +
    `<code>${String(errMsg || "").slice(0, 400)}</code>\n\n` +
    `👉 fragment.com dan yangi cookie oling va serverni qayta ishga tushiring.\n` +
    `Admin paneldan qo'lda yuborish mumkin.`;

  if (bot && channelId) {
    try {
      await bot.telegram.sendMessage(channelId, text, { parse_mode: "HTML" });
    } catch (e) {
      console.error("❌ Fragment xato kanaliga yuborilmadi:", e.message);
    }
  }

  if (bot && owner) {
    try {
      await bot.telegram.sendMessage(
        owner,
        `⚠️ To'lovingiz qabul qilindi, lekin stars hozir avtomatik yuborilmadi.\n\nAdmin tez orada yuboradi yoki @StarsPaymeeSupport ga yozing.\n\nBuyurtma #${order.id}`
      );
    } catch {
      /* ignore */
    }
  }
}

/**
 * stars_usdt buyurtmasini Fragment orqali yetkazish (RobynHood emas).
 */
export async function sendStarsViaFragment(order, ctx) {
  const {
    pool,
    releasePriceSlotByOrderId,
    releaseDiscountPriceSlotByOrderId,
    removePriceFromCacheByOrderId,
    sendUnifiedChannelNotification,
    usdtSlotKey,
  } = ctx;

  const orderId = order.id;
  const username = order.recipient_username || order.recipient;
  const stars = order.type_amount;

  const paymentMethod =
    typeof ctx.getFragmentPaymentMethod === "function"
      ? ctx.getFragmentPaymentMethod()
      : "ton";

  console.log("🔹 sendStarsViaFragment:", {
    orderId,
    username,
    stars,
    payment_method: paymentMethod,
  });

  try {
    const result = await buyStarsViaFragment(username, stars, pool, {
      getFragmentPaymentMethod: ctx.getFragmentPaymentMethod,
    });
    const errMsg = result.error || "";

    if (!result.success) {
      if (isFragmentCookieError(errMsg)) {
        await pool.query(
          `UPDATE orders SET status = 'processing', payment_status = 'paid' WHERE id = $1`,
          [orderId]
        );
        await notifyFragmentCookieIssue(ctx, order, errMsg);
        sendUnifiedChannelNotification(order, "stars_usdt", true).catch(() => {});
        throw new Error(errMsg);
      }

      await pool.query("UPDATE orders SET status = 'failed' WHERE id = $1", [orderId]);
      releasePriceSlotByOrderId(orderId, usdtSlotKey(stars));
      releaseDiscountPriceSlotByOrderId(orderId);
      removePriceFromCacheByOrderId(orderId);
      sendUnifiedChannelNotification(order, "stars_usdt", true).catch(() => {});
      throw new Error(errMsg || "Fragment stars xatosi");
    }

    const txId = result.transaction_id || `fragment_${Date.now()}`;

    await pool.query(
      `UPDATE orders SET status='completed', payment_status='paid', transaction_id=$1 WHERE id=$2`,
      [txId, orderId]
    );

    releasePriceSlotByOrderId(orderId, usdtSlotKey(stars));
    releaseDiscountPriceSlotByOrderId(orderId);
    removePriceFromCacheByOrderId(orderId);

    console.log(`✅ Fragment Stars yuborildi: #${orderId} -> ${txId}`);
    sendUnifiedChannelNotification(order, "stars_usdt").catch(() => {});

    return txId;
  } catch (err) {
    console.error("❌ sendStarsViaFragment error:", err);

    if (!isFragmentCookieError(err.message)) {
      await pool.query("UPDATE orders SET status='error' WHERE id=$1", [orderId]).catch(() => {});
      releasePriceSlotByOrderId(orderId, usdtSlotKey(stars));
      releaseDiscountPriceSlotByOrderId(orderId);
      removePriceFromCacheByOrderId(orderId);
      sendUnifiedChannelNotification(order, "stars_usdt", true).catch(() => {});
    }

    throw err;
  }
}
