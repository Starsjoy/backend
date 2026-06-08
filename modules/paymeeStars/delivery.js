import {
  deliverStarsViaPaymeeApi,
  isPartnerPurchaseSuccess,
  isPaymeeBalanceError,
  isPaymeeConfigError,
  isPaymeeRetryableError,
  shouldRetryPaymeePurchase,
  paymeeConfigured,
  checkPaymeeFulfillment,
} from "../paymeeClient/index.js";
import { failPaymeeOrderInsufficientBalance } from "../paymeeClient/paidUndelivered.js";
import { paymeeSlotKey } from "./orderCreate.js";

/**
 * stars_paymee buyurtmasini StarsPaymee Partner API orqali yetkazish.
 */
export async function sendStarsViaPaymee(order, ctx) {
  const {
    pool,
    releasePriceSlotByOrderId,
    releaseDiscountPriceSlotByOrderId,
    removePriceFromCacheByOrderId,
    sendUnifiedChannelNotification,
    bot,
  } = ctx;

  const orderId = order.id;
  const username = order.recipient_username || order.recipient;
  const stars = order.type_amount;
  const slotKey = paymeeSlotKey(stars);

  if (!paymeeConfigured()) {
    const msg = "STARS_PAYMEE_API_URL / STARS_PAYMEE_API_KEY .env da sozlang";
    await pool.query(
      `UPDATE orders SET status = 'processing', payment_status = 'paid' WHERE id = $1`,
      [orderId]
    );
    throw new Error(msg);
  }

  console.log("🔹 sendStarsViaPaymee:", { orderId, username, stars });

  const fulfillment = await checkPaymeeFulfillment({ product: "stars", stars });
  if (!fulfillment.ok && fulfillment.code === "PAYMEE_INSUFFICIENT_BALANCE") {
    return failPaymeeOrderInsufficientBalance(order, ctx, {
      product: "stars",
      notifyType: "stars_paymee",
      slotKey,
      balance_usdt: fulfillment.balance_usdt,
      required_usdt: fulfillment.required_usdt,
    });
  }

  try {
    let data;
    try {
      data = await deliverStarsViaPaymeeApi(username, stars, orderId);
    } catch (firstErr) {
      if (shouldRetryPaymeePurchase(firstErr)) {
        const retryKey = `paymee-stars-${orderId}-r-${Date.now()}`;
        console.warn(
          `🔄 Paymee stars #${orderId} qayta urinish (${firstErr.message}) key=${retryKey}`
        );
        data = await deliverStarsViaPaymeeApi(username, stars, orderId, retryKey);
      } else {
        throw firstErr;
      }
    }

    if (!isPartnerPurchaseSuccess(data)) {
      throw new Error(
        data?.error || `Paymee javob noto'g'ri: ${JSON.stringify(data).slice(0, 200)}`
      );
    }

    const txId = data.transaction_id || `paymee_${orderId}_${Date.now()}`;

    await pool.query(
      `UPDATE orders SET status='completed', payment_status='paid', transaction_id=$1 WHERE id=$2`,
      [txId, orderId]
    );

    releasePriceSlotByOrderId(orderId, slotKey);
    releaseDiscountPriceSlotByOrderId(orderId);
    removePriceFromCacheByOrderId(orderId);

    console.log(`✅ Paymee Stars yuborildi: #${orderId} -> ${txId}`);
    sendUnifiedChannelNotification(order, "stars_paymee").catch(() => {});

    return { success: true, transaction_id: txId };
  } catch (err) {
    const errMsg = err.message || String(err);
    console.error(
      `❌ Paymee stars #${orderId} (@${username}, ${stars}⭐):`,
      errMsg,
      err.body ? JSON.stringify(err.body).slice(0, 400) : ""
    );

    if (isPaymeeBalanceError(err)) {
      return failPaymeeOrderInsufficientBalance(order, ctx, {
        product: "stars",
        notifyType: "stars_paymee",
        slotKey,
        balance_usdt: err.body?.balance_usdt,
        required_usdt: err.body?.required_usdt,
        apiError: errMsg,
      });
    }

    if (isPaymeeConfigError(err) || isPaymeeRetryableError(err)) {
      await pool.query(
        `UPDATE orders SET status = 'processing', payment_status = 'paid' WHERE id = $1`,
        [orderId]
      );
      if (bot && process.env.ADMIN_IDS) {
        const admins = String(process.env.ADMIN_IDS)
          .split(",")
          .map((id) => id.trim())
          .filter(Boolean);
        for (const adminId of admins) {
          bot.telegram
            .sendMessage(
              adminId,
              `⚠️ Paymee stars #${orderId} (@${username}, ${stars}⭐)\n${errMsg}`
            )
            .catch(() => {});
        }
      }
      throw err;
    }

    await pool.query("UPDATE orders SET status = 'failed' WHERE id = $1", [orderId]);
    releasePriceSlotByOrderId(orderId, slotKey);
    releaseDiscountPriceSlotByOrderId(orderId);
    removePriceFromCacheByOrderId(orderId);
    sendUnifiedChannelNotification(order, "stars_paymee", true).catch(() => {});
    throw err;
  }
}
