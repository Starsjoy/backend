import {
  buyStarsViaFragment,
  isFragmentCookieError,
  isFragmentPythonSetupError,
} from "./fragmentDelivery.js";
import { notifyFragmentDeliveryIssue } from "./fragmentNotify.js";

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
      if (isFragmentPythonSetupError(errMsg)) {
        await pool.query(
          `UPDATE orders SET status = 'processing', payment_status = 'paid' WHERE id = $1`,
          [orderId]
        );
        await notifyFragmentDeliveryIssue(ctx, order, errMsg, "stars");
        throw new Error(errMsg);
      }

      if (isFragmentCookieError(errMsg)) {
        await pool.query(
          `UPDATE orders SET status = 'processing', payment_status = 'paid' WHERE id = $1`,
          [orderId]
        );
        await notifyFragmentDeliveryIssue(ctx, order, errMsg, "stars");
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

    return { success: true, transaction_id: txId };
  } catch (err) {
    console.error("❌ sendStarsViaFragment error:", err);
    throw err;
  }
}
