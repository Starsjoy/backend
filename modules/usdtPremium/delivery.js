import {
  buyPremiumViaFragment,
  isFragmentCookieError,
  isFragmentPythonSetupError,
} from "../usdtStars/fragmentDelivery.js";
import { notifyFragmentDeliveryIssue } from "../usdtStars/fragmentNotify.js";
import { usdtPremiumSlotKey } from "./orderCreate.js";

/**
 * premium_usdt buyurtmasini Fragment orqali yetkazish.
 */
export async function sendPremiumViaFragment(order, ctx) {
  const {
    pool,
    releasePriceSlotByOrderId,
    releaseDiscountPriceSlotByOrderId,
    removePriceFromCacheByOrderId,
    sendUnifiedChannelNotification,
    processPremiumReferralBonusByUserId,
  } = ctx;

  const orderId = order.id;
  const username = order.recipient_username || order.recipient;
  const months = order.type_amount;

  const payMethod =
    typeof ctx.getFragmentPaymentMethod === "function"
      ? ctx.getFragmentPaymentMethod()
      : "ton";

  console.log("🔹 sendPremiumViaFragment:", {
    orderId,
    username,
    months,
    payment_method: payMethod,
  });

  try {
    const result = await buyPremiumViaFragment(username, months, pool, {
      getFragmentPaymentMethod: ctx.getFragmentPaymentMethod,
    });
    const errMsg = result.error || "";

    if (!result.success) {
      if (isFragmentPythonSetupError(errMsg) || isFragmentCookieError(errMsg)) {
        await pool.query(
          `UPDATE orders SET status = 'processing', payment_status = 'paid' WHERE id = $1`,
          [orderId]
        );
        await notifyFragmentDeliveryIssue(ctx, order, errMsg, "premium");
        sendUnifiedChannelNotification(order, "premium_usdt", true).catch(() => {});
        throw new Error(errMsg);
      }

      await pool.query("UPDATE orders SET status = 'failed' WHERE id = $1", [orderId]);
      releasePriceSlotByOrderId(orderId, usdtPremiumSlotKey(months));
      releaseDiscountPriceSlotByOrderId(orderId);
      removePriceFromCacheByOrderId(orderId);
      sendUnifiedChannelNotification(order, "premium_usdt", true).catch(() => {});
      throw new Error(errMsg || "Fragment premium xatosi");
    }

    const txId = result.transaction_id || `fragment_premium_${Date.now()}`;

    await pool.query(
      `UPDATE orders SET status='completed', payment_status='paid', transaction_id=$1 WHERE id=$2`,
      [txId, orderId]
    );

    releasePriceSlotByOrderId(orderId, usdtPremiumSlotKey(months));
    releaseDiscountPriceSlotByOrderId(orderId);
    removePriceFromCacheByOrderId(orderId);

    if (order.owner_user_id && processPremiumReferralBonusByUserId) {
      processPremiumReferralBonusByUserId(order.owner_user_id, order.id).catch((err) =>
        console.error("❌ Premium referral bonus error:", err.message)
      );
    }

    console.log(`✅ Fragment Premium yuborildi: #${orderId} -> ${txId}`);
    sendUnifiedChannelNotification(order, "premium_usdt").catch(() => {});

    return txId;
  } catch (err) {
    console.error("❌ sendPremiumViaFragment error:", err);

    if (
      !isFragmentCookieError(err.message) &&
      !isFragmentPythonSetupError(err.message)
    ) {
      await pool.query("UPDATE orders SET status='error' WHERE id=$1", [orderId]).catch(() => {});
      releasePriceSlotByOrderId(orderId, usdtPremiumSlotKey(months));
      releaseDiscountPriceSlotByOrderId(orderId);
      removePriceFromCacheByOrderId(orderId);
      sendUnifiedChannelNotification(order, "premium_usdt", true).catch(() => {});
    }

    throw err;
  }
}
