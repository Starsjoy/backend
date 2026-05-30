import {
  deliverStarsViaPaymeeApi,
  isPartnerPurchaseSuccess,
  paymeeConfigured,
  shouldRetryPaymeePurchase,
} from "../paymeeClient/index.js";
import { getCachedSettings } from "../settings/settingsDb.js";
import { fetchUserbotStarsBalance } from "./balance.js";
import {
  getGiftBalanceMin,
  getRefillCooldownMs,
  getRefillRecipientUsername,
  getRefillStarsAmount,
} from "./config.js";
import {
  getRecentSuccessfulRefill,
  insertRefillRecord,
  updateRefillRecord,
} from "./db.js";

let refillInProgress = false;

export function getUserbotRefillPublicConfig() {
  return {
    min_balance: getGiftBalanceMin(),
    refill_stars: getRefillStarsAmount(),
    refill_username: getRefillRecipientUsername(),
    cooldown_ms: getRefillCooldownMs(),
  };
}

/**
 * Gift buyurtma yaratilishida: balans < GIFT_BALANCE bo'lsa Paymee orqali to'ldirish.
 * `orders` jadvaliga yozilmaydi — faqat `userbot_star_refills`.
 */
export async function ensureUserbotStarRefillForGiftOrder(ctx, options = {}) {
  const { pool, notifyOrdersChannel } = ctx;
  const trigger = options.trigger || "gift_order";

  const settings = getCachedSettings();
  if (!settings.userbot_auto_refill_enabled) {
    return { action: "skipped", reason: "disabled" };
  }

  if (!paymeeConfigured()) {
    return { action: "skipped", reason: "paymee_not_configured" };
  }

  const minBalance = getGiftBalanceMin();
  const refillStars = getRefillStarsAmount();
  const recipient = getRefillRecipientUsername();

  const balanceBefore = await fetchUserbotStarsBalance();
  if (balanceBefore == null) {
    return { action: "skipped", reason: "balance_unavailable" };
  }

  if (balanceBefore >= minBalance) {
    return { action: "ok", balance: balanceBefore, reason: "balance_sufficient" };
  }

  const recent = await getRecentSuccessfulRefill(pool, getRefillCooldownMs());
  if (recent) {
    return {
      action: "skipped",
      reason: "cooldown",
      balance: balanceBefore,
      last_refill_at: recent.created_at,
    };
  }

  if (refillInProgress) {
    return { action: "skipped", reason: "in_progress", balance: balanceBefore };
  }

  refillInProgress = true;
  let record = null;

  try {
    record = await insertRefillRecord(pool, {
      stars_amount: refillStars,
      recipient_username: recipient,
      balance_before: balanceBefore,
      trigger_reason: trigger,
      status: "pending",
    });

    const idempotencyKey = `userbot-refill-${record.id}`;
    let paymeeData;

    try {
      paymeeData = await deliverStarsViaPaymeeApi(
        recipient,
        refillStars,
        `refill-${record.id}`,
        idempotencyKey
      );
    } catch (firstErr) {
      if (shouldRetryPaymeePurchase(firstErr)) {
        paymeeData = await deliverStarsViaPaymeeApi(
          recipient,
          refillStars,
          `refill-${record.id}`,
          `${idempotencyKey}-r2`
        );
      } else {
        throw firstErr;
      }
    }

    if (!isPartnerPurchaseSuccess(paymeeData)) {
      throw new Error(
        paymeeData?.error || `Paymee javob: ${JSON.stringify(paymeeData).slice(0, 180)}`
      );
    }

    const txId = paymeeData.transaction_id || `paymee_refill_${record.id}`;
    const balanceAfter = await fetchUserbotStarsBalance();

    await updateRefillRecord(pool, record.id, {
      status: "completed",
      transaction_id: txId,
      paymee_response: paymeeData,
      balance_after: balanceAfter,
    });

    const msg =
      `🤖 <b>Userbot avto-to'ldirish</b>\n\n` +
      `⭐ Userbot balansi <b>${balanceBefore}</b> ⭐ edi (minimum: <b>${minBalance}</b>).\n\n` +
      `✅ Paymee orqali <b>${refillStars}</b> ⭐ yuborildi → @${recipient}\n` +
      `🆔 Tranzaksiya: <code>${txId}</code>\n` +
      (balanceAfter != null ? `📊 Hozirgi balans: <b>${balanceAfter}</b> ⭐\n` : "") +
      `\n📌 Sabab: gift buyurtmasi (balans past)`;

    if (notifyOrdersChannel) {
      await notifyOrdersChannel(msg);
    }

    console.log(
      `✅ Userbot refill #${record.id}: ${refillStars}⭐ → @${recipient} (balans ${balanceBefore}→${balanceAfter ?? "?"})`
    );

    return {
      action: "refilled",
      refill_id: record.id,
      transaction_id: txId,
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      stars: refillStars,
      recipient,
    };
  } catch (err) {
    const errMsg = err.message || String(err);
    console.error("❌ Userbot star refill:", errMsg);

    if (record?.id) {
      await updateRefillRecord(pool, record.id, {
        status: "failed",
        error_message: errMsg,
        paymee_response: err.body || null,
      });
    }

    if (notifyOrdersChannel) {
      await notifyOrdersChannel(
        `⚠️ <b>Userbot avto-to'ldirish XATO</b>\n\n` +
          `⭐ Balans: <b>${balanceBefore}</b> (min: ${minBalance})\n` +
          `👤 Maqsad: @${recipient}, ${refillStars} ⭐\n` +
          `❌ ${errMsg}`
      );
    }

    return {
      action: "failed",
      error: errMsg,
      balance: balanceBefore,
      refill_id: record?.id,
    };
  } finally {
    refillInProgress = false;
  }
}
