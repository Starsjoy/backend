import { paymeeConfigured, getPaymeeBalance } from "./client.js";

const DEFAULT_THRESHOLD_USDT = 20;
const DEFAULT_INTERVAL_MS = 10 * 60 * 1000;

let monitorInterval = null;

/**
 * Paymee USDT balansni har 10 daqiqada tekshiradi.
 * $20 dan kam bo'lsa ERROR_LOG_CHANNEL_ID ga ogohlantirish yuboradi.
 */
export function startPaymeeBalanceMonitor(options = {}) {
  const {
    bot,
    channelId,
    thresholdUsd = Number(process.env.PAYMEE_BALANCE_ALERT_USDT) || DEFAULT_THRESHOLD_USDT,
    intervalMs = Number(process.env.PAYMEE_BALANCE_CHECK_MS) || DEFAULT_INTERVAL_MS,
  } = options;

  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }

  if (!bot) {
    console.warn("⚠️ Paymee balans monitor: BOT_TOKEN yo'q — ogohlantirish o'chirilgan");
    return null;
  }

  if (!channelId) {
    console.warn("⚠️ Paymee balans monitor: ERROR_LOG_CHANNEL_ID yo'q");
    return null;
  }

  if (!paymeeConfigured()) {
    console.log("ℹ️ Paymee balans monitor: STARS_PAYMEE_API_URL/KEY yo'q — ishlamaydi");
    return null;
  }

  const runCheck = async () => {
    if (!paymeeConfigured()) return;

    try {
      const data = await getPaymeeBalance();
      const balance = Number(data?.balance_usdt);
      if (!Number.isFinite(balance)) {
        console.warn("⚠️ Paymee balans monitor: balance_usdt o'qilmadi", data);
        return;
      }

      if (balance < thresholdUsd) {
        const text =
          `⚠️ <b>Paymee balans kam!</b>\n\n` +
          `💵 Qoldiq: <b>${balance.toFixed(2)} USDT</b>\n` +
          `📉 Ogohlantirish limiti: <b>${thresholdUsd} USDT</b>\n\n` +
          `⛽ Iltimos, Paymee hisobini <b>to'ldiring</b>.`;

        await bot.telegram.sendMessage(channelId, text, { parse_mode: "HTML" });
        console.log(
          `📢 Paymee balans ogohlantirish yuborildi: ${balance.toFixed(2)} USDT < ${thresholdUsd}`
        );
      }
    } catch (err) {
      console.error("❌ Paymee balans monitor tekshiruvi:", err.message);
    }
  };

  void runCheck();
  monitorInterval = setInterval(runCheck, intervalMs);

  console.log(
    `✅ Paymee balans monitor: har ${Math.round(intervalMs / 60_000)} daqiqa, ` +
      `limit ${thresholdUsd} USDT → kanal ${channelId}`
  );

  return {
    stop: () => {
      if (monitorInterval) {
        clearInterval(monitorInterval);
        monitorInterval = null;
      }
    },
  };
}

export function stopPaymeeBalanceMonitor() {
  if (monitorInterval) {
    clearInterval(monitorInterval);
    monitorInterval = null;
  }
}
