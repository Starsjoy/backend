import {
  paymeeConfigured,
  getPaymeeBalance,
  getPaymeePricing,
} from "./client.js";

export const PAYMEE_OUT_OF_STOCK_MESSAGES = {
  stars:
    "Afsuski, stars tugab qoldi. Admin hozir to'ldirmoqda. Keyinroq qayta urinib ko'ring.",
  premium:
    "Afsuski, Premium tugab qoldi. Admin hozir to'ldirmoqda. Keyinroq qayta urinib ko'ring.",
  gift:
    "Afsuski, Gift tugab qoldi. Admin hozir to'ldirmoqda. Keyinroq qayta urinib ko'ring.",
};

export function getPaymeeOutOfStockMessage(product) {
  return PAYMEE_OUT_OF_STOCK_MESSAGES[product] || PAYMEE_OUT_OF_STOCK_MESSAGES.stars;
}

/**
 * @param {{ product: 'stars'|'premium'|'gift', stars?: number, months?: number }} params
 */
export async function checkPaymeeFulfillment({ product, stars, months }) {
  if (!paymeeConfigured()) {
    return { ok: true, skipped: true };
  }

  try {
    const [balanceData, pricing] = await Promise.all([
      getPaymeeBalance(),
      getPaymeePricing(),
    ]);

    const balanceUsdt = Number(balanceData?.balance_usdt) || 0;
    let requiredUsdt = 0;

    if (product === "stars" || product === "gift") {
      const starsNum = Number(stars);
      const rate = Number(pricing?.stars?.usdt_per_star);
      if (!Number.isFinite(starsNum) || starsNum <= 0) {
        return { ok: false, code: "INVALID_STARS", error: "Stars miqdori noto'g'ri" };
      }
      if (!Number.isFinite(rate) || rate <= 0) {
        return {
          ok: false,
          code: "PAYMEE_PRICING_UNAVAILABLE",
          error: "Paymee tariflari vaqtincha mavjud emas",
        };
      }
      requiredUsdt = starsNum * rate;
    } else if (product === "premium") {
      const m = Number(months);
      const usdtMap = pricing?.premium?.usdt || {};
      requiredUsdt = Number(usdtMap[String(m)] ?? usdtMap[m]);
      if (![3, 6, 12].includes(m) || !Number.isFinite(requiredUsdt) || requiredUsdt <= 0) {
        return {
          ok: false,
          code: "PAYMEE_PRICING_UNAVAILABLE",
          error: "Premium tarifi topilmadi",
        };
      }
    } else {
      return { ok: false, code: "INVALID_PRODUCT", error: "Noto'g'ri product" };
    }

    if (balanceUsdt < requiredUsdt) {
      return {
        ok: false,
        code: "PAYMEE_INSUFFICIENT_BALANCE",
        message: getPaymeeOutOfStockMessage(product),
        product,
        balance_usdt: balanceUsdt,
        required_usdt: requiredUsdt,
      };
    }

    return {
      ok: true,
      balance_usdt: balanceUsdt,
      required_usdt: requiredUsdt,
    };
  } catch (err) {
    console.error("❌ checkPaymeeFulfillment:", err.message);
    return {
      ok: false,
      code: "PAYMEE_CHECK_FAILED",
      error: "Balans tekshiruvi vaqtincha ishlamadi. Birozdan keyin qayta urinib ko'ring.",
    };
  }
}

export function sendPaymeeInsufficientResponse(res, check) {
  return res.status(503).json({
    success: false,
    error: check.message || getPaymeeOutOfStockMessage(check.product || "stars"),
    code: check.code || "PAYMEE_INSUFFICIENT_BALANCE",
    product: check.product,
    balance_usdt: check.balance_usdt,
    required_usdt: check.required_usdt,
  });
}
