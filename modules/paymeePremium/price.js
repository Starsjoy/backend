import { paymeePremiumSlotKey } from "./orderCreate.js";
import { checkPaymeeFulfillment } from "../paymeeClient/availability.js";

/**
 * GET /api/paymee-premium/price/:months — Paymee premium slot (paymee_premium_N).
 */
export async function getPaymeePremiumPrice(req, res, ctx) {
  const {
    pool,
    PREMIUM_3,
    PREMIUM_6,
    PREMIUM_12,
    PRICE_SLOT_CONFIG,
    priceSlots,
    calculatePremiumSlotPrice,
  } = ctx;

  const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };
  const months = parseInt(req.params.months, 10);

  if (![3, 6, 12].includes(months)) {
    return res.status(400).json({ error: "months: 3, 6 yoki 12 bo'lishi kerak" });
  }

  const paymeeCheck = await checkPaymeeFulfillment({ product: "premium", months });
  if (!paymeeCheck.ok && paymeeCheck.code === "PAYMEE_INSUFFICIENT_BALANCE") {
    return res.json({
      available: false,
      code: paymeeCheck.code,
      message: paymeeCheck.message,
    });
  }

  const baseAmount = priceMap[months];
  const slotKey = paymeePremiumSlotKey(months);

  if (!priceSlots[slotKey]) {
    priceSlots[slotKey] = {};
  }

  let conflictPrices = new Set();
  try {
    const rows = await pool.query(
      `SELECT DISTINCT summ FROM orders 
       WHERE order_type IN ('gift', 'premium', 'premium_usdt', 'premium_paymee', 'stars', 'stars_usdt', 'stars_paymee') 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= NOW() - INTERVAL '8 minutes'`
    );
    conflictPrices = new Set(rows.rows.map((r) => r.summ));
  } catch (err) {
    console.error("⚠️ Paymee premium conflict prices:", err.message);
  }

  let slotIndex = -1;
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (priceSlots[slotKey][i]) {
      const elapsed = Date.now() - priceSlots[slotKey][i].createdAt;
      if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) continue;
      delete priceSlots[slotKey][i];
    }

    const candidatePrice = calculatePremiumSlotPrice(months, i);
    if (conflictPrices.has(candidatePrice)) continue;

    slotIndex = i;
    break;
  }

  if (slotIndex === -1) {
    return res.json({
      available: false,
      message: "Hozirda juda ko'p buyurtmalar mavjud",
    });
  }

  const price = calculatePremiumSlotPrice(months, slotIndex);
  const minPrice = price - 950;
  const usedSlots = Object.keys(priceSlots[slotKey]).length;

  res.json({
    available: true,
    months,
    basePrice: baseAmount,
    price,
    currentPrice: price,
    minPrice,
    slotIndex,
    availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - usedSlots,
    pool: slotKey,
    delivery: "paymee",
  });
}
