import { paymeeSlotKey } from "./orderCreate.js";

/**
 * GET /api/paymee-stars/price/:stars — Paymee buyurtma uchun alohida slot pool (paymee_N).
 */
export async function getPaymeeStarsPrice(req, res, ctx) {
  const {
    pool,
    STARS_PRICE_PER_UNIT,
    PRICE_SLOT_CONFIG,
    priceSlots,
    calculateSlotPrice,
  } = ctx;

  const stars = parseInt(req.params.stars, 10);
  if (!stars || Number.isNaN(stars) || stars < 50 || stars > 10000) {
    return res.status(400).json({ error: "Stars 50 dan 10000 gacha bo'lishi kerak" });
  }

  const slotKey = paymeeSlotKey(stars);
  if (!priceSlots[slotKey]) {
    priceSlots[slotKey] = {};
  }

  let conflictPrices = new Set();
  try {
    const rows = await pool.query(
      `SELECT DISTINCT summ FROM orders 
       WHERE order_type IN ('gift', 'premium', 'stars', 'stars_usdt', 'stars_paymee') 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= NOW() - INTERVAL '8 minutes'`
    );
    conflictPrices = new Set(rows.rows.map((r) => r.summ));
  } catch (err) {
    console.error("⚠️ Paymee stars conflict prices:", err.message);
  }

  let slotIndex = -1;
  for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
    if (priceSlots[slotKey][i]) {
      const elapsed = Date.now() - priceSlots[slotKey][i].createdAt;
      if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) continue;
      delete priceSlots[slotKey][i];
    }

    const candidatePrice = calculateSlotPrice(stars, i);
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

  const maxPrice = stars * STARS_PRICE_PER_UNIT;
  const price = calculateSlotPrice(stars, slotIndex);
  const minPrice = maxPrice - 950;
  const usedSlots = Object.keys(priceSlots[slotKey]).length;

  res.json({
    available: true,
    stars,
    maxPrice,
    minPrice,
    price,
    currentPrice: price,
    slotIndex,
    availableSlots: PRICE_SLOT_CONFIG.MAX_SLOTS - usedSlots,
    pool: slotKey,
    delivery: "paymee",
  });
}
