import { usdtSlotKey } from "./orderCreate.js";

/**
 * GET /api/usdt-stars/price/:stars — Fragment buyurtma uchun alohida slot pool (usdt_N).
 */
export async function getUsdtStarsPrice(req, res, ctx) {
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

  const slotKey = usdtSlotKey(stars);
  if (!priceSlots[slotKey]) {
    priceSlots[slotKey] = {};
  }

  let conflictPrices = new Set();
  try {
    const rows = await pool.query(
      `SELECT DISTINCT summ FROM orders 
       WHERE order_type IN ('gift', 'premium', 'stars', 'stars_usdt') 
       AND payment_status IS DISTINCT FROM 'paid'
       AND created_at >= NOW() - INTERVAL '20 minutes'`
    );
    conflictPrices = new Set(rows.rows.map((r) => r.summ));
  } catch (err) {
    console.error("⚠️ USDT stars conflict prices:", err.message);
  }

  let slotIndex = -1;
  // 0-slot (yaxlit asosiy narx) berilmaydi: mijoz ko'rsatilgan summa o'rniga yaxlit narx tashlasa, pul o'sha narxdagi boshqa mijoz orderiga yozilib ketardi
  for (let i = 1; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
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
    fragment_payment_method: ctx.getFragmentPaymentMethod?.() || "ton",
  });
}
