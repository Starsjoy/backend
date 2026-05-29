import crypto from "crypto";
import {
  PROMO_USER_USAGE_SQL,
  releasePromocodeUsage,
} from "../promocodes/helpers.js";

const ORDER_TYPE = "premium_paymee";
const VALID_MONTHS = [3, 6, 12];

export function paymeePremiumSlotKey(months) {
  return `paymee_premium_${months}`;
}

function slotIndexFromPremiumSumm(months, summ, baseAmount) {
  const diff = baseAmount - summ;
  if (diff >= 0 && diff % 100 === 0 && diff / 100 < 10) return diff / 100;
  if (diff >= 50 && (diff - 50) % 100 === 0 && (diff - 50) / 100 < 10) {
    return 10 + (diff - 50) / 100;
  }
  return -1;
}

/**
 * POST /api/paymee-premium/order — karta to'lov + StarsPaymee Partner API.
 */
export async function createPaymeePremiumOrder(req, res, ctx) {
  const {
    pool,
    PREMIUM_3,
    PREMIUM_6,
    PREMIUM_12,
    PRICE_SLOT_CONFIG,
    priceSlots,
    calculatePremiumSlotPrice,
    generateUniqueOrderSum,
    addPriceToCache,
    releasePriceSlotByOrderId,
    releaseDiscountPriceSlotByOrderId,
    removePriceFromCacheByOrderId,
    INTERNAL_API_BASE,
    bot,
  } = ctx;

  const priceMap = { 3: PREMIUM_3, 6: PREMIUM_6, 12: PREMIUM_12 };

  try {
    const { username, months, applied_promocode } = req.body;

    const maxPendingOrders = 3;
    const tgUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    if (tgUserId) {
      const activeOrdersRes = await pool.query(
        `SELECT COUNT(*) as count FROM orders WHERE owner_user_id = $1 AND status = 'pending' AND payment_status = 'pending'`,
        [tgUserId]
      );
      if (parseInt(activeOrdersRes.rows[0].count, 10) >= maxPendingOrders) {
        return res.status(429).json({
          error: "Sizda to'lanmagan buyurtmalar mavjud. Iltimos oldin ularni to'lang yoki biroz kuting.",
        });
      }
    }

    if (!username || !months) {
      return res.status(400).json({ error: "username va months kerak" });
    }

    const monthsNum = parseInt(months, 10);
    if (!VALID_MONTHS.includes(monthsNum)) {
      return res.status(400).json({ error: "months: 3, 6 yoki 12 bo'lishi kerak" });
    }

    const baseAmount = priceMap[monthsNum];
    if (!baseAmount) {
      return res.status(400).json({ error: "Noto'g'ri months" });
    }

    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;
    const ownerUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    const slotKey = paymeePremiumSlotKey(monthsNum);

    if (!priceSlots[slotKey]) {
      priceSlots[slotKey] = {};
    }

    const pendingOrders = await pool.query(
      `SELECT id, summ, created_at FROM orders 
       WHERE order_type = $1 AND type_amount = $2 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= NOW() - INTERVAL '8 minutes'`,
      [ORDER_TYPE, monthsNum]
    );

    for (const order of pendingOrders.rows) {
      const slotIdx = slotIndexFromPremiumSumm(monthsNum, order.summ, baseAmount);
      if (slotIdx >= 0 && slotIdx < 20 && !priceSlots[slotKey][slotIdx]) {
        priceSlots[slotKey][slotIdx] = {
          orderId: order.id,
          createdAt: new Date(order.created_at).getTime(),
        };
      }
    }

    const conflictPrices = await pool.query(
      `SELECT DISTINCT summ FROM orders 
       WHERE order_type IN ('gift', 'premium', 'premium_usdt', 'premium_paymee', 'stars', 'stars_usdt', 'stars_paymee') 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= NOW() - INTERVAL '8 minutes'`
    );
    const conflictSet = new Set(conflictPrices.rows.map((r) => r.summ));

    let priceSlotIndex = -1;
    let amount;

    for (let i = 0; i < PRICE_SLOT_CONFIG.MAX_SLOTS; i++) {
      if (priceSlots[slotKey][i]) {
        const elapsed = Date.now() - priceSlots[slotKey][i].createdAt;
        if (elapsed <= PRICE_SLOT_CONFIG.SLOT_TIMEOUT) continue;
        delete priceSlots[slotKey][i];
      }

      const candidatePrice = calculatePremiumSlotPrice(monthsNum, i);
      if (conflictSet.has(candidatePrice)) continue;

      priceSlotIndex = i;
      amount = candidatePrice;
      break;
    }

    if (priceSlotIndex === -1) {
      return res.status(503).json({
        error: "Hozirda juda ko'p buyurtmalar mavjud. Iltimos, 1-2 daqiqadan keyin qayta urinib ko'ring.",
        code: "SLOTS_FULL",
      });
    }

    const tempReservationId = `temp_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    priceSlots[slotKey][priceSlotIndex] = {
      orderId: tempReservationId,
      createdAt: Date.now(),
    };

    const client = await pool.connect();
    let order;

    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock(1003)");

      let finalAmount = amount;
      let finalDiscountAmount = 0;
      let promoCodeValid = null;

      if (applied_promocode) {
        const promoRes = await client.query(
          `SELECT * FROM promocodes WHERE code = $1 FOR UPDATE`,
          [applied_promocode]
        );
        if (promoRes.rows.length > 0) {
          const promo = promoRes.rows[0];
          if (promo.is_active && promo.used_count < promo.usage_limit) {
            if (promo.target_type === "all" || promo.target_type === "premium") {
              if (promo.target_amount === null || promo.target_amount === monthsNum) {
                const userUsage = await client.query(PROMO_USER_USAGE_SQL, [
                  ownerUserId,
                  applied_promocode,
                ]);
                if (userUsage.rows.length === 0) {
                  finalDiscountAmount = Math.floor(finalAmount * (promo.discount_percent / 100));
                  finalAmount = finalAmount - finalDiscountAmount;
                  promoCodeValid = promo.code;
                  await client.query(
                    `UPDATE promocodes SET used_count = used_count + 1 WHERE id = $1`,
                    [promo.id]
                  );
                }
              }
            }
          }
        }
      }

      const uniqueSum = await generateUniqueOrderSum(finalAmount, client);
      const orderId = crypto.randomUUID();

      const result = await client.query(
        `INSERT INTO orders (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount, summ, payment_method, payment_status, status, applied_promocode, discount_amount, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'card', 'pending', 'pending', $8, $9, NOW())
         RETURNING *`,
        [
          orderId,
          ownerUserId,
          cleanUsername,
          cleanUsername,
          ORDER_TYPE,
          monthsNum,
          uniqueSum,
          promoCodeValid,
          finalDiscountAmount,
        ]
      );

      await client.query("COMMIT");
      order = result.rows[0];

      if (priceSlots[slotKey][priceSlotIndex]) {
        priceSlots[slotKey][priceSlotIndex].orderId = order.id;
      }

      addPriceToCache(order.summ, order.id, ORDER_TYPE);
    } catch (err) {
      await client.query("ROLLBACK");
      if (priceSlots[slotKey][priceSlotIndex]?.orderId === tempReservationId) {
        delete priceSlots[slotKey][priceSlotIndex];
      }
      throw err;
    } finally {
      client.release();
    }

    console.log(
      `🧾 Paymee Premium Order: #${order.id} | @${cleanUsername} | ${order.summ} so'm | ${monthsNum} oy`
    );

    fetch(`${INTERNAL_API_BASE}/api/balance/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ order_id: order.id, type: ORDER_TYPE }),
    }).catch(() => {});

    setTimeout(async () => {
      try {
        const check = await pool.query(
          "SELECT status, order_type, owner_user_id, expired_notified, applied_promocode FROM orders WHERE id = $1",
          [order.id]
        );
        if (check.rows[0]?.status === "pending") {
          await pool.query(
            "UPDATE orders SET status='expired', payment_status='expired' WHERE id=$1",
            [order.id]
          );
          if (check.rows[0]?.applied_promocode) {
            await releasePromocodeUsage(pool, check.rows[0].applied_promocode);
          }
          releasePriceSlotByOrderId(order.id, slotKey);
          releaseDiscountPriceSlotByOrderId(order.id);
          removePriceFromCacheByOrderId(order.id);

          const owner = check.rows[0]?.owner_user_id;
          if (owner && bot && !check.rows[0]?.expired_notified) {
            try {
              await bot.telegram.sendMessage(
                owner,
                `⚠️ Siz premium (Paymee) sotib olishga harakat qildingiz, ammo to'lov amalga oshirilmadi.\n\n👉 @StarsPaymeeSupport`
              );
              await pool.query(`UPDATE orders SET expired_notified = true WHERE id = $1`, [
                order.id,
              ]);
            } catch {
              /* ignore */
            }
          }
        }
      } catch {
        /* ignore */
      }
    }, 5 * 60 * 1000);

    res.json({
      id: order.id,
      username: cleanUsername,
      recipient: cleanUsername,
      months: order.type_amount,
      amount: order.summ,
      status: order.status,
      created_at: order.created_at,
      delivery: "paymee",
    });
  } catch (err) {
    console.error("❌ /api/paymee-premium/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
}
