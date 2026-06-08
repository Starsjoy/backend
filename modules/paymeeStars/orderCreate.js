import crypto from "crypto";
import {
  PROMO_USER_USAGE_SQL,
  releasePromocodeUsage,
} from "../promocodes/helpers.js";
import { checkPaymeeFulfillment } from "../paymeeClient/availability.js";
import {
  rejectForbiddenClientPriceFields,
  sendGuardFailure,
  validateClientFinalAmount,
  validateClientSlotPrice,
} from "../payments/clientAmountGuard.js";
import { getExpiredOrderNotifyText } from "../notifications/orderExpiredMessages.js";

const ORDER_TYPE = "stars_paymee";

export function paymeeSlotKey(starsNum) {
  return `paymee_${starsNum}`;
}

/**
 * POST /api/paymee-stars/order — karta to'lov + StarsPaymee Partner API yetkazish.
 */
export async function createPaymeeStarsOrder(req, res, ctx) {
  const {
    pool,
    STARS_PRICE_PER_UNIT,
    PRICE_SLOT_CONFIG,
    priceSlots,
    calculateSlotPrice,
    generateUniqueOrderSum,
    addPriceToCache,
    releasePriceSlotByOrderId,
    releaseDiscountPriceSlotByOrderId,
    removePriceFromCacheByOrderId,
    INTERNAL_API_BASE,
    bot,
  } = ctx;

  try {
    const forbidden = rejectForbiddenClientPriceFields(req.body);
    if (!forbidden.ok) {
      return sendGuardFailure(res, forbidden);
    }

    const { username, stars, applied_promocode } = req.body;

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

    if (!username || !stars) {
      return res.status(400).json({ error: "username va stars kerak" });
    }

    const starsNum = parseInt(stars, 10);
    if (!Number.isInteger(starsNum) || starsNum < 50 || starsNum > 10000) {
      return res.status(400).json({ error: "Stars miqdori 50 dan 10000 gacha bo'lishi kerak" });
    }

    const paymeeCheck = await checkPaymeeFulfillment({ product: "stars", stars: starsNum });
    if (
      !paymeeCheck.ok &&
      paymeeCheck.code !== "PAYMEE_INSUFFICIENT_BALANCE"
    ) {
      return res.status(503).json({
        error: paymeeCheck.error || "Paymee tekshiruvi muvaffaqiyatsiz",
        code: paymeeCheck.code,
      });
    }

    const cleanUsername = username.startsWith("@") ? username.slice(1) : username;
    const ownerUserId = req.telegramUser?.id ? String(req.telegramUser.id) : null;
    const slotKey = paymeeSlotKey(starsNum);

    if (!priceSlots[slotKey]) {
      priceSlots[slotKey] = {};
    }

    const pendingOrders = await pool.query(
      `SELECT id, summ, created_at FROM orders 
       WHERE order_type = $1 AND type_amount = $2 
       AND status = 'pending' AND payment_status = 'pending'
       AND created_at >= NOW() - INTERVAL '8 minutes'`,
      [ORDER_TYPE, starsNum]
    );

    for (const order of pendingOrders.rows) {
      const maxPrice = starsNum * STARS_PRICE_PER_UNIT;
      const diff = maxPrice - order.summ;
      let slotIdx = -1;
      if (diff >= 0 && diff <= 950 && diff % 50 === 0) {
        slotIdx = diff / 50;
      }
      if (slotIdx >= 0 && slotIdx < 20 && !priceSlots[slotKey][slotIdx]) {
        priceSlots[slotKey][slotIdx] = {
          orderId: order.id,
          createdAt: new Date(order.created_at).getTime(),
        };
      }
    }

    const conflictPrices = await pool.query(
      `SELECT DISTINCT summ FROM orders 
       WHERE order_type IN ('gift', 'premium', 'stars', 'stars_usdt', 'stars_paymee') 
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

      const candidatePrice = calculateSlotPrice(starsNum, i);
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

    const slotCheck = validateClientSlotPrice(req.body, amount);
    if (!slotCheck.ok) {
      return sendGuardFailure(res, slotCheck);
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
      await client.query("SELECT pg_advisory_xact_lock(1002)");

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
            if (promo.target_type === "all" || promo.target_type === "stars") {
              if (promo.target_amount === null || promo.target_amount === starsNum) {
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

      const finalCheck = validateClientFinalAmount(req.body, finalAmount);
      if (!finalCheck.ok) {
        await client.query("ROLLBACK");
        return sendGuardFailure(res, finalCheck);
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
          starsNum,
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
      `🧾 Paymee Stars Order: #${order.id} | @${cleanUsername} | ${order.summ} so'm | ${starsNum}⭐`
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
                getExpiredOrderNotifyText("stars_paymee")
              );
              await pool.query(`UPDATE orders SET expired_notified = true WHERE id = $1`, [order.id]);
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
      stars: order.type_amount,
      amount: order.summ,
      status: order.status,
      created_at: order.created_at,
      delivery: "paymee",
    });
  } catch (err) {
    console.error("❌ /api/paymee-stars/order error:", err);
    res.status(500).json({ error: "Server error" });
  }
}
