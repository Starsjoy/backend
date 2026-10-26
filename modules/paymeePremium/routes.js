import { createPaymeePremiumOrder } from "./orderCreate.js";
import { sendPremiumViaPaymee } from "./delivery.js";
import { getPaymeePremiumPrice } from "./price.js";
import { paymeePremiumSearch } from "./search.js";
import { logPaymentMatchDebug } from "../payments/matchDebug.js";
import {
  sendGuardFailure,
  validatePaymentCardLast4,
} from "../payments/clientAmountGuard.js";

const ORDER_TYPE = "premium_paymee";

export async function matchPaymeePremiumPayment(req, res, ctx) {
  const { pool } = ctx;

  try {
    const { amount, card_last4 } = req.body;
    if (amount == null || amount === "") {
      return res.status(400).json({ error: "amount kerak" });
    }
    const matchAmount = parseInt(amount, 10);
    if (!matchAmount || matchAmount <= 0) {
      return res.status(400).json({ error: "amount noto'g'ri" });
    }

    if (card_last4) {
      const cardCheck = validatePaymentCardLast4(card_last4);
      if (!cardCheck.ok) {
        return sendGuardFailure(res, cardCheck);
      }
    }

    const updated = await pool.query(
      `UPDATE orders
       SET payment_status = 'paid',
           status = CASE WHEN status = 'pending' THEN 'processing' ELSE status END
       WHERE id = (
         SELECT id FROM orders 
         WHERE summ = $1 
           AND payment_status = 'pending'
           AND status = 'pending'
           AND order_type = $2
           AND created_at >= NOW() - INTERVAL '15 minutes'
         ORDER BY id DESC 
         LIMIT 1
         FOR UPDATE SKIP LOCKED
       )
       RETURNING *`,
      [matchAmount, ORDER_TYPE]
    );

    if (!updated.rows.length) {
      console.log(`❌ Paymee premium match topilmadi: amount=${matchAmount}`);
      await logPaymentMatchDebug(pool, matchAmount, "paymee-premium");
      return res.status(404).json({ message: "Pending Paymee premium payment not found" });
    }

    const order = updated.rows[0];
    console.log(
      `🎉 Paymee Premium to'lov tasdiqlandi: #${order.id} | ${order.summ} so'm → Partner API`
    );

    sendPremiumViaPaymee(order, ctx).catch((err) => {
      console.error("❌ Paymee premium delivery async error:", err.message);
    });

    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      months: order.type_amount,
      amount: order.summ,
      status: "processing",
      payment_status: "paid",
      order_type: ORDER_TYPE,
    });
  } catch (err) {
    console.error("❌ /api/paymee-premium/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
}

export function registerPaymeePremiumRoutes(app, ctx) {
  const { orderLimiter, searchLimiter, telegramAuth, internalSecretAuth } = ctx;

  app.get("/api/paymee-premium/price/:months", (req, res) =>
    getPaymeePremiumPrice(req, res, ctx)
  );

  app.post("/api/paymee-premium/search", searchLimiter, telegramAuth, (req, res) =>
    paymeePremiumSearch(req, res)
  );

  app.post("/api/paymee-premium/order", orderLimiter, telegramAuth, (req, res) =>
    createPaymeePremiumOrder(req, res, ctx)
  );

  app.post("/api/paymee-premium/match", internalSecretAuth, (req, res) =>
    matchPaymeePremiumPayment(req, res, ctx)
  );

  app.get("/api/paymee-premium/transactions/:id", telegramAuth, async (req, res) => {
    try {
      const id = Number(req.params.id);
      const result = await ctx.pool.query(
        "SELECT * FROM orders WHERE id=$1 AND order_type=$2",
        [id, ORDER_TYPE]
      );
      if (!result.rows.length) {
        return res.status(404).json({ error: "Order topilmadi" });
      }
      const order = result.rows[0];
      const legacyStatus =
        order.status === "completed" || order.status === "delivered"
          ? "premium_sent"
          : order.status;

      return res.json({
        id: order.id,
        username: order.recipient_username,
        recipient: order.recipient,
        muddat_oy: order.type_amount,
        amount: order.summ,
        status: legacyStatus,
        // Yetkazish kechikdi (kechikish xabari yuborilgan) — ekran "admin yuboradi" holatiga o'tsin
        delayed: Boolean(order.delay_notified),
        payment_status: order.payment_status,
        transaction_id: order.transaction_id,
        created_at: order.created_at,
      });
    } catch (err) {
      console.error("❌ /api/paymee-premium/transactions error:", err);
      res.status(500).json({ error: "Server error" });
    }
  });

  console.log(
    "✅ Paymee Premium moduli: /api/paymee-premium/price, /api/paymee-premium/order, /api/paymee-premium/match"
  );
}
