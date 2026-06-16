import { createPaymeeStarsOrder } from "./orderCreate.js";
import { sendStarsViaPaymee } from "./delivery.js";
import { getPaymeeStarsPrice } from "./price.js";
import { paymeeStarsSearch } from "./search.js";
import { logPaymentMatchDebug } from "../payments/matchDebug.js";
import {
  sendGuardFailure,
  validatePaymentCardLast4,
} from "../payments/clientAmountGuard.js";
import {
  checkPaymeeHealth,
  getPaymeeBalance,
  getPaymeePricing,
  paymeeConfigured,
} from "../paymeeClient/index.js";

const ORDER_TYPE = "stars_paymee";

export async function matchPaymeeStarsPayment(req, res, ctx) {
  const { pool } = ctx;

  try {
    const { card_last4, amount } = req.body;
    if (!card_last4 || amount == null || amount === "") {
      return res.status(400).json({ error: "card_last4 va amount kerak" });
    }
    const matchAmount = parseInt(amount, 10);
    if (!matchAmount || matchAmount <= 0) {
      return res.status(400).json({ error: "amount noto'g'ri" });
    }

    const cardCheck = validatePaymentCardLast4(card_last4);
    if (!cardCheck.ok) {
      return sendGuardFailure(res, cardCheck);
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
      console.log(
        `❌ Paymee stars match topilmadi: amount=${matchAmount} card=${card_last4}`
      );
      await logPaymentMatchDebug(pool, matchAmount, "paymee-stars");
      return res.status(404).json({ message: "Pending Paymee stars payment not found" });
    }

    const order = updated.rows[0];
    console.log(
      `🎉 Paymee Stars to'lov tasdiqlandi: #${order.id} | ${order.summ} so'm → Partner API`
    );

    sendStarsViaPaymee(order, ctx).catch((err) => {
      console.error("❌ Paymee stars delivery async error:", err.message);
    });

    res.json({
      id: order.id,
      username: order.recipient_username,
      recipient: order.recipient,
      stars: order.type_amount,
      amount: order.summ,
      status: "processing",
      payment_status: "paid",
      order_type: ORDER_TYPE,
    });
  } catch (err) {
    console.error("❌ /api/paymee-stars/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
}

export function registerPaymeeStarsRoutes(app, ctx) {
  const { orderLimiter, searchLimiter, telegramAuth, internalSecretAuth, adminAuth } = ctx;

  app.get("/api/admin/paymee/status", adminAuth, async (_req, res) => {
    try {
      if (!paymeeConfigured()) {
        return res.json({
          configured: false,
          error: "STARS_PAYMEE_API_URL yoki STARS_PAYMEE_API_KEY yo'q",
        });
      }
      const apiUrl = process.env.STARS_PAYMEE_API_URL;
      const [health, balance, pricing] = await Promise.all([
        checkPaymeeHealth().catch((e) => ({ success: false, error: e.message })),
        getPaymeeBalance().catch((e) => ({ success: false, error: e.message })),
        getPaymeePricing().catch((e) => ({ success: false, error: e.message })),
      ]);
      res.json({
        configured: true,
        api_url: apiUrl,
        docs: "https://api.starstg.uz/api/purchase/v1/docs",
        health,
        balance,
        pricing,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/paymee-stars/price/:stars", (req, res) => getPaymeeStarsPrice(req, res, ctx));

  app.post("/api/paymee-stars/search", searchLimiter, telegramAuth, (req, res) =>
    paymeeStarsSearch(req, res)
  );

  app.post("/api/paymee-stars/order", orderLimiter, telegramAuth, (req, res) =>
    createPaymeeStarsOrder(req, res, ctx)
  );

  app.post("/api/paymee-stars/match", internalSecretAuth, (req, res) =>
    matchPaymeeStarsPayment(req, res, ctx)
  );

  console.log(
    "✅ Paymee Stars moduli: /api/paymee-stars/price, /api/paymee-stars/search, /api/paymee-stars/order, /api/paymee-stars/match"
  );
}
