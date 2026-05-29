import { createUsdtStarsOrder } from "./orderCreate.js";
import { sendStarsViaFragment } from "./delivery.js";
import { getUsdtStarsPrice } from "./price.js";
import { verifyFragmentCookies, fragmentEnvReadyAsync } from "./fragmentDelivery.js";
import {
  runFragmentCookieTest,
  getFragmentCookieStatus,
} from "./fragmentCookieTest.js";
import {
  getFragmentTokens,
  setFragmentTokens,
  maskFragmentTokens,
  FRAGMENT_TOKEN_KEYS,
} from "../tokens/tokensDb.js";

const ORDER_TYPE = "stars_usdt";

/**
 * SMS to'lov tasdiqlash — faqat stars_usdt buyurtmalari.
 */
export async function matchUsdtStarsPayment(req, res, ctx) {
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
        `❌ USDT stars match topilmadi: amount=${matchAmount} card=${card_last4}`
      );
      return res.status(404).json({ message: "Pending USDT stars payment not found" });
    }

    const order = updated.rows[0];
    console.log(
      `🎉 USDT Stars to'lov tasdiqlandi: #${order.id} | ${order.summ} so'm → Fragment`
    );

    const payMethod =
      typeof ctx.getFragmentPaymentMethod === "function"
        ? ctx.getFragmentPaymentMethod()
        : "ton";
    console.log(`📤 Fragment stars yuborish: payment_method=${payMethod}`);

    sendStarsViaFragment(order, ctx).catch((err) => {
      console.error("❌ Fragment delivery async error:", err.message);
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
    console.error("❌ /api/usdt-stars/match error:", err);
    res.status(500).json({ error: "Server error" });
  }
}

export function registerUsdtStarsRoutes(app, ctx) {
  const { orderLimiter, telegramAuth, internalSecretAuth, adminAuth } = ctx;

  app.get("/api/admin/tokens/fragment", adminAuth, async (req, res) => {
    try {
      const tokens = await getFragmentTokens(ctx.pool);
      const masked = req.query.masked === "1" || req.query.masked === "true";
      res.json({
        tokens: masked ? maskFragmentTokens(tokens) : tokens,
        keys: FRAGMENT_TOKEN_KEYS,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.put("/api/admin/tokens/fragment", adminAuth, async (req, res) => {
    try {
      const body = req.body || {};
      await setFragmentTokens(ctx.pool, {
        fragment_dt: body.fragment_dt,
        fragment_ssid: body.fragment_ssid,
        fragment_token: body.fragment_token,
        fragment_ton_token: body.fragment_ton_token,
      });
      const tokens = await getFragmentTokens(ctx.pool);
      res.json({ success: true, tokens });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/admin/fragment/verify", adminAuth, async (req, res) => {
    if (!(await fragmentEnvReadyAsync(ctx.pool))) {
      return res.status(503).json({
        ok: false,
        error: "SEED/API_KEY .env da yoki tokens jadvalida fragment_ssid/token to'ldiring",
      });
    }
    const result = await verifyFragmentCookies(ctx.pool);
    res.status(result.ok ? 200 : 503).json(result);
  });

  app.get("/api/admin/fragment/env-status", adminAuth, async (req, res) => {
    try {
      res.json(await getFragmentCookieStatus(ctx.pool));
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/admin/fragment/cookie-test", adminAuth, async (req, res) => {
    try {
      const raw = String(req.query.source || "env").toLowerCase();
      const source = raw === "db" || raw === "auto" ? raw : "env";
      const result = await runFragmentCookieTest(ctx.pool, { source });
      res.status(result.ok ? 200 : 503).json(result);
    } catch (err) {
      res.status(500).json({ ok: false, error: err.message });
    }
  });

  app.get("/api/usdt-stars/price/:stars", (req, res) => getUsdtStarsPrice(req, res, ctx));

  app.post("/api/usdt-stars/order", orderLimiter, telegramAuth, (req, res) =>
    createUsdtStarsOrder(req, res, ctx)
  );

  app.post("/api/usdt-stars/match", internalSecretAuth, (req, res) =>
    matchUsdtStarsPayment(req, res, ctx)
  );

  console.log(
    "✅ USDT Stars moduli: /api/usdt-stars/price, /api/usdt-stars/order, /api/usdt-stars/match"
  );
}
