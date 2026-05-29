import {
  robynhoodConfigured,
  getRobynPurchaseHistory,
  getRobynTransaction,
  getPurchaseByIdempotencyKey,
  getRobynBalance,
  getRobynStarsPrice,
  syncRobynOrderFromProvider,
  verifyRobynhoodApiReachable,
} from "./client.js";

export function registerRobynhoodAdminRoutes(app, ctx) {
  const { adminAuth, pool } = ctx;

  app.get("/api/admin/robynhood/status", adminAuth, async (_req, res) => {
    try {
      if (!robynhoodConfigured()) {
        return res.json({
          configured: false,
          error: "ROB_API_KEY .env da yo'q",
        });
      }
      const check = await verifyRobynhoodApiReachable();
      const [balance, price] = await Promise.all([
        getRobynBalance().catch((e) => ({ error: e.message })),
        getRobynStarsPrice(50).catch((e) => ({ error: e.message })),
      ]);
      res.json({
        configured: true,
        reachable: check.ok,
        api_url: process.env.ROBYNHOOD_API_URL || "https://robynhood.parssms.info",
        balance,
        stars_price_50: price,
        check,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get("/api/admin/robynhood/history", adminAuth, async (req, res) => {
    try {
      if (!robynhoodConfigured()) {
        return res.status(503).json({ error: "ROB_API_KEY yo'q" });
      }
      const limit = req.query.limit ?? 50;
      const offset = req.query.offset ?? 0;
      const data = await getRobynPurchaseHistory(limit, offset);
      res.json({ success: true, ...data });
    } catch (err) {
      res.status(err.status || 500).json({
        error: err.message,
        body: err.body,
      });
    }
  });

  app.get("/api/admin/robynhood/transaction/:txId", adminAuth, async (req, res) => {
    try {
      if (!robynhoodConfigured()) {
        return res.status(503).json({ error: "ROB_API_KEY yo'q" });
      }
      const txId = req.params.txId;
      if (!txId) return res.status(400).json({ error: "transaction id kerak" });
      const data = await getRobynTransaction(txId);
      res.json({ success: true, transaction: data });
    } catch (err) {
      res.status(err.status || 500).json({
        error: err.message,
        body: err.body,
      });
    }
  });

  app.get("/api/admin/robynhood/idempotency/:key", adminAuth, async (req, res) => {
    try {
      if (!robynhoodConfigured()) {
        return res.status(503).json({ error: "ROB_API_KEY yo'q" });
      }
      const key = decodeURIComponent(req.params.key || "");
      if (!key) return res.status(400).json({ error: "kalit kerak" });
      const data = await getPurchaseByIdempotencyKey(key);
      if (!data) {
        return res.status(404).json({ error: "Topilmadi", idempotency_key: key });
      }
      res.json({ success: true, purchase: data });
    } catch (err) {
      res.status(err.status || 500).json({
        error: err.message,
        body: err.body,
      });
    }
  });

  /** DB buyurtmani RobynHood bilan solishtirish; completed bo'lsa order yangilash */
  app.post("/api/admin/robynhood/sync-order/:orderId", adminAuth, async (req, res) => {
    try {
      if (!robynhoodConfigured()) {
        return res.status(503).json({ error: "ROB_API_KEY yo'q" });
      }
      const orderId = Number(req.params.orderId);
      if (!orderId) return res.status(400).json({ error: "orderId noto'g'ri" });

      const q = await pool.query("SELECT * FROM orders WHERE id=$1", [orderId]);
      if (!q.rows.length) {
        return res.status(404).json({ error: "Order topilmadi" });
      }
      const order = q.rows[0];
      const sync = await syncRobynOrderFromProvider(order);

      if (!sync.found) {
        return res.json({
          success: true,
          synced: false,
          message: "RobynHoodda bu kalit bilan xarid yo'q",
          idempotency_key: sync.idempotency_key,
        });
      }

      if (sync.completed && sync.remote?.transaction_id) {
        const newStatus =
          order.status === "delivered" ? "delivered" : "completed";
        await pool.query(
          `UPDATE orders SET status=$1, transaction_id=$2 WHERE id=$3`,
          [newStatus, sync.remote.transaction_id, orderId]
        );
        return res.json({
          success: true,
          synced: true,
          updated: true,
          idempotency_key: sync.idempotency_key,
          transaction_id: sync.remote.transaction_id,
          remote: sync.remote,
        });
      }

      res.json({
        success: true,
        synced: true,
        updated: false,
        idempotency_key: sync.idempotency_key,
        remote: sync.remote,
      });
    } catch (err) {
      res.status(err.status || 500).json({
        error: err.message,
        body: err.body,
      });
    }
  });

  console.log(
    "✅ RobynHood admin: /api/admin/robynhood/status, history, transaction, idempotency, sync-order"
  );
}
