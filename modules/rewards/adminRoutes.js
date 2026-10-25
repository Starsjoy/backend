import { REWARD_ORDER_PREFIX } from "./config.js";

/**
 * Admin panel "Bonuslar" sahifasi — faqat o'qish.
 *   GET /api/admin/rewards/overview — umumiy statistika
 *   GET /api/admin/rewards/ledger   — har bir yozuv (filtr, qidiruv, sahifalash)
 */
const KINDS = ["purchase", "referral", "redeem", "refund", "admin"];

export function registerRewardsAdminRoutes(app, { pool, adminAuth }) {
  app.get("/api/admin/rewards/overview", adminAuth, async (_req, res) => {
    try {
      const [totals, periods, unseen, items, top] = await Promise.all([
        pool.query(`
          SELECT
            (SELECT COALESCE(SUM(bonus_balance), 0)::int FROM users) AS balance_total,
            (SELECT COUNT(*)::int FROM users WHERE bonus_balance > 0) AS users_with_balance,
            COALESCE(SUM(delta) FILTER (WHERE kind = 'purchase'), 0)::int AS earned_purchase,
            COALESCE(SUM(delta) FILTER (WHERE kind = 'referral'), 0)::int AS earned_referral,
            COALESCE(-SUM(delta) FILTER (WHERE kind = 'redeem'), 0)::int AS redeemed,
            COALESCE(SUM(delta) FILTER (WHERE kind = 'refund'), 0)::int AS refunded,
            COUNT(*) FILTER (WHERE kind = 'redeem')::int AS redeem_count,
            COUNT(DISTINCT user_id) FILTER (WHERE kind IN ('purchase', 'referral'))::int AS earners
          FROM bonus_ledger`),
        pool.query(`
          SELECT
            COALESCE(SUM(delta) FILTER (WHERE kind IN ('purchase','referral') AND created_at > NOW() - INTERVAL '1 day'), 0)::int AS earned_day,
            COALESCE(SUM(delta) FILTER (WHERE kind IN ('purchase','referral') AND created_at > NOW() - INTERVAL '7 days'), 0)::int AS earned_week,
            COALESCE(-SUM(delta) FILTER (WHERE kind = 'redeem' AND created_at > NOW() - INTERVAL '1 day'), 0)::int AS redeemed_day,
            COALESCE(-SUM(delta) FILTER (WHERE kind = 'redeem' AND created_at > NOW() - INTERVAL '7 days'), 0)::int AS redeemed_week
          FROM bonus_ledger`),
        pool.query(`
          SELECT COUNT(*)::int AS entries, COALESCE(SUM(delta), 0)::int AS stars, COUNT(DISTINCT user_id)::int AS users
          FROM bonus_ledger WHERE seen = false AND delta > 0`),
        pool.query(`
          SELECT l.meta->>'item' AS item, COUNT(*)::int AS count, COALESCE(-SUM(l.delta), 0)::int AS stars,
                 COUNT(*) FILTER (WHERE o.status IN ('completed', 'delivered'))::int AS delivered,
                 COUNT(*) FILTER (WHERE o.status IN ('pending', 'processing'))::int AS in_progress,
                 COUNT(*) FILTER (WHERE o.status = 'cancelled')::int AS refunded
          FROM bonus_ledger l LEFT JOIN orders o ON o.id = l.order_id
          WHERE l.kind = 'redeem' GROUP BY 1 ORDER BY 2 DESC`),
        pool.query(`
          SELECT u.user_id, u.username, u.bonus_balance,
                 COALESCE(SUM(l.delta) FILTER (WHERE l.kind IN ('purchase','referral')), 0)::int AS earned,
                 COUNT(l.id) FILTER (WHERE l.seen = false AND l.delta > 0)::int AS unseen
          FROM users u LEFT JOIN bonus_ledger l ON l.user_id = u.user_id
          WHERE u.bonus_balance > 0
          GROUP BY u.user_id, u.username, u.bonus_balance
          ORDER BY u.bonus_balance DESC LIMIT 10`),
      ]);
      res.json({
        success: true,
        totals: totals.rows[0],
        periods: periods.rows[0],
        unseen: unseen.rows[0],
        items: items.rows,
        top_users: top.rows,
      });
    } catch (err) {
      console.error("❌ /api/admin/rewards/overview:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.get("/api/admin/rewards/ledger", adminAuth, async (req, res) => {
    try {
      const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 30));
      const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
      const kind = KINDS.includes(req.query.kind) ? req.query.kind : null;
      const seen = req.query.seen === "seen" ? true : req.query.seen === "unseen" ? false : null;
      const search = String(req.query.search || "").trim().replace(/^@/, "");

      const where = [];
      const params = [];
      if (kind) { params.push(kind); where.push(`l.kind = $${params.length}`); }
      if (seen !== null) { params.push(seen); where.push(`l.seen = $${params.length} AND l.delta > 0`); }
      if (search) {
        params.push(`%${search}%`);
        where.push(`(u.username ILIKE $${params.length} OR l.user_id ILIKE $${params.length} OR o.recipient_username ILIKE $${params.length})`);
      }
      const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
      const from = `FROM bonus_ledger l
        LEFT JOIN users u ON u.user_id = l.user_id
        LEFT JOIN orders o ON o.id = l.order_id`;

      const [rows, total] = await Promise.all([
        pool.query(
          `SELECT l.id, l.delta, l.kind, l.seen, l.created_at, l.user_id, u.username,
                  l.meta->>'item' AS item, l.meta->>'friend_username' AS friend_username,
                  o.id AS order_id, o.order_type, o.type_amount, o.summ, o.recipient_username,
                  o.status AS order_status, (o.order_id LIKE '${REWARD_ORDER_PREFIX}%') AS is_reward_order
           ${from} ${whereSql}
           ORDER BY l.id DESC
           LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, limit, offset]
        ),
        pool.query(`SELECT COUNT(*)::int AS c ${from} ${whereSql}`, params),
      ]);
      res.json({ success: true, entries: rows.rows, total: total.rows[0].c, limit, offset });
    } catch (err) {
      console.error("❌ /api/admin/rewards/ledger:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });
}
