import crypto from "crypto";
import { REWARD_ORDER_PREFIX } from "./config.js";
import { applyLedgerEntry, deductBalance } from "./db.js";
import { MINI_APP_URL, getUserAppLanguage } from "../notifications/orderExpiredMessages.js";
import { escapeTelegramHtml } from "../usdtStars/fragmentNotify.js";

/** Bitta admin bonusining yuqori chegarasi (tasodifiy ortiqcha raqamdan himoya) */
const ADMIN_GRANT_MAX = 1000;

const GRANT_TEXTS = {
  uz: { title: (n) => `🎁 Admin tomonidan sizga +${n} ⭐ bonus berildi!`, reason: "Sabab", body: "Bonuslarni ilovadagi «Bonuslar» bo'limida ko'rasiz va sovg'alarga almashtirasiz.", button: "🎁 Bonuslar" },
  ru: { title: (n) => `🎁 Админ начислил вам +${n} ⭐ бонуса!`, reason: "Причина", body: "Смотрите их в разделе «Бонусы» в приложении и обменивайте на подарки.", button: "🎁 Бонусы" },
  en: { title: (n) => `🎁 The admin has given you +${n} ⭐ bonus!`, reason: "Reason", body: "Find it in the «Rewards» section of the app and exchange it for gifts.", button: "🎁 Rewards" },
};

/**
 * Admin panel "Bonuslar" sahifasi — faqat o'qish.
 *   GET /api/admin/rewards/overview — umumiy statistika
 *   GET /api/admin/rewards/ledger   — har bir yozuv (filtr, qidiruv, sahifalash)
 */
const KINDS = ["purchase", "referral", "redeem", "refund", "admin", "deduct"];

export function registerRewardsAdminRoutes(app, { pool, adminAuth, bot, notifyErrorChannel }) {
  /** Admin userga bonus beradi: darhol balansga, userga xabar, xizmat kanaliga audit */
  app.post("/api/admin/rewards/user/:userId/grant", adminAuth, async (req, res) => {
    try {
      const uid = String(req.params.userId || "").trim();
      const amount = Number(req.body?.amount);
      const reason = String(req.body?.reason || "").trim().slice(0, 200);
      if (!Number.isInteger(amount) || amount < 1 || amount > ADMIN_GRANT_MAX) {
        return res.status(400).json({ error: `Miqdor 1 dan ${ADMIN_GRANT_MAX} gacha butun son bo'lishi kerak` });
      }
      const u = await pool.query(`SELECT user_id, username FROM users WHERE user_id = $1`, [uid]);
      if (!u.rowCount) return res.status(404).json({ error: "User topilmadi" });

      const admin = req.adminUser || {};
      const result = await applyLedgerEntry(pool, {
        userId: uid,
        delta: amount,
        kind: "admin",
        refKey: `admin:${crypto.randomUUID()}`,
        meta: { reason: reason || null, admin_id: admin.id ? String(admin.id) : null, admin_username: admin.username || null },
      });
      if (!result) return res.status(500).json({ error: "Bonus yozilmadi" });

      console.log(`🛠 Admin bonus: @${admin.username || admin.id} → user=${uid} +${amount}⭐ (${reason || "sababsiz"})`);

      // Userga xabar (uning app tilida)
      if (bot) {
        try {
          const lang = await getUserAppLanguage(pool, uid);
          const tr = GRANT_TEXTS[lang] || GRANT_TEXTS.uz;
          const text = `${tr.title(amount)}\n\n${reason ? `${tr.reason}: ${reason}\n\n` : ""}${tr.body}`;
          await bot.telegram.sendMessage(uid, text, {
            reply_markup: { inline_keyboard: [[{ text: tr.button, url: MINI_APP_URL }]] },
          });
        } catch (err) {
          console.error(`⚠️ Admin bonus xabari yuborilmadi (user=${uid}):`, err.message);
        }
      }

      // Audit: qaysi admin, kimga, qancha
      notifyErrorChannel?.(
        `🛠 <b>Admin bonus berdi</b>\n\n` +
          `👮 @${escapeTelegramHtml(admin.username || String(admin.id || "?"))} → 👤 @${escapeTelegramHtml(u.rows[0].username || uid)}\n` +
          `💫 +${amount} ⭐ · yangi balans ${result.balance} ⭐\n` +
          (reason ? `📝 ${escapeTelegramHtml(reason)}` : "📝 sababsiz")
      );

      res.json({ success: true, balance: result.balance, ledger_id: result.ledgerId });
    } catch (err) {
      console.error("❌ /api/admin/rewards/grant:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  /**
   * Admin user balansidan ayiradi ({ amount }) yoki hammasini nolga tushiradi ({ all: true }).
   * Userga xabar YUBORILMAYDI va yozuv uning tarixida ko'rinmaydi — faqat xizmat kanaliga audit.
   */
  app.post("/api/admin/rewards/user/:userId/deduct", adminAuth, async (req, res) => {
    try {
      const uid = String(req.params.userId || "").trim();
      const all = req.body?.all === true;
      const amount = all ? null : Number(req.body?.amount);
      const reason = String(req.body?.reason || "").trim().slice(0, 200);
      if (!all && (!Number.isInteger(amount) || amount < 1)) {
        return res.status(400).json({ error: "Miqdor 1 dan katta butun son bo'lishi kerak" });
      }
      const u = await pool.query(`SELECT user_id, username, bonus_balance FROM users WHERE user_id = $1`, [uid]);
      if (!u.rowCount) return res.status(404).json({ error: "User topilmadi" });
      if (!all && amount > u.rows[0].bonus_balance) {
        return res.status(400).json({ error: `Balansda faqat ${u.rows[0].bonus_balance} ⭐ bor` });
      }

      const admin = req.adminUser || {};
      const result = await deductBalance(pool, {
        userId: uid,
        amount,
        refKey: `deduct:${crypto.randomUUID()}`,
        meta: { reason: reason || null, all, admin_id: admin.id ? String(admin.id) : null, admin_username: admin.username || null },
      });
      if (!result) return res.status(404).json({ error: "User topilmadi" });
      if (!result.deducted) return res.status(400).json({ error: "Balans allaqachon 0" });

      console.log(`🛠 Admin ayirdi: @${admin.username || admin.id} → user=${uid} −${result.deducted}⭐${all ? " (nolga)" : ""} (${reason || "sababsiz"})`);

      notifyErrorChannel?.(
        `🛠 <b>Admin bonusni ${all ? "nolga tushirdi" : "ayirdi"}</b>\n\n` +
          `👮 @${escapeTelegramHtml(admin.username || String(admin.id || "?"))} → 👤 @${escapeTelegramHtml(u.rows[0].username || uid)}\n` +
          `💫 −${result.deducted} ⭐ · yangi balans ${result.balance} ⭐\n` +
          (reason ? `📝 ${escapeTelegramHtml(reason)}` : "📝 sababsiz")
      );

      res.json({ success: true, deducted: result.deducted, balance: result.balance, ledger_id: result.ledgerId });
    } catch (err) {
      console.error("❌ /api/admin/rewards/deduct:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.get("/api/admin/rewards/overview", adminAuth, async (_req, res) => {
    try {
      const [totals, periods, unseen, items, top] = await Promise.all([
        pool.query(`
          SELECT
            (SELECT COALESCE(SUM(bonus_balance), 0)::int FROM users) AS balance_total,
            (SELECT COUNT(*)::int FROM users WHERE bonus_balance > 0) AS users_with_balance,
            COALESCE(SUM(delta) FILTER (WHERE kind = 'purchase'), 0)::int AS earned_purchase,
            COALESCE(SUM(delta) FILTER (WHERE kind = 'referral'), 0)::int AS earned_referral,
            COALESCE(SUM(delta) FILTER (WHERE kind = 'admin'), 0)::int AS earned_admin,
            COALESCE(-SUM(delta) FILTER (WHERE kind = 'deduct'), 0)::int AS deducted,
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
      const limit = Math.max(1, Math.min(100, parseInt(req.query.limit, 10) || 10));
      const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
      const kind = KINDS.includes(req.query.kind) ? req.query.kind : null;
      const seen = req.query.seen === "seen" ? true : req.query.seen === "unseen" ? false : null;
      const search = String(req.query.search || "").trim().replace(/^@/, "");
      const userId = String(req.query.user_id || "").trim();

      const where = [];
      const params = [];
      if (userId) { params.push(userId); where.push(`l.user_id = $${params.length}`); }
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
                  l.meta->>'reason' AS reason, l.meta->>'admin_username' AS admin_username,
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

  /** Bonusi bor (yoki bo'lgan) userlar — balans bo'yicha, sahifalab */
  app.get("/api/admin/rewards/users", adminAuth, async (req, res) => {
    try {
      const limit = Math.max(1, Math.min(50, parseInt(req.query.limit, 10) || 10));
      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const search = String(req.query.search || "").trim().replace(/^@/, "");
      const params = [];
      let searchSql = "";
      if (search) {
        params.push(`%${search}%`);
        searchSql = `AND (u.username ILIKE $1 OR u.user_id ILIKE $1 OR u.name ILIKE $1)`;
      }
      const base = `
        FROM users u
        JOIN (
          SELECT user_id,
                 COALESCE(SUM(delta) FILTER (WHERE kind = 'purchase'), 0)::int AS earned_purchase,
                 COALESCE(SUM(delta) FILTER (WHERE kind = 'referral'), 0)::int AS earned_referral,
                 COALESCE(-SUM(delta) FILTER (WHERE kind = 'redeem'), 0)::int AS spent,
                 COUNT(*) FILTER (WHERE seen = false AND delta > 0)::int AS unseen_count,
                 COALESCE(SUM(delta) FILTER (WHERE seen = false AND delta > 0), 0)::int AS unseen_stars,
                 MAX(created_at) AS last_at
          FROM bonus_ledger GROUP BY user_id
        ) l ON l.user_id = u.user_id
        WHERE TRUE ${searchSql}`;
      const [rows, total] = await Promise.all([
        pool.query(
          `SELECT u.user_id, u.username, u.name, u.bonus_balance, l.*
           ${base}
           ORDER BY u.bonus_balance DESC, l.last_at DESC
           LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
          [...params, limit, (page - 1) * limit]
        ),
        pool.query(`SELECT COUNT(*)::int AS c ${base}`, params),
      ]);
      res.json({ success: true, users: rows.rows, total: total.rows[0].c, page, limit });
    } catch (err) {
      console.error("❌ /api/admin/rewards/users:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  /** Bitta userning bonus profili */
  app.get("/api/admin/rewards/user/:userId", adminAuth, async (req, res) => {
    try {
      const uid = String(req.params.userId || "").trim();
      const user = await pool.query(
        `SELECT user_id, username, name, language, bonus_balance, referrer_user_id, created_at FROM users WHERE user_id = $1`,
        [uid]
      );
      if (!user.rowCount) return res.status(404).json({ error: "User topilmadi" });
      const [led, ord, ref, referrer] = await Promise.all([
        pool.query(
          `SELECT COALESCE(SUM(delta) FILTER (WHERE kind = 'purchase'), 0)::int AS earned_purchase,
                  COALESCE(SUM(delta) FILTER (WHERE kind = 'referral'), 0)::int AS earned_referral,
                  COALESCE(SUM(delta) FILTER (WHERE kind = 'admin'), 0)::int AS earned_admin,
                  COALESCE(-SUM(delta) FILTER (WHERE kind = 'deduct'), 0)::int AS deducted,
                  COALESCE(-SUM(delta) FILTER (WHERE kind = 'redeem'), 0)::int AS spent,
                  COUNT(*) FILTER (WHERE kind = 'redeem')::int AS redeem_count,
                  COALESCE(SUM(delta) FILTER (WHERE kind = 'refund'), 0)::int AS refunded,
                  COUNT(*) FILTER (WHERE seen = false AND delta > 0)::int AS unseen_count,
                  COALESCE(SUM(delta) FILTER (WHERE seen = false AND delta > 0), 0)::int AS unseen_stars,
                  COUNT(*)::int AS entries
           FROM bonus_ledger WHERE user_id = $1`,
          [uid]
        ),
        pool.query(
          `SELECT COUNT(*)::int AS orders_count,
                  COALESCE(SUM(type_amount) FILTER (WHERE order_type LIKE 'stars%'), 0)::int AS stars_bought,
                  COALESCE(SUM(type_amount) FILTER (WHERE order_type LIKE 'premium%'), 0)::int AS premium_months,
                  COUNT(*) FILTER (WHERE order_type = 'gift')::int AS gifts_count,
                  COALESCE(SUM(summ), 0)::bigint AS total_spent,
                  MAX(created_at) AS last_order_at
           FROM orders
           WHERE owner_user_id = $1 AND status IN ('completed', 'delivered') AND summ > 0
             AND COALESCE(payment_method, '') NOT IN ('bonus', 'referral', 'admin_manual')`,
          [uid]
        ),
        pool.query(`SELECT COUNT(*)::int AS friends FROM users WHERE referrer_user_id = $1`, [uid]),
        user.rows[0].referrer_user_id
          ? pool.query(`SELECT user_id, username FROM users WHERE user_id = $1`, [String(user.rows[0].referrer_user_id)])
          : Promise.resolve({ rows: [] }),
      ]);
      res.json({
        success: true,
        user: user.rows[0],
        bonus: led.rows[0],
        purchases: { ...ord.rows[0], total_spent: Number(ord.rows[0].total_spent) || 0 },
        friends: ref.rows[0].friends,
        referrer: referrer.rows[0] || null,
      });
    } catch (err) {
      console.error("❌ /api/admin/rewards/user:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });
}
