import { getMissions } from "../missions/config.js";

/**
 * Vaqt chegaralari. Loyihada `created_at` Toshkent devor-vaqti sifatida saqlanadi
 * (DEFAULT (NOW() AT TIME ZONE 'Asia/Tashkent')), shuning uchun taqqoslashda ham
 * xuddi shu ifodani ishlatamiz — boshqa so'rovlar (masalan /api/gift/match) kabi.
 */
const NOW_TK = "(NOW() AT TIME ZONE 'Asia/Tashkent')";
const BOUNDS = `
  SELECT date_trunc('day',   ${NOW_TK}) AS d,
         ${NOW_TK} - INTERVAL '7 days'  AS w,
         date_trunc('month', ${NOW_TK}) AS m
`;

/** Kunlik yangi userlar + referaldan kelganlar (oxirgi N kun, bo'sh kunlar 0 bilan). */
async function dailySeries(pool, days) {
  const r = await pool.query(
    `WITH series AS (
       SELECT generate_series(
         date_trunc('day', ${NOW_TK}) - ($1::int - 1) * INTERVAL '1 day',
         date_trunc('day', ${NOW_TK}),
         INTERVAL '1 day'
       ) AS d
     )
     SELECT to_char(s.d, 'YYYY-MM-DD') AS date,
            COUNT(u.id)::int AS total,
            COUNT(u.id) FILTER (WHERE u.referrer_user_id IS NOT NULL)::int AS referral
     FROM series s
     LEFT JOIN users u
       ON u.created_at >= s.d AND u.created_at < s.d + INTERVAL '1 day'
     GROUP BY s.d
     ORDER BY s.d`,
    [days]
  );
  return r.rows;
}

/** Yangi userlar va referaldan kelganlar: kun / hafta / oy / jami. */
async function userCounts(pool) {
  const r = await pool.query(
    `WITH b AS (${BOUNDS})
     SELECT
       COUNT(*)::int                                                              AS all_total,
       COUNT(*) FILTER (WHERE u.created_at >= b.d)::int                           AS all_day,
       COUNT(*) FILTER (WHERE u.created_at >= b.w)::int                           AS all_week,
       COUNT(*) FILTER (WHERE u.created_at >= b.m)::int                           AS all_month,
       COUNT(*) FILTER (WHERE u.referrer_user_id IS NOT NULL)::int                AS ref_total,
       COUNT(*) FILTER (WHERE u.referrer_user_id IS NOT NULL
                          AND u.created_at >= b.d)::int                           AS ref_day,
       COUNT(*) FILTER (WHERE u.referrer_user_id IS NOT NULL
                          AND u.created_at >= b.w)::int                           AS ref_week,
       COUNT(*) FILTER (WHERE u.referrer_user_id IS NOT NULL
                          AND u.created_at >= b.m)::int                           AS ref_month,
       COUNT(*) FILTER (WHERE u.referrer_user_id IS NOT NULL
                          AND u.subscribe_user = true)::int                       AS ref_subscribed
     FROM users u CROSS JOIN b`
  );
  const x = r.rows[0];
  return {
    users: { total: x.all_total, day: x.all_day, week: x.all_week, month: x.all_month },
    referral_users: {
      total: x.ref_total, day: x.ref_day, week: x.ref_week, month: x.ref_month,
      subscribed: x.ref_subscribed,
    },
  };
}

/** Missiya sovg'alari: nechta va qaysi gift topshirilgan. */
async function bonusStats(pool) {
  // Muvaffaqiyatli claim'lar user_missions'da qoladi (xatoda revertClaim qiladi),
  // shuning uchun davrlar bo'yicha hisob shu jadvaldan olinadi.
  const claims = await pool.query(
    `WITH b AS (${BOUNDS})
     SELECT
       COUNT(*)::int                                       AS total,
       COUNT(*) FILTER (WHERE um.claimed_at >= b.d)::int   AS day,
       COUNT(*) FILTER (WHERE um.claimed_at >= b.w)::int   AS week,
       COUNT(*) FILTER (WHERE um.claimed_at >= b.m)::int   AS month
     FROM user_missions um CROSS JOIN b
     WHERE um.claimed = true`
  );

  const byLevel = await pool.query(
    `SELECT mission_level::int AS level, COUNT(*)::int AS claimed
     FROM user_missions WHERE claimed = true
     GROUP BY mission_level ORDER BY mission_level`
  );

  // orders'da xato bo'lgan urinishlar ham qoladi → yetkazilgan/xato ajratib ko'rsatamiz
  const byGift = await pool.query(
    `SELECT gift_id,
            COUNT(*)::int                                          AS attempts,
            COUNT(*) FILTER (WHERE status = 'completed')::int      AS delivered,
            COUNT(*) FILTER (WHERE status = 'error')::int          AS failed,
            COALESCE(SUM(type_amount) FILTER (WHERE status = 'completed'), 0)::int AS stars_spent
     FROM orders
     WHERE payment_method = 'bonus'
     GROUP BY gift_id`
  );

  const missions = getMissions();
  const levelByGift = new Map(missions.map((m) => [String(m.gift_id), m]));
  const claimedByLevel = new Map(byLevel.rows.map((r) => [r.level, r.claimed]));

  const gifts = byGift.rows.map((g) => {
    const m = levelByGift.get(String(g.gift_id));
    return {
      gift_id: g.gift_id,
      level: m?.level ?? null,
      label: m?.label ?? g.gift_id,
      gift_stars: m?.stars ?? null,
      attempts: g.attempts,
      delivered: g.delivered,
      failed: g.failed,
      stars_spent: g.stars_spent,
    };
  });
  gifts.sort((a, b) => (a.level ?? 99) - (b.level ?? 99));

  return {
    claims: claims.rows[0],
    total_stars_spent: gifts.reduce((s, g) => s + g.stars_spent, 0),
    total_delivered: gifts.reduce((s, g) => s + g.delivered, 0),
    total_failed: gifts.reduce((s, g) => s + g.failed, 0),
    // Har missiya uchun qator — hali hech kim olmagan bo'lsa ham ko'rinsin
    levels: missions.map((m) => {
      const g = gifts.find((x) => x.level === m.level);
      return {
        level: m.level,
        label: m.label,
        gift_id: String(m.gift_id),
        gift_stars: m.stars,
        required: m.required,
        claimed: claimedByLevel.get(m.level) || 0,
        delivered: g?.delivered || 0,
        failed: g?.failed || 0,
        stars_spent: g?.stars_spent || 0,
      };
    }),
    gifts,
  };
}

export function registerAnalyticsRoutes(app, { pool, adminAuth }) {
  // ======================
  // 📊 GET /api/admin/analytics/overview?days=30
  // ======================
  app.get("/api/admin/analytics/overview", adminAuth, async (req, res) => {
    try {
      const days = Math.min(Math.max(Number(req.query.days) || 30, 7), 90);

      const [counts, daily, bonus] = await Promise.all([
        userCounts(pool),
        dailySeries(pool, days),
        bonusStats(pool),
      ]);

      res.json({ success: true, ...counts, daily, bonus });
    } catch (err) {
      console.error("❌ /api/admin/analytics/overview error:", err);
      res.status(500).json({ error: "Server xato" });
    }
  });
}
