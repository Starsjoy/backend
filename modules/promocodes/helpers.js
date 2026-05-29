/** Promokod qayta ishlatilmasligi: faqat bekor/yaroqsiz holatlar bundan mustasno */
export const PROMO_REUSE_EXCLUDED_STATUSES = ["expired", "failed", "error", "cancelled"];

export const PROMO_USER_USAGE_SQL = `SELECT id FROM orders
  WHERE owner_user_id = $1 AND applied_promocode = $2
  AND status NOT IN ('expired', 'failed', 'error', 'cancelled')
  LIMIT 1`;

export async function releasePromocodeUsage(pool, code) {
  if (!code) return;
  await pool.query(
    `UPDATE promocodes SET used_count = GREATEST(used_count - 1, 0) WHERE code = $1`,
    [code]
  );
}
