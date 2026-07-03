/** Foydalanuvchi buyurtmalar tarixi — stars | premium | gift */

export const USER_HISTORY_SQL = `
  SELECT
    id,
    recipient_username AS username,
    type_amount,
    summ AS amount,
    gift_id,
    created_at,
    CASE
      WHEN order_type IN ('stars', 'stars_usdt', 'stars_paymee') THEN 'stars'
      WHEN order_type IN ('premium', 'premium_usdt', 'premium_paymee') THEN 'premium'
      WHEN order_type = 'gift' THEN 'gift'
      ELSE 'stars'
    END AS kind,
    CASE
      WHEN status IN ('completed', 'delivered')
        AND order_type IN ('stars', 'stars_usdt', 'stars_paymee') THEN 'stars_sent'
      WHEN status IN ('completed', 'delivered')
        AND order_type IN ('premium', 'premium_usdt', 'premium_paymee') THEN 'premium_sent'
      WHEN status IN ('completed', 'delivered', 'gift_sent')
        AND order_type = 'gift' THEN 'gift_sent'
      ELSE status
    END AS status
  FROM orders
  WHERE owner_user_id = $1
  ORDER BY created_at DESC
`;

export function mapUserHistoryRow(row) {
  const kind = row.kind || "stars";
  const typeAmount = row.type_amount;

  return {
    id: row.id,
    kind,
    username: row.username || null,
    amount: row.amount,
    gift_id: row.gift_id || null,
    stars: kind === "premium" ? null : typeAmount,
    months: kind === "premium" ? typeAmount : null,
    status: row.status,
    created_at: row.created_at,
  };
}

export function mapUserHistoryRows(rows) {
  return (rows || []).map(mapUserHistoryRow);
}
