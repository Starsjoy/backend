const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const HISTORY_LIMIT = 15;

function entryLabel(e) {
  const m = e.meta || {};
  if (e.kind === "referral") return m.friend_username ? `referal @${esc(m.friend_username)}` : "referal";
  if (e.kind === "purchase") {
    const type = String(m.order_type || "");
    if (type.includes("premium")) return `Premium ${esc(m.type_amount)} oy xaridi`;
    if (type.includes("gift")) return `Gift (${esc(m.type_amount)} ⭐) xaridi`;
    return `${esc(m.type_amount)} Stars xaridi`;
  }
  return esc(e.kind);
}

function shortDate(value) {
  const d = new Date(new Date(value).getTime() + 5 * 60 * 60 * 1000); // Toshkent vaqti
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}.${p(d.getUTCMonth() + 1)}`;
}

/**
 * Yechilgan bonus qayerdan yig'ilgani: oxirgi muvaffaqiyatli yechishdan keyingi kirimlar.
 * Qaytarilgan (refund) yechish hisobga olinmaydi — uning bonusi hali ishlatilmagan.
 * Xato bo'lsa bo'sh qaytadi: tarix yo'qligi yechish xabariga to'siq bo'lmasin.
 */
export async function redeemHistoryText(pool, { userId, orderId, toStars = (n) => n }) {
  try {
    const cur = await pool.query(`SELECT id FROM bonus_ledger WHERE ref_key = $1`, [`redeem:${orderId}`]);
    const curId = cur.rows[0]?.id;
    if (!curId) return "";
    const prev = await pool.query(
      `SELECT COALESCE(MAX(l.id), 0) AS id FROM bonus_ledger l
       WHERE l.user_id = $1 AND l.kind = 'redeem' AND l.id < $2
         AND NOT EXISTS (SELECT 1 FROM bonus_ledger r WHERE r.ref_key = 'refund:' || l.order_id)`,
      [String(userId), curId]
    );
    const rows = await pool.query(
      `SELECT delta, kind, meta, created_at FROM bonus_ledger
       WHERE user_id = $1 AND id > $2 AND id < $3 AND delta > 0 AND kind <> 'refund'
       ORDER BY id DESC`,
      [String(userId), prev.rows[0].id, curId]
    );
    if (!rows.rowCount) return "";

    const total = toStars(rows.rows.reduce((sum, e) => sum + Number(e.delta), 0));
    const lines = rows.rows
      .slice(0, HISTORY_LIMIT)
      .map((e) => `• ${shortDate(e.created_at)} +${toStars(e.delta)} ⭐ — ${entryLabel(e)}`);
    const rest = rows.rowCount - HISTORY_LIMIT;
    if (rest > 0) lines.push(`… yana ${rest} ta`);
    return `\n\n📜 <b>Bonus tarixi</b> (jami +${total} ⭐):\n${lines.join("\n")}`;
  } catch (err) {
    console.error(`⚠️ Bonus tarixi olinmadi (order=#${orderId}):`, err.message);
    return "";
  }
}
