/**
 * Loyihalararo summa band qilish.
 *
 * StarsJoy, UzGets, PremiumSend va Premium24 bir xil kartalarga pul qabul qiladi, to'lov esa
 * faqat summa bo'yicha buyurtmaga bog'lanadi. Ikki loyihada bir vaqtda bir xil summali ochiq
 * buyurtma bo'lsa, bitta to'lov ikkalasini ham yopadi. Shuning uchun har bir yangi buyurtma summasi
 * umumiy jadvalda (StarsJoy bazasi) 15 daqiqaga band qilinadi: bitta summa — bitta buyurtma.
 * INSERT ... ON CONFLICT DO NOTHING atomik, ikki loyiha bir soniyada so'rasa ham bittasi oladi.
 *
 * Jadval bazasi: AMOUNT_LOCK_ENV_FILE (standart /root/backend/.env).
 * Baza javob bermasa — eski xatti-harakat (faqat o'z bazasi tekshiruvi), savdo to'xtamaydi.
 */
import fs from "fs";
import path from "path";
import pg from "pg";

const HOLD_MINUTES = 15; // to'lov oynasi 8-10 daqiqa + zaxira
const PROJECT = path.basename(process.cwd());

let pool = null;
let ready = null;

function getPool() {
  if (pool) return pool;
  const file = process.env.AMOUNT_LOCK_ENV_FILE || "/root/backend/.env";
  let url = null;
  try {
    const m = fs.readFileSync(file, "utf8").match(/^DATABASE_URL=(.*)$/m);
    url = m ? m[1].trim().replace(/^["']|["']$/g, "") : null;
  } catch {
    url = null;
  }
  if (!url) url = process.env.DATABASE_URL;
  pool = new pg.Pool({ connectionString: url, max: 2, idleTimeoutMillis: 30000, connectionTimeoutMillis: 3000 });
  pool.on("error", (e) => console.error("⚠️ Summa band qilish pool:", e.message));
  ready = pool
    .query(
      `CREATE TABLE IF NOT EXISTS amount_reservations (
         summ BIGINT PRIMARY KEY,
         project TEXT NOT NULL,
         reserved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
         expires_at TIMESTAMPTZ NOT NULL
       )`
    )
    .catch((e) => console.error("⚠️ amount_reservations jadvali:", e.message));
  return pool;
}

/** Summani band qiladi. true — shu loyihaga berildi; false — boshqa buyurtmada band. */
export async function reserveAmount(summ) {
  const db = getPool();
  try {
    await ready;
    await db.query("DELETE FROM amount_reservations WHERE summ = $1 AND expires_at < NOW()", [summ]);
    const r = await db.query(
      `INSERT INTO amount_reservations (summ, project, expires_at)
       VALUES ($1, $2, NOW() + ($3 || ' minutes')::interval)
       ON CONFLICT (summ) DO NOTHING RETURNING summ`,
      [summ, PROJECT, String(HOLD_MINUTES)]
    );
    return r.rowCount === 1;
  } catch (e) {
    console.error("⚠️ Summa band qilinmadi (faqat o'z bazasi tekshirildi):", summ, e.message);
    return true;
  }
}
