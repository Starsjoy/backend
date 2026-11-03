/**
 * "To'lov topilmadi" ogohlantirishidan oldingi tekshiruv.
 *
 * Bitta karta SMS'ini bir nechta loyiha ko'radi: to'lov boshqa loyihada yopilgan bo'lsa,
 * ogohlantirish kerak emas. Qo'shni loyihalar bazasi PAYMENT_PEER_ENV_FILES dagi .env
 * fayllardan olinadi (shu serverdagi loyihalar), faqat o'qiladi.
 * Hech qayerda topilmasa, bitta SMS uchun faqat bitta loyiha xabar yuboradi.
 */
import fs from "fs";
import crypto from "crypto";
import pg from "pg";

const BEFORE_SMS_MS = 12 * 60 * 1000; // buyurtma to'lovdan oldin ochiladi (to'lov oynasi 8 daqiqa)
const AFTER_SMS_MS = 60 * 1000;
const CLAIM_DIR = "/tmp/payment-alert-claims";
const CLAIM_TTL_MS = 24 * 60 * 60 * 1000;

let pools = null;

function readDatabaseUrl(file) {
  try {
    const m = fs.readFileSync(file, "utf8").match(/^DATABASE_URL=(.*)$/m);
    return m ? m[1].trim().replace(/^["']|["']$/g, "") : null;
  } catch {
    return null;
  }
}

function getPools() {
  if (pools) return pools;
  const peers = String(process.env.PAYMENT_PEER_ENV_FILES || "")
    .split(",")
    .map((f) => f.trim())
    .filter(Boolean)
    .map(readDatabaseUrl);
  const urls = [...new Set([process.env.DATABASE_URL, ...peers].filter(Boolean))];
  pools = urls.map((connectionString) => {
    const pool = new pg.Pool({ connectionString, max: 1, idleTimeoutMillis: 30000, connectionTimeoutMillis: 5000 });
    pool.on("error", (err) => console.error("⚠️ To'lov tekshiruvi pool xatosi:", err.message));
    return pool;
  });
  return pools;
}

/** SMS vaqti atrofida shu summa bilan to'langan buyurtma biror loyihada bormi */
export async function isPaidAnywhere(amount, smsReceivedAt) {
  const from = new Date(smsReceivedAt - BEFORE_SMS_MS);
  const to = new Date(smsReceivedAt + AFTER_SMS_MS);
  const results = await Promise.all(
    getPools().map((pool) =>
      pool
        .query(
          `SELECT 1 FROM orders
            WHERE summ = $1 AND payment_status = 'paid' AND created_at BETWEEN $2 AND $3
            LIMIT 1`,
          [Math.round(Number(amount)), from, to]
        )
        .then((r) => r.rowCount > 0)
        .catch((err) => {
          console.error("⚠️ To'lov tekshiruvi so'rovi xatosi:", err.message);
          return false;
        })
    )
  );
  return results.some(Boolean);
}

/** Bir xil SMS uchun serverdagi loyihalardan faqat birinchisi true oladi */
export function claimAlert(smsText) {
  try {
    fs.mkdirSync(CLAIM_DIR, { recursive: true });
    const now = Date.now();
    for (const name of fs.readdirSync(CLAIM_DIR)) {
      const file = `${CLAIM_DIR}/${name}`;
      if (now - fs.statSync(file).mtimeMs > CLAIM_TTL_MS) fs.rmSync(file, { force: true });
    }
    const key = crypto.createHash("sha1").update(String(smsText)).digest("hex");
    fs.closeSync(fs.openSync(`${CLAIM_DIR}/${key}`, "wx"));
    return true;
  } catch (err) {
    return err.code !== "EEXIST";
  }
}

/** Hech qayerda yopilmagan to'lov uchungina send() chaqiriladi */
export async function notifyIfUnpaidEverywhere(payment, send) {
  if (await isPaidAnywhere(payment.amount, payment.timestamp)) {
    console.log(`✅ ${payment.amount} so'm to'lov boshqa loyihada yopilgan, ogohlantirish kerak emas`);
    return;
  }
  if (!claimAlert(payment.text || `${payment.amount}:${payment.timestamp}`)) return;
  send();
}
