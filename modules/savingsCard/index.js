/**
 * Jamg'arma kartasi: foydaning bir qismini mijoz to'lovlari orqali avtomatik yig'ish.
 *
 * Qoida (foydalanuvchi bilan kelishilgan, 2026-11-06):
 *  - Kun uch davrga bo'linadi, hisob nuqtalari Toshkent vaqti bilan 08:00, 20:00 va 00:00.
 *  - Har hisob nuqtasida oldingi davrdagi BARCHA loyihalar (StarsJoy, UzGets, PremiumSend, Premium24) karta
 *    tushumi hisoblanadi: to'langan buyurtmalar, bonus/admin/USDT'siz. Uning SAVINGS_PERCENT foizi (standart 6%)
 *    — jamg'arma maqsadi. Karta esa faqat StarsJoy'da almashadi.
 *    6% = sof foydaning (12%) yarmi: *5830 ga tushgan buyurtmalarning tannarxi aylanmadan to'lanadi,
 *    shuning uchun 12% olinsa foydaning deyarli hammasi jamg'armaga ketardi.
 *  - Qarz = barcha maqsadlar − jamg'arma kartasiga (uzcard3) tushgan barcha pul. Qarz SAVINGS_MIN (50 000) dan oshsa
 *    mijozlarga jamg'arma kartasi ko'rsatiladi, qarz yopilgach avvalgi kartaga qaytiladi.
 *    Ortiqcha tushgani (almashish paytida to'lov oynasi ochiq qolganlar) keyingi davrdan ayiriladi.
 *  - Kartani admin yoki limit avtomatikasi almashtirsa — keyingi hisob nuqtasigacha aralashilmaydi.
 *  - Jamg'arma kartasi oxirgi 3 kunda limit olgan bo'lsa yoqilmaydi; qaytishda limitdagi karta tanlanmaydi.
 *  - Xabar faqat @shavkatov_ff ga va faqat ikki holatda: karta jamg'armaga o'tganda (kutilayotgan summa)
 *    va avvalgi kartaga qaytganda (shu safar tushgan summa).
 *
 * Holat bazada (savings_checkpoints, savings_state): balanceChecker alohida jarayon, restartda yo'qolmasin.
 */
import fs from "fs";
import pg from "pg";
import { REST_MS } from "../cardLimit/index.js";

const TZ_OFFSET_MS = 5 * 60 * 60 * 1000; // Asia/Tashkent, yozgi vaqt yo'q
const CHECKPOINT_HOURS = [0, 8, 20];
const WORKER_INTERVAL_MS = 60 * 1000;
// Bundan kichik qarz uchun karta almashtirilmaydi — keyingi davrga qo'shiladi (kechasi tushum kam bo'lganda
// 7 ming so'm uchun karta soatlab *5830 da turib qolmasin)
const MIN_OUTSTANDING = () => Number(process.env.SAVINGS_MIN || 50000);
const ADVISORY_LOCK_KEY = 5830006;
const OWNER_ID = "6418750920"; // @shavkatov_ff — xabarlar faqat shu akkauntga (foydalanuvchi talabi)

/** Loyiha tushumi: to'langan karta buyurtmalari (bonus, referal, admin va USDT buyurtmalarisiz) */
const REVENUE_SQL = `
  SELECT COALESCE(SUM(summ), 0)::bigint AS s FROM orders
  WHERE payment_status = 'paid' AND summ > 0
    AND COALESCE(payment_method, '') NOT IN ('bonus', 'referral', 'admin_manual')
    AND order_type NOT LIKE '%usdt%'
    AND created_at >= $1 AND created_at < $2`;

const fmt = (n) => Math.round(Number(n) || 0).toLocaleString("ru-RU").replace(/ /g, " ");

const PEER_NAMES = { uzgets_backend: "UzGets", premiumsent_backend: "PremiumSend", premium24_backend: "Premium24" };

/**
 * Boshqa loyihalar bazasi: PAYMENT_PEER_ENV_FILES dagi .env fayllar (shu serverdagi loyihalar), faqat o'qiladi.
 * Nom papkadan: /root/uzgets_backend/.env → UzGets.
 */
export function peersFromEnv() {
  return String(process.env.PAYMENT_PEER_ENV_FILES || "")
    .split(",")
    .map((f) => f.trim())
    .filter(Boolean)
    .map((file) => {
      const m = fs.readFileSync(file, "utf8").match(/^DATABASE_URL=(.*)$/m);
      const dir = file.split("/").slice(-2, -1)[0];
      if (!m) throw new Error(`${file} da DATABASE_URL yo'q`);
      const pool = new pg.Pool({ connectionString: m[1].trim().replace(/^["']|["']$/g, ""), max: 1, idleTimeoutMillis: 30000 });
      pool.on("error", (err) => console.error(`⚠️ Jamg'arma (${dir}) pool xatosi:`, err.message));
      return { name: PEER_NAMES[dir] || dir, pool };
    });
}

/** (from, to] oralig'idagi hisob nuqtalari, o'sish tartibida */
export function checkpointsBetween(from, to) {
  const out = [];
  const startDay = Math.floor((from.getTime() + TZ_OFFSET_MS) / 86400000);
  const endDay = Math.floor((to.getTime() + TZ_OFFSET_MS) / 86400000);
  for (let day = startDay; day <= endDay; day++) {
    for (const h of CHECKPOINT_HOURS) {
      const at = new Date(day * 86400000 + h * 3600000 - TZ_OFFSET_MS);
      if (at > from && at <= to) out.push(at);
    }
  }
  return out;
}

/** Keyingi hisob nuqtasi */
export function nextCheckpoint(now) {
  return checkpointsBetween(now, new Date(now.getTime() + 86400000))[0];
}

/**
 * Sof qaror (bazaga tegmaydi).
 * @returns {{action: "none"|"activate"|"restore"|"stop", slot?: string, reason?: string}}
 */
export function decideSavingsAction({
  outstanding, active, currentSlot, savingsSlot, prevSlot, overrideUntil, now,
  savingsLimited, uzcardSlots, limitedSlots,
}) {
  if (active) {
    // Faol paytda kartani boshqasi almashtirgan: admin qo'lda yoki limit avtomatikasi
    if (currentSlot !== savingsSlot) return { action: "stop", reason: "override" };
    if (outstanding > 0) return { action: "none" };
    const candidates = [prevSlot, ...uzcardSlots].filter((s) => s && s !== savingsSlot && !limitedSlots.includes(s));
    return candidates.length ? { action: "restore", slot: candidates[0] } : { action: "none", reason: "no_free_card" };
  }
  if (outstanding < MIN_OUTSTANDING()) return { action: "none" };
  if (overrideUntil && now < overrideUntil) return { action: "none", reason: "override" };
  if (savingsLimited) return { action: "none", reason: "savings_limited" };
  return { action: "activate", slot: savingsSlot };
}

export function createSavingsCard({
  pool,
  settingKey,
  savingsSlot,
  savingsLast4,
  listUzcards, // () => [{ slot, last4 }]
  percent = 6,
  projectName = "StarsJoy",
  peers = [], // [{ name, pool }] — boshqa loyihalar bazasi (tushum hisobi uchun)
  fetchImpl = (...args) => fetch(...args),
}) {

  async function telegram(chatId, text) {
    const res = await fetchImpl(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(15000),
    });
    const data = await res.json().catch(() => ({}));
    if (!data.ok) throw new Error(data.description || `HTTP ${res.status}`);
  }
  /** Tarmoq uzilishida xabar yo'qolmasin: 3 marta, 3 va 10 soniya oraliq bilan */
  async function sendWithRetry(chatId, text, delays = [3000, 10000]) {
    for (let i = 0; ; i++) {
      try {
        return await telegram(chatId, text);
      } catch (e) {
        if (i >= delays.length) throw e;
        console.error(`⚠️ Jamg'arma xabari (${i + 1}-urinish): ${e.message}`);
        await new Promise((r) => setTimeout(r, delays[i]));
      }
    }
  }
  const alertOwner = (text) =>
    sendWithRetry(OWNER_ID, text).catch((e) => console.error("❌ Jamg'arma xabari (3 urinishdan keyin):", e.message));

  async function ensureTables() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS savings_checkpoints (
        checkpoint_at TIMESTAMPTZ PRIMARY KEY,
        period_start TIMESTAMPTZ NOT NULL,
        revenue BIGINT NOT NULL,
        target BIGINT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS savings_state (
        id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        active BOOLEAN NOT NULL DEFAULT false,
        prev_slot TEXT,
        activated_at TIMESTAMPTZ,
        override_until TIMESTAMPTZ
      )`);
    await pool.query(`ALTER TABLE savings_state ADD COLUMN IF NOT EXISTS collected_at_activation BIGINT NOT NULL DEFAULT 0`);
    await pool.query(`ALTER TABLE savings_checkpoints ADD COLUMN IF NOT EXISTS breakdown JSONB`);
    await pool.query(`INSERT INTO savings_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`);
  }

  /** Barcha loyihalar tushumi. Bitta loyiha bazasi javob bermasa — xato: hisob nuqtasi keyingi tickda qayta urinadi */
  async function revenueBetween(client, from, to) {
    const sources = [{ name: projectName, db: client }, ...peers.map((p) => ({ name: p.name, db: p.pool }))];
    const parts = await Promise.all(
      sources.map(async (src) => ({ name: src.name, sum: Number((await src.db.query(REVENUE_SQL, [from, to])).rows[0].s) }))
    );
    return { total: parts.reduce((a, p) => a + p.sum, 0), breakdown: Object.fromEntries(parts.map((p) => [p.name, p.sum])) };
  }

  /** Umumiy hisob: maqsadlar, jamg'arma kartasiga tushgani, qarz */
  async function totals(client, startedAt) {
    const [t, c] = await Promise.all([
      client.query(`SELECT COALESCE(SUM(target), 0)::bigint AS s FROM savings_checkpoints`),
      // Kartaga tushgan HAR QANDAY pul hisoblanadi: buyurtmaga mos kelmagan to'lov ham (mijoz summani
      // noto'g'ri yozgan va h.k.) baribir jamg'arma kartasida turibdi
      client.query(
        `SELECT COALESCE(SUM(amount), 0)::bigint AS s FROM sms_payments
         WHERE card_last4 = $1 AND received_at >= $2`,
        [savingsLast4, startedAt]
      ),
    ]);
    const target = Number(t.rows[0].s);
    const collected = Number(c.rows[0].s);
    return { target, collected, outstanding: target - collected };
  }

  async function limitedLast4s(client, now) {
    const r = await client.query(`SELECT card_last4, limited_at FROM card_limit_state`).catch(() => ({ rows: [] }));
    return r.rows.filter((x) => now.getTime() - new Date(x.limited_at).getTime() < REST_MS).map((x) => x.card_last4);
  }

  async function setSlot(client, slot) {
    await client.query(
      `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [settingKey, slot]
    );
  }

  /** Bitta tick: yangi hisob nuqtalari + karta qarori. Xabarlar tranzaksiyadan keyin yuboriladi. */
  async function tick(now = new Date()) {
    const messages = [];
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [ADVISORY_LOCK_KEY]);

      const st = (await client.query(`SELECT * FROM savings_state WHERE id = 1`)).rows[0];
      const startedAt = new Date(st.started_at);
      const last = (await client.query(`SELECT MAX(checkpoint_at) AS m FROM savings_checkpoints`)).rows[0].m;
      let periodStart = last ? new Date(last) : startedAt;

      for (const cp of checkpointsBetween(periodStart, now)) {
        const { total, breakdown } = await revenueBetween(client, periodStart, cp);
        const target = Math.round((total * percent) / 100);
        await client.query(
          `INSERT INTO savings_checkpoints (checkpoint_at, period_start, revenue, target, breakdown)
           VALUES ($1, $2, $3, $4, $5) ON CONFLICT (checkpoint_at) DO NOTHING`,
          [cp, periodStart, total, target, breakdown]
        );
        periodStart = cp;
      }

      const sum = await totals(client, startedAt);
      const setting = await client.query(`SELECT value FROM settings WHERE key = $1`, [settingKey]);
      const currentSlot = setting.rows[0]?.value || "uzcard1";
      const cards = listUzcards();
      const limited = await limitedLast4s(client, now);
      const limitedSlots = cards.filter((c) => limited.includes(c.last4)).map((c) => c.slot);

      const decision = decideSavingsAction({
        outstanding: sum.outstanding,
        active: st.active,
        currentSlot,
        savingsSlot,
        prevSlot: st.prev_slot,
        overrideUntil: st.override_until ? new Date(st.override_until) : null,
        now,
        savingsLimited: limited.includes(savingsLast4),
        uzcardSlots: cards.map((c) => c.slot),
        limitedSlots,
      });
      const last4Of = (slot) => cards.find((c) => c.slot === slot)?.last4 || "?";

      if (decision.action === "activate") {
        const prev = currentSlot === savingsSlot ? st.prev_slot || "uzcard1" : currentSlot;
        await setSlot(client, savingsSlot);
        await client.query(
          `UPDATE savings_state SET active = true, prev_slot = $1, activated_at = NOW(), override_until = NULL,
             collected_at_activation = $2 WHERE id = 1`,
          [prev, sum.collected]
        );
        messages.push(
          `💳 StarsJoy kartasi *${savingsLast4} ga o'tdi\n\n` +
            `Kutilayotgan tushum: ${fmt(sum.outstanding)} so'm\n` +
            `(barcha loyihalar tushumining ${percent}%, foydaning yarmi)\n\n` +
            `To'lgach *${last4Of(prev)} ga qaytadi.`
        );
      } else if (decision.action === "restore") {
        await setSlot(client, decision.slot);
        await client.query(`UPDATE savings_state SET active = false, activated_at = NULL WHERE id = 1`);
        const thisTime = sum.collected - Number(st.collected_at_activation || 0);
        messages.push(
          `✅ StarsJoy kartasi *${last4Of(decision.slot)} ga qaytdi\n\n` +
            `*${savingsLast4} ga tushdi: ${fmt(thisTime)} so'm` +
            (sum.outstanding < 0 ? `\n(${fmt(-sum.outstanding)} so'm ortiqcha — keyingi davrdan ayiriladi)` : "")
        );
      } else if (decision.action === "stop") {
        const until = nextCheckpoint(now);
        // Xabar yuborilmaydi (faqat almashish/qaytish xabarlari kelishilgan); holat admin panelda ko'rinadi
        await client.query(`UPDATE savings_state SET active = false, activated_at = NULL, override_until = $1 WHERE id = 1`, [until]);
        console.log(`⏸ Jamg'arma to'xtatildi: karta ${currentSlot} ga almashtirilgan, ${until.toISOString()} gacha`);
      }

      await client.query("COMMIT");
      for (const m of messages) await alertOwner(m);
      return { decision, ...sum, currentSlot };
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /** Admin panel uchun holat (faqat o'qish) */
  async function status(now = new Date()) {
    const st = (await pool.query(`SELECT * FROM savings_state WHERE id = 1`)).rows[0];
    if (!st) return null;
    const sum = await totals(pool, new Date(st.started_at));
    const recent = await pool.query(
      `SELECT checkpoint_at, period_start, revenue, target, breakdown FROM savings_checkpoints ORDER BY checkpoint_at DESC LIMIT 6`
    );
    return {
      percent,
      savings_last4: savingsLast4,
      active: st.active,
      started_at: st.started_at,
      override_until: st.override_until,
      next_checkpoint: nextCheckpoint(now),
      ...sum,
      recent: recent.rows,
    };
  }

  function startWorker() {
    const run = () => tick().catch((e) => console.error("❌ Jamg'arma tick:", e.message));
    run();
    setInterval(run, WORKER_INTERVAL_MS).unref?.();
  }

  return { ensureTables, tick, status, startWorker };
}
