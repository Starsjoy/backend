/**
 * Jamg'arma kartasi: foydaning bir qismini mijoz to'lovlari orqali avtomatik yig'ish.
 *
 * Qoida (foydalanuvchi bilan kelishilgan, 2026-11-06):
 *  - Kun uch davrga bo'linadi, hisob nuqtalari Toshkent vaqti bilan 08:00, 20:00 va 00:00.
 *  - Har hisob nuqtasida oldingi davrda StarsJoy kartalariga tushgan pul (sms_payments, decision='matched')
 *    hisoblanadi. Uning SAVINGS_PERCENT foizi (standart 6%) — jamg'arma maqsadi.
 *    6% = sof foydaning (12%) yarmi: *5830 ga tushgan buyurtmalarning tannarxi aylanmadan to'lanadi,
 *    shuning uchun 12% olinsa foydaning deyarli hammasi jamg'armaga ketardi.
 *  - Qarz = barcha maqsadlar − jamg'arma kartasiga (uzcard3) tushgan StarsJoy to'lovlari. Qarz bo'lsa
 *    mijozlarga jamg'arma kartasi ko'rsatiladi, qarz yopilgach avvalgi kartaga qaytiladi.
 *    Ortiqcha tushgani (almashish paytida to'lov oynasi ochiq qolganlar) keyingi davrdan ayiriladi.
 *  - Kartani admin yoki limit avtomatikasi almashtirsa — keyingi hisob nuqtasigacha aralashilmaydi.
 *  - Jamg'arma kartasi oxirgi 3 kunda limit olgan bo'lsa yoqilmaydi; qaytishda limitdagi karta tanlanmaydi.
 *
 * Holat bazada (savings_checkpoints, savings_state): balanceChecker alohida jarayon, restartda yo'qolmasin.
 */
import { REST_MS } from "../cardLimit/index.js";

const TZ_OFFSET_MS = 5 * 60 * 60 * 1000; // Asia/Tashkent, yozgi vaqt yo'q
const CHECKPOINT_HOURS = [0, 8, 20];
const WORKER_INTERVAL_MS = 60 * 1000;
const MIN_OUTSTANDING = 1000; // so'm: bundan kichik qarz uchun karta almashtirilmaydi
const ADVISORY_LOCK_KEY = 5830006;
const DEFAULT_OWNER_ID = "6418750920"; // @shavkatov_ff

const fmt = (n) => Math.round(Number(n) || 0).toLocaleString("ru-RU").replace(/ /g, " ");
const tashkentTime = (d) => new Date(d.getTime() + TZ_OFFSET_MS).toISOString().slice(11, 16);

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
  if (outstanding < MIN_OUTSTANDING) return { action: "none" };
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
  fetchImpl = (...args) => fetch(...args),
}) {
  const ownerId = () => String(process.env.CARD_ALERT_USER_ID || DEFAULT_OWNER_ID);

  async function telegram(chatId, text) {
    const res = await fetchImpl(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
    });
    const data = await res.json().catch(() => ({}));
    if (!data.ok) throw new Error(data.description || `HTTP ${res.status}`);
  }
  const alertOwner = (text) => telegram(ownerId(), text).catch((e) => console.error("❌ Jamg'arma xabari:", e.message));

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
    await pool.query(`INSERT INTO savings_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`);
  }

  async function revenueBetween(client, from, to) {
    const r = await client.query(
      `SELECT COALESCE(SUM(amount), 0)::bigint AS s FROM sms_payments
       WHERE decision = 'matched' AND received_at >= $1 AND received_at < $2`,
      [from, to]
    );
    return Number(r.rows[0].s);
  }

  /** Umumiy hisob: maqsadlar, jamg'arma kartasiga tushgani, qarz */
  async function totals(client, startedAt) {
    const [t, c] = await Promise.all([
      client.query(`SELECT COALESCE(SUM(target), 0)::bigint AS s FROM savings_checkpoints`),
      client.query(
        `SELECT COALESCE(SUM(amount), 0)::bigint AS s FROM sms_payments
         WHERE decision = 'matched' AND card_last4 = $1 AND received_at >= $2`,
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
        const revenue = await revenueBetween(client, periodStart, cp);
        const target = Math.round((revenue * percent) / 100);
        await client.query(
          `INSERT INTO savings_checkpoints (checkpoint_at, period_start, revenue, target)
           VALUES ($1, $2, $3, $4) ON CONFLICT (checkpoint_at) DO NOTHING`,
          [cp, periodStart, revenue, target]
        );
        messages.push(
          `🏦 Jamg'arma hisobi (${tashkentTime(periodStart)}–${tashkentTime(cp)})\n\n` +
            `Tushum: ${fmt(revenue)} so'm\nSof foyda (12%): ${fmt(revenue * 0.12)} so'm\n` +
            `Jamg'armaga (${percent}%): ${fmt(target)} so'm`
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
          `UPDATE savings_state SET active = true, prev_slot = $1, activated_at = NOW(), override_until = NULL WHERE id = 1`,
          [prev]
        );
        messages.push(`💳 Jamg'arma kartasi *${savingsLast4} yoqildi.\n\nYig'iladi: ${fmt(sum.outstanding)} so'm. To'lgach *${last4Of(prev)} ga qaytadi.`);
      } else if (decision.action === "restore") {
        await setSlot(client, decision.slot);
        await client.query(`UPDATE savings_state SET active = false, activated_at = NULL WHERE id = 1`);
        messages.push(
          `✅ Jamg'arma to'ldi: *${savingsLast4} ga jami ${fmt(sum.collected)} so'm tushdi` +
            (sum.outstanding < 0 ? ` (${fmt(-sum.outstanding)} so'm ortiqcha, keyingi davrdan ayiriladi)` : "") +
            `.\n\nKarta *${last4Of(decision.slot)} ga qaytdi.`
        );
      } else if (decision.action === "stop") {
        const until = nextCheckpoint(now);
        await client.query(`UPDATE savings_state SET active = false, activated_at = NULL, override_until = $1 WHERE id = 1`, [until]);
        messages.push(
          `⏸ Jamg'arma to'xtatildi: karta *${last4Of(currentSlot)} ga almashtirilgan (qo'lda yoki limit).\n\n` +
            `Qolgan ${fmt(Math.max(sum.outstanding, 0))} so'm ${tashkentTime(until)} dagi hisobdan keyin yig'iladi.`
        );
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
      `SELECT checkpoint_at, period_start, revenue, target FROM savings_checkpoints ORDER BY checkpoint_at DESC LIMIT 6`
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
