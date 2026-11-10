/**
 * Karta limiti: "LIMIT PREVISHEN" SMS kelganda ikki UZCARD orasida avtomatik almashtirish.
 *
 * Qoidalar:
 *  - Limit faqat FAOL kartaga kelganda hisobga olinadi. Eski kartaga kelgani e'tiborsiz:
 *    mijoz yangi karta ko'rsatilgan bo'lsa ham eskisiga to'lashga urinishi mumkin.
 *  - Limit olgan karta 25 soat dam oladi (bank limiti 24 soatda ochiladi, +1 soat zaxira).
 *  - Navbat: aylanma UZCARD'lar (uzcard3 — jamg'arma, qatnashmaydi), ular ham dam olayotgan bo'lsa HUMO.
 *    Hammasi dam olayotgan bo'lsa karta o'zgarmaydi, egasiga bir marta shoshilinch xabar boradi.
 *  - HUMO'ga avtomatika o'tkazgan bo'lsa, UZCARD dami tugashi bilan avtomatik UZCARD'ga qaytadi.
 *  - Almashganda limitdan 10 daqiqa oldindan buyon to'lamaganlarga 2 daqiqadan keyin xabar boradi.
 *
 * Holat bazada: listener alohida jarayon, restartda ham navbat yo'qolmasligi kerak.
 */

export const REST_MS = 25 * 60 * 60 * 1000;
export const LOOKBACK_MS = 10 * 60 * 1000;
export const NOTIFY_DELAY_MS = 2 * 60 * 1000;
const SMS_MAX_AGE_MS = 15 * 60 * 1000;
const WORKER_INTERVAL_MS = 30 * 1000;
const SEND_GAP_MS = 60;
const ADVISORY_LOCK_KEY = 7872113;
const DEFAULT_OWNER_ID = "6418750920"; // @shavkatov_ff

const NOTICE = {
  uz: "💳 To‘lov kartamiz yangilandi.\n\nOldingi to‘lovingiz o‘tmagan bo‘lsa, yangi buyurtma oching. To‘lov oynasida yangi karta chiqadi 👇",
  ru: "💳 Наша платёжная карта обновлена.\n\nЕсли предыдущая оплата не прошла, откройте новый заказ. В окне оплаты появится новая карта 👇",
};
const BUTTON = { uz: "Yangi buyurtma ochish", ru: "Открыть новый заказ" };

const PAID_STATUSES = ["completed", "delivered", "stars_sent", "premium_sent", "gift_sent"];

/** "LIMIT PREVISHEN: P2P Credit part,...,02.11.26 15:41,karta ***1131. ..." → { last4, smsAt } */
export function parseLimitSms(text) {
  const s = String(text || "");
  if (!/^\s*LIMIT PREVISHEN\b/i.test(s) || !/\bCredit\b/i.test(s)) return null;
  const m = s.match(/(\d{2})\.(\d{2})\.(\d{2}) (\d{2}):(\d{2}),\s*karta \*+(\d{4})/i);
  if (!m) return null;
  const [, dd, mm, yy, hh, min, last4] = m;
  const smsAt = new Date(`20${yy}-${mm}-${dd}T${hh}:${min}:00+05:00`);
  return Number.isNaN(smsAt.getTime()) ? null : { last4, smsAt };
}

/**
 * Sof qaror (bazaga tegmaydi).
 * @param {{last4: string, cards: {slot: string, last4: string}[], activeSlot: string,
 *   limitedAt: Record<string, Date|null>, now: Date}} input
 */
export const SAVINGS_SLOT = "uzcard3";

export function isResting(last4, limitedAt, now) {
  const at = limitedAt[last4];
  return Boolean(at && now.getTime() - at.getTime() < REST_MS);
}

export function decideLimitAction({ last4, cards, humo = null, activeSlot, limitedAt, now }) {
  const all = humo ? [...cards, humo] : cards;
  const active = all.find((c) => c.slot === activeSlot);
  if (!active || active.last4 !== last4) return { action: "ignore" };

  const candidates = [
    ...cards.filter((c) => c.slot !== activeSlot && c.slot !== SAVINGS_SLOT),
    ...(humo && humo.slot !== activeSlot ? [humo] : []),
  ];
  if (!candidates.length) return { action: "no_reserve", active };

  const free = candidates.find((c) => c.last4 !== last4 && !isResting(c.last4, limitedAt, now));
  return free ? { action: "switch", active, other: free } : { action: "both_limited", active, other: candidates[0] };
}

/** HUMO'da turibmiz (avtomatika o'tkazgan): dami tugagan aylanma UZCARD bormi? */
export function decideReturnFromHumo({ cards, humo, activeSlot, limitedAt, now }) {
  if (!humo || activeSlot !== humo.slot) return null;
  return cards.find((c) => c.slot !== SAVINGS_SLOT && !isResting(c.last4, limitedAt, now)) || null;
}

export function createCardLimitGuard({
  pool,
  project,
  settingKey,
  listUzcards,
  getHumo = () => null, // { slot, last4 } — HUMO zaxira (faqat HUMO SMS'lari tinglanadigan loyihada)
  fallbackSlot,
  normalizeSlot = (s) => s,
  hasExpectedCardColumn = false,
  fetchImpl = (...args) => fetch(...args),
}) {
  const ownerId = () => String(process.env.CARD_ALERT_USER_ID || DEFAULT_OWNER_ID);

  async function ensureTables() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS card_limit_state (
        card_last4 VARCHAR(4) PRIMARY KEY,
        limited_at TIMESTAMPTZ NOT NULL,
        alerted_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS card_switch_notices (
        id BIGSERIAL PRIMARY KEY,
        from_last4 VARCHAR(4) NOT NULL,
        to_last4 VARCHAR(4) NOT NULL,
        limit_at TIMESTAMPTZ NOT NULL,
        switched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        notify_after TIMESTAMPTZ NOT NULL,
        claimed_at TIMESTAMPTZ
      );
    `);
  }

  async function telegram(chatId, text, replyMarkup) {
    const body = { chat_id: chatId, text, ...(replyMarkup ? { reply_markup: replyMarkup } : {}) };
    const res = await fetchImpl(`https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return { ok: Boolean(data.ok), error: data.description || "" };
  }

  const alertOwner = (text) =>
    telegram(ownerId(), text).catch((e) => console.error("❌ Karta limiti xabari:", e.message));

  /** Bitta tranzaksiyada qaror va yozuv: bir xil SMS ikki marta kelsa ham bitta almashtirish */
  async function applyLimit(parsed, now) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [ADVISORY_LOCK_KEY]);

      const setting = await client.query("SELECT value FROM settings WHERE key = $1", [settingKey]);
      const activeSlot = normalizeSlot(setting.rows[0]?.value) || fallbackSlot();
      const cards = listUzcards();
      const humo = getHumo();
      const state = await client.query("SELECT card_last4, limited_at, alerted_at FROM card_limit_state");
      const byCard = new Map(state.rows.map((r) => [r.card_last4, r]));
      const limitedAt = Object.fromEntries(state.rows.map((r) => [r.card_last4, new Date(r.limited_at)]));

      const decision = decideLimitAction({ last4: parsed.last4, cards, humo, activeSlot, limitedAt, now });
      if (decision.action === "ignore") {
        await client.query("COMMIT");
        return decision;
      }

      // Limit vaqti birinchi xabardan sanaladi: takroriy xabarlar 3 kunni uzaytirmaydi
      const own = byCard.get(parsed.last4);
      const isNewLimit = !own || now.getTime() - new Date(own.limited_at).getTime() >= REST_MS;
      if (isNewLimit) {
        await client.query(
          `INSERT INTO card_limit_state (card_last4, limited_at, alerted_at) VALUES ($1, $2, NULL)
           ON CONFLICT (card_last4) DO UPDATE SET limited_at = EXCLUDED.limited_at, alerted_at = NULL`,
          [parsed.last4, parsed.smsAt]
        );
      }

      if (decision.action === "switch") {
        await client.query(
          `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [settingKey, decision.other.slot]
        );
        await client.query(
          `INSERT INTO card_switch_notices (from_last4, to_last4, limit_at, notify_after)
           VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 millisecond'))`,
          [decision.active.last4, decision.other.last4, parsed.smsAt, NOTIFY_DELAY_MS]
        );
        // HUMO'ga avtomatika o'tkazdi — UZCARD bo'shaganda o'zi qaytaradi
        await client.query(
          `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [`${settingKey}_auto_humo`, humo && decision.other.slot === humo.slot ? "1" : "0"]
        );
      } else {
        const alreadyAlerted = !isNewLimit && own?.alerted_at;
        decision.alert = !alreadyAlerted;
        if (decision.alert) {
          await client.query("UPDATE card_limit_state SET alerted_at = NOW() WHERE card_last4 = $1", [parsed.last4]);
        }
      }

      await client.query("COMMIT");
      return decision;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
  }

  /** SMS listener chaqiradi. Limit xabari bo'lmasa hech narsa qilmaydi. */
  async function handleSms(text, now = new Date()) {
    const parsed = parseLimitSms(text);
    if (!parsed) return null;

    // Restartdagi catch-up eski xabarni qayta o'qisa ham karta almashmasin
    if (Math.abs(now.getTime() - parsed.smsAt.getTime()) > SMS_MAX_AGE_MS) return { action: "stale" };

    const decision = await applyLimit(parsed, now);
    if (decision.action === "switch") {
      console.log(`💳 Limit: karta avtomatik almashtirildi ***${decision.active.last4} → ***${decision.other.last4}`);
    } else if (decision.action === "both_limited" && decision.alert) {
      await alertOwner(
        `🚨 ${project}: barcha kartalarda limit!\n\n` +
          `Faol karta ***${decision.active.last4} limitga yetdi, zaxira kartalar ham oxirgi 25 soatda limit olgan. ` +
          `Karta almashtirilmadi, mijozlar to'lay olmasligi mumkin.\n\nZudlik bilan tekshiring.`
      );
    } else if (decision.action === "no_reserve") {
      await alertOwner(`🚨 ${project}: ***${decision.active.last4} limitga yetdi, zaxira UZCARD sozlanmagan. Zudlik bilan tekshiring.`);
    }
    return decision;
  }

  async function findRecipients(notice) {
    const expectedCard = hasExpectedCardColumn ? "AND (o.expected_card_last4 IS NULL OR o.expected_card_last4 = $3)" : "";
    const params = [
      new Date(new Date(notice.limit_at).getTime() - LOOKBACK_MS),
      notice.switched_at,
      ...(hasExpectedCardColumn ? [notice.from_last4] : []),
    ];
    const r = await pool.query(
      `SELECT DISTINCT o.owner_user_id AS user_id, u.language, u.username
         FROM orders o
         LEFT JOIN users u ON u.user_id::text = o.owner_user_id
        WHERE o.created_at >= $1 AND o.created_at <= $2
          AND o.payment_method = 'card'
          AND o.status IN ('pending', 'expired', 'failed')
          AND o.owner_user_id IS NOT NULL
          ${expectedCard}
          AND NOT EXISTS (
            SELECT 1 FROM orders p
             WHERE p.owner_user_id = o.owner_user_id
               AND p.created_at >= $1
               AND (p.payment_status = 'paid' OR p.status = ANY('{${PAID_STATUSES.join(",")}}'::text[]))
          )`,
      params
    );
    return r.rows;
  }

  async function sendNotice(notice) {
    const recipients = await findRecipients(notice);
    if (!recipients.some((u) => String(u.user_id) === ownerId())) {
      recipients.unshift({ user_id: ownerId(), language: "uz", username: null });
    }

    const webAppUrl = process.env.WEBAPP_URL;
    const failed = [];
    let delivered = 0;
    for (const user of recipients) {
      const lang = user.language === "ru" ? "ru" : "uz";
      const markup = webAppUrl ? { inline_keyboard: [[{ text: BUTTON[lang], web_app: { url: webAppUrl } }]] } : undefined;
      const res = await telegram(user.user_id, NOTICE[lang], markup).catch((e) => ({ ok: false, error: e.message }));
      if (res.ok) delivered += 1;
      else failed.push(`${user.username ? `@${user.username}` : user.user_id}: ${res.error}`);
      await new Promise((r) => setTimeout(r, SEND_GAP_MS));
    }

    await alertOwner(
      `🔁 ${project}: karta avtomatik almashdi\n***${notice.from_last4} → ***${notice.to_last4}\n\n` +
        `Xabar: ${delivered}/${recipients.length} ta yetdi` +
        (failed.length ? `\nYetmadi:\n${failed.slice(0, 20).join("\n")}` : "")
    );
  }

  /** Avval band qilinadi: jarayon yiqilsa ham mijozga xabar ikki marta bormaydi */
  async function processDueNotices() {
    for (;;) {
      const r = await pool.query(
        `UPDATE card_switch_notices SET claimed_at = NOW()
          WHERE id = (
            SELECT id FROM card_switch_notices
             WHERE claimed_at IS NULL AND notify_after <= NOW()
             ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED
          )
          RETURNING *`
      );
      if (!r.rows.length) return;
      await sendNotice(r.rows[0]);
    }
  }

  /** Avtomatika HUMO'ga o'tkazgan bo'lsa: UZCARD dami tugashi bilan qaytaradi (+ mijozlarga xabar navbati) */
  async function maybeReturnFromHumo(now = new Date()) {
    const humo = getHumo();
    if (!humo) return null;
    const client = await pool.connect();
    let back = null;
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [ADVISORY_LOCK_KEY]);
      const flag = await client.query("SELECT value FROM settings WHERE key = $1", [`${settingKey}_auto_humo`]);
      if (flag.rows[0]?.value !== "1") {
        await client.query("COMMIT");
        return null;
      }
      const setting = await client.query("SELECT value FROM settings WHERE key = $1", [settingKey]);
      const activeSlot = normalizeSlot(setting.rows[0]?.value) || fallbackSlot();
      if (activeSlot !== humo.slot) {
        // Admin qo'lda boshqa kartaga o'tkazgan — avtomatika endi aralashmaydi
        await client.query("UPDATE settings SET value = '0', updated_at = NOW() WHERE key = $1", [`${settingKey}_auto_humo`]);
        await client.query("COMMIT");
        return null;
      }
      const state = await client.query("SELECT card_last4, limited_at FROM card_limit_state");
      const limitedAt = Object.fromEntries(state.rows.map((r) => [r.card_last4, new Date(r.limited_at)]));
      back = decideReturnFromHumo({ cards: listUzcards(), humo, activeSlot, limitedAt, now });
      if (back) {
        await client.query(
          `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
          [settingKey, back.slot]
        );
        await client.query("UPDATE settings SET value = '0', updated_at = NOW() WHERE key = $1", [`${settingKey}_auto_humo`]);
        await client.query(
          `INSERT INTO card_switch_notices (from_last4, to_last4, limit_at, notify_after)
           VALUES ($1, $2, NOW(), NOW() + ($3 * INTERVAL '1 millisecond'))`,
          [humo.last4, back.last4, NOTIFY_DELAY_MS]
        );
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      throw err;
    } finally {
      client.release();
    }
    if (back) console.log(`💳 HUMO ***${humo.last4} → UZCARD ***${back.last4} (dam tugadi)`);
    return back;
  }

  function startWorker() {
    const tick = () =>
      maybeReturnFromHumo()
        .catch((e) => console.error("❌ HUMO'dan qaytish:", e.message))
        .then(() => processDueNotices())
        .catch((e) => console.error("❌ Karta almashgani xabari:", e.message));
    tick();
    return setInterval(tick, WORKER_INTERVAL_MS);
  }

  return { ensureTables, handleSms, processDueNotices, maybeReturnFromHumo, startWorker };
}
