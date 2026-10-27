import crypto from "crypto";
import {
  REWARD_ORDER_PREFIX,
  getReferralSince,
  referralRewardForOrder,
  getDailyRedeemCapStars,
  getUserDailyRedeemLimit,
  isRewardOrder,
  isRewardsEnabledFor,
  rewardForOrder,
} from "./config.js";
import { applyLedgerEntry } from "./db.js";
import { MINI_APP_URL, getUserAppLanguage } from "../notifications/orderExpiredMessages.js";
import { escapeTelegramHtml } from "../usdtStars/fragmentNotify.js";
import {
  isFragmentCookieError,
  isFragmentPythonSetupError,
  isFragmentWalletConfigError,
} from "../usdtStars/fragmentDelivery.js";

/** Bonus yozilmaydigan to'lov turlari (tekin / ichki buyurtmalar) */
const NON_PAID_METHODS = ["bonus", "referral", "admin_manual"];
const DELIVERED = ["completed", "delivered"];

const CREDIT_TEXTS = {
  uz: {
    buyer: (n) => `🎁 Sizga +${n} ⭐ bonus berildi!\n\nBonuslarni ilovadagi «Bonuslar» bo'limida ko'rasiz va sovg'alarga almashtirasiz.`,
    friend: (n, u) => `👥 ${u ? `Do'stingiz @${u}` : "Do'stingiz"} xarid qildi, sizga +${n} ⭐ bonus berildi!\n\nBonuslarni ilovadagi «Bonuslar» bo'limida ko'rasiz.`,
    button: "🎁 Bonuslar",
  },
  ru: {
    buyer: (n) => `🎁 Вам начислено +${n} ⭐ бонуса!\n\nСмотрите их в разделе «Бонусы» в приложении и обменивайте на подарки.`,
    friend: (n, u) => `👥 ${u ? `Ваш друг @${u}` : "Ваш друг"} сделал покупку, вам начислено +${n} ⭐ бонуса!\n\nСмотрите в разделе «Бонусы» в приложении.`,
    button: "🎁 Бонусы",
  },
  en: {
    buyer: (n) => `🎁 You've received +${n} ⭐ bonus!\n\nFind it in the «Rewards» section of the app and exchange it for gifts.`,
    friend: (n, u) => `👥 ${u ? `Your friend @${u}` : "Your friend"} made a purchase, you've received +${n} ⭐ bonus!\n\nFind it in the «Rewards» section of the app.`,
    button: "🎁 Rewards",
  },
};

/** Bonus yozilgani haqida userga xabar (uning app tilida). Xato bo'lsa jim — bonus baribir yozilgan. */
async function notifyCredit({ pool, bot }, userId, kind, points, friendUsername = null) {
  if (!bot) return;
  try {
    const lang = await getUserAppLanguage(pool, userId);
    const tr = CREDIT_TEXTS[lang] || CREDIT_TEXTS.uz;
    const text = kind === "referral" ? tr.friend(points, friendUsername) : tr.buyer(points);
    await bot.telegram.sendMessage(userId, text, {
      reply_markup: { inline_keyboard: [[{ text: tr.button, url: MINI_APP_URL }]] },
    });
  } catch (err) {
    console.error(`⚠️ Bonus xabari yuborilmadi (user=${userId}):`, err.message);
  }
}

/** Xarid bonusi (va referal bonus) shuncha vaqtdan keyin yoziladi — ilovada ham, xabar ham shunda */
export const REWARD_CREDIT_DELAY_MS = 5 * 60 * 1000;

/**
 * Yetkazilgan buyurtmani bonus navbatiga qo'yadi (5 daqiqadan keyin runRewardsCreditJob yozadi).
 * Takroriy chaqiruv — o'zgarishsiz (order_id PRIMARY KEY).
 */
export async function creditRewardsForOrder(ctx, orderId) {
  const { pool } = ctx;
  if (!orderId) return;
  await pool.query(
    `INSERT INTO bonus_credit_queue (order_id, due_at) VALUES ($1, $2)
     ON CONFLICT (order_id) DO NOTHING`,
    [orderId, new Date(Date.now() + REWARD_CREDIT_DELAY_MS)]
  );
}

/** Har daqiqada: vaqti kelgan buyurtmalar uchun bonusni yozib, xabar yuboradi */
export async function runRewardsCreditJob(ctx) {
  const { pool } = ctx;
  const due = await pool.query(
    `SELECT order_id FROM bonus_credit_queue
     WHERE processed_at IS NULL AND due_at <= NOW() AND attempts < 5
     ORDER BY due_at LIMIT 50`
  );
  for (const row of due.rows) {
    // Atomik band qilish — bir nechta jarayon bo'lsa ham 1 marta
    const claim = await pool.query(
      `UPDATE bonus_credit_queue SET processed_at = NOW(), attempts = attempts + 1
       WHERE order_id = $1 AND processed_at IS NULL RETURNING order_id`,
      [row.order_id]
    );
    if (!claim.rowCount) continue;
    try {
      await processRewardsForOrder(ctx, row.order_id);
    } catch (err) {
      // Keyingi daqiqada qayta urinish (ledger ref_key tufayli ikki marta yozilmaydi)
      await pool.query(`UPDATE bonus_credit_queue SET processed_at = NULL WHERE order_id = $1`, [row.order_id]);
      console.error(`❌ Bonus navbati #${row.order_id}:`, err.message);
    }
  }
}

/**
 * Yetkazilgan buyurtma uchun xaridorga bonus + taklif qilgan do'stga referal bonus.
 * Idempotent: ref_key tufayli necha marta chaqirilsa ham 1 marta yoziladi.
 */
async function processRewardsForOrder(ctx, orderId) {
  const { pool } = ctx;
  if (!orderId) return;
  const r = await pool.query(
    `SELECT id, order_id, owner_user_id, order_type, type_amount, summ, payment_method, status
     FROM orders WHERE id = $1`,
    [orderId]
  );
  const order = r.rows[0];
  if (!order || !order.owner_user_id) return;
  if (!DELIVERED.includes(order.status)) return;
  if (Number(order.summ) <= 0) return;
  if (NON_PAID_METHODS.includes(String(order.payment_method || "").toLowerCase())) return;
  if (isRewardOrder(order)) return;

  const buyerId = String(order.owner_user_id);

  if (isRewardsEnabledFor(buyerId)) {
    const points = rewardForOrder(order);
    if (points > 0) {
      const res = await applyLedgerEntry(pool, {
        userId: buyerId,
        delta: points,
        kind: "purchase",
        refKey: `order:${order.id}`,
        orderId: order.id,
        meta: { order_type: order.order_type, type_amount: order.type_amount },
      });
      if (res) {
        console.log(`🎁 Bonus +${points}⭐: user=${buyerId}, order=#${order.id}`);
        // "yuborildi" xabaridan keyin — ikkinchi xabar
        await notifyCredit(ctx, buyerId, "purchase", points);
      }
    }
  }

  // Referal: taklif qilingan YANGI do'stning FAQAT birinchi xaridi — Stars (har 50⭐ → +3) yoki Premium (har oy → +1)
  const firstPurchase = await pool.query(
    `SELECT id FROM orders
     WHERE owner_user_id = $1 AND status = ANY($2::text[]) AND summ > 0
       AND COALESCE(LOWER(payment_method), '') <> ALL($3::text[])
       AND order_id NOT LIKE $4
     ORDER BY id LIMIT 1`,
    [buyerId, DELIVERED, NON_PAID_METHODS, `${REWARD_ORDER_PREFIX}%`]
  );
  if (firstPurchase.rows[0]?.id !== order.id) return;

  const referralPoints = referralRewardForOrder(order);
  if (referralPoints <= 0) return;

  const u = await pool.query(
    `SELECT username, referrer_user_id, created_at FROM users WHERE user_id = $1`,
    [buyerId]
  );
  const friend = u.rows[0];
  const referrerId = friend?.referrer_user_id ? String(friend.referrer_user_id) : null;
  if (!referrerId || referrerId === buyerId || !isRewardsEnabledFor(referrerId)) return;
  // Avvaldan StarsJoy foydalanuvchisi bo'lgan odam referal hisoblanmaydi
  if (!friend.created_at || new Date(friend.created_at) < getReferralSince()) return;

  const res = await applyLedgerEntry(pool, {
    userId: referrerId,
    delta: referralPoints,
    kind: "referral",
    // Bir do'st uchun umrida 1 marta (eski yozuvlar referral:order:<id> — ular 1-xariddan keyin yana yozilmaydi)
    refKey: `referral:friend:${buyerId}`,
    orderId: order.id,
    meta: { friend_username: u.rows[0]?.username || null, type_amount: order.type_amount },
  });
  if (res) {
    console.log(`🎁 Referal bonus +${referralPoints}⭐: referrer=${referrerId}, friend=${buyerId}, order=#${order.id}`);
    await notifyCredit(ctx, referrerId, "referral", referralPoints, friend.username || null);
  }
}

export class RedeemError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    this.extra = extra;
  }
}

/**
 * Balansdan atomik yechib olish va bonus buyurtmasini yaratish.
 * Global advisory lock: barcha yechib olishlar ketma-ket — balans ham, kunlik limitlar ham poyga holatisiz.
 */
export async function createRedemption(pool, { userId, username, item, starsOrderType }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('starsjoy:bonus:redeem'))`);

    const active = await client.query(
      `SELECT id FROM orders
       WHERE owner_user_id = $1 AND order_id LIKE $2 AND status IN ('pending', 'processing')
       LIMIT 1`,
      [userId, `${REWARD_ORDER_PREFIX}%`]
    );
    if (active.rowCount) {
      throw new RedeemError("in_progress", "Oldingi bonus hali yuborilmoqda");
    }

    // Avval balans (user uchun eng tushunarli xato); limitlar buzilsa ROLLBACK balansni qaytaradi
    const upd = await client.query(
      `UPDATE users SET bonus_balance = bonus_balance - $1
       WHERE user_id = $2 AND bonus_balance >= $1
       RETURNING bonus_balance`,
      [item.cost, userId]
    );
    if (!upd.rowCount) {
      throw new RedeemError("insufficient", "Balans yetarli emas");
    }

    const userToday = await client.query(
      `SELECT COUNT(*)::int AS n FROM bonus_ledger
       WHERE user_id = $1 AND kind = 'redeem' AND created_at > NOW() - INTERVAL '1 day'`,
      [userId]
    );
    if (userToday.rows[0].n >= getUserDailyRedeemLimit()) {
      throw new RedeemError("user_daily_limit", "Bugungi limit tugadi, ertaga urinib ko'ring");
    }

    const globalToday = await client.query(
      `SELECT COALESCE(-SUM(delta), 0)::int AS stars FROM bonus_ledger
       WHERE kind = 'redeem' AND created_at > NOW() - INTERVAL '1 day'`
    );
    if (globalToday.rows[0].stars + item.cost > getDailyRedeemCapStars()) {
      throw new RedeemError("global_daily_cap", "Hozircha bonus berish vaqtincha to'xtatilgan, keyinroq urinib ko'ring");
    }

    const isGift = item.kind === "gift";
    const orderRes = await client.query(
      `INSERT INTO orders
         (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount,
          summ, payment_method, payment_status, status, gift_id, gift_anonymous, gift_comment, created_at)
       VALUES ($1, $2, $3, $3, $4, $5, 0, 'bonus', 'paid', 'pending', $6, false, $7, NOW())
       RETURNING *`,
      [
        `${REWARD_ORDER_PREFIX}${crypto.randomUUID()}`,
        userId,
        username,
        isGift ? "gift" : starsOrderType,
        item.stars,
        isGift ? item.gift_id : null,
        isGift ? "StarsJoy bonus 🎁" : null,
      ]
    );
    const order = orderRes.rows[0];

    await client.query(
      `INSERT INTO bonus_ledger (user_id, delta, kind, ref_key, order_id, meta, seen)
       VALUES ($1, $2, 'redeem', $3, $4, $5, true)`,
      [userId, -item.cost, `redeem:${order.id}`, order.id, { item: item.id }]
    );

    await client.query("COMMIT");
    return { order, balance: upd.rows[0].bonus_balance };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

const REFUND_TEXTS = {
  uz: (n) => `⚠️ Bonusni yuborib bo'lmadi. ${n}⭐ balansingizga qaytarildi.\n\nBirozdan keyin qayta urinib ko'ring yoki @StarsjoySupport ga yozing.`,
  ru: (n) => `⚠️ Не удалось отправить бонус. ${n}⭐ возвращены на ваш баланс.\n\nПопробуйте позже или напишите в @StarsjoySupport.`,
  en: (n) => `⚠️ We couldn't send your bonus. ${n}⭐ has been returned to your balance.\n\nPlease try again later or contact @StarsjoySupport.`,
};

function itemLabel(order) {
  return order.order_type === "gift"
    ? `Gift (${order.type_amount} ⭐)`
    : `${order.type_amount} Stars`;
}

/**
 * Yetkazilmagan bonus buyurtmasini bekor qilib, ⭐ ni qaytaradi.
 * status='cancelled' — admin "qayta yuborish" ro'yxatiga tushmaydi (ikki marta berilmasin).
 */
export async function refundRedemption(ctx, orderId, { allowedStatuses = ["failed", "error", "expired"] } = {}) {
  const { pool, bot, notifyErrorChannel } = ctx;
  const cancelled = await pool.query(
    `UPDATE orders SET status = 'cancelled'
     WHERE id = $1 AND order_id LIKE $2 AND status = ANY($3::text[])
     RETURNING id, owner_user_id, recipient_username, order_type, type_amount`,
    [orderId, `${REWARD_ORDER_PREFIX}%`, allowedStatuses]
  );
  const order = cancelled.rows[0];
  if (!order) return false;

  const redeem = await pool.query(
    `SELECT -delta AS cost FROM bonus_ledger WHERE ref_key = $1`,
    [`redeem:${order.id}`]
  );
  const cost = Number(redeem.rows[0]?.cost) || 0;
  if (cost <= 0) return false;

  const res = await applyLedgerEntry(pool, {
    userId: String(order.owner_user_id),
    delta: cost,
    kind: "refund",
    refKey: `refund:${order.id}`,
    orderId: order.id,
  });
  if (!res) return false;

  console.log(`↩️ Bonus qaytarildi: +${cost}⭐ user=${order.owner_user_id}, order=#${order.id}`);

  try {
    const lang = await getUserAppLanguage(pool, order.owner_user_id);
    await bot?.telegram.sendMessage(order.owner_user_id, (REFUND_TEXTS[lang] || REFUND_TEXTS.uz)(cost));
  } catch {
    /* ignore */
  }
  notifyErrorChannel?.(
    `⚠️ <b>Bonus yetkazilmadi, balansga qaytarildi</b>\n\n` +
      `📦 Order: #${order.id}\n` +
      `👤 @${escapeTelegramHtml(order.recipient_username)}\n` +
      `💫 ${escapeTelegramHtml(itemLabel(order))} (${cost}⭐)`
  );
  return true;
}

/**
 * Yetkazishdan OLDIN pending → processing. reconcile faqat pending'ni qaytaradi, shuning uchun
 * yuborilayotgan (yoki yuborilib, server o'chib qolgan) buyurtma avtomatik qaytarilmaydi.
 * reconcile allaqachon bekor qilgan bo'lsa false — yuborilmaydi.
 */
export async function claimRedemption(pool, orderId) {
  const r = await pool.query(
    `UPDATE orders SET status = 'processing' WHERE id = $1 AND status = 'pending' RETURNING id`,
    [orderId]
  );
  return r.rowCount > 0;
}

/** Bu xatolar provayderga so'rov yetib bormasdan bo'ladi — hech narsa yuborilmagan, qaytarish xavfsiz */
function isNotSentError(err) {
  const msg = String(err?.message || "");
  return (
    err?.status === 401 ||
    err?.status === 503 ||
    msg.includes("STARS_PAYMEE_API_URL") ||
    isFragmentCookieError(msg) ||
    isFragmentWalletConfigError(msg) ||
    isFragmentPythonSetupError(msg)
  );
}

/**
 * Yetkazish xato bilan tugadi. Aniq yuborilmagan bo'lsa → failed (finalize qaytaradi).
 * Noaniq bo'lsa (masalan Paymee 500/502) processing'da qoladi — admin hal qiladi.
 */
export async function handleRedemptionError(pool, orderId, err) {
  if (!isNotSentError(err)) return;
  await pool.query(`UPDATE orders SET status = 'failed' WHERE id = $1 AND status = 'processing'`, [orderId]);
}

/** Yetkazish urinishidan keyin: natijaga qarab kanal xabari yoki qaytarish */
export async function finalizeRedemption(ctx, orderId) {
  const { pool, bot, notifyOrdersChannel, sendDeliveredOrderNotify } = ctx;
  const r = await pool.query(
    `SELECT o.id, o.owner_user_id, o.recipient_username, o.order_type, o.type_amount, o.status,
            u.username AS owner_username
     FROM orders o LEFT JOIN users u ON u.user_id = o.owner_user_id
     WHERE o.id = $1`,
    [orderId]
  );
  const order = r.rows[0];
  if (!order) return;

  if (DELIVERED.includes(order.status)) {
    const owner = String(order.owner_username || "").replace(/^@/, "");
    const recipient = String(order.recipient_username || "").replace(/^@/, "");
    const who =
      owner && owner.toLowerCase() !== recipient.toLowerCase()
        ? `@${escapeTelegramHtml(owner)} → @${escapeTelegramHtml(recipient)}`
        : `@${escapeTelegramHtml(recipient)}`;
    notifyOrdersChannel?.(
      `🎁 <b>User bonus oldi!</b>\n\n` +
        `📦 Order: #${order.id}\n` +
        `👤 ${who}\n` +
        `💫 ${escapeTelegramHtml(itemLabel(order))} (bonus balansdan)\n` +
        `✅ Status: Yetkazildi`
    );
    await sendDeliveredOrderNotify?.(pool, bot, order.id);
    return;
  }
  if (["failed", "error", "expired"].includes(order.status)) {
    await refundRedemption(ctx, order.id);
  }
  // pending/processing — noaniq holat (masalan, provayder javobi kelmadi): admin ko'radi,
  // ikki marta berilmasligi uchun avtomatik qaytarilmaydi.
}

/**
 * Davriy tekshiruv: server qayta ishga tushib qolgan yoki tugallanmay qolgan
 * bonus buyurtmalari (xato / 30 daqiqadan beri pending) — qaytariladi.
 */
export async function reconcileRedemptions(ctx) {
  const { pool } = ctx;
  const stuck = await pool.query(
    `SELECT o.id, o.status FROM orders o
     WHERE o.order_id LIKE $1
       AND (o.status IN ('failed', 'error', 'expired')
            OR (o.status = 'pending' AND o.created_at < NOW() - INTERVAL '30 minutes'))
       AND NOT EXISTS (SELECT 1 FROM bonus_ledger l WHERE l.ref_key = 'refund:' || o.id)
     LIMIT 20`,
    [`${REWARD_ORDER_PREFIX}%`]
  );
  for (const row of stuck.rows) {
    await refundRedemption(ctx, row.id, { allowedStatuses: ["failed", "error", "expired", "pending"] }).catch(
      (e) => console.error(`❌ Bonus reconcile #${row.id}:`, e.message)
    );
  }

  // processing'da qotganlar — yetkazilgan-yetkazilmagani noma'lum, admin'ga ogohlantirish (jarayon davomida 1 marta)
  const processing = await pool.query(
    `SELECT o.id, o.recipient_username, o.order_type, o.type_amount FROM orders o
     WHERE o.order_id LIKE $1 AND o.status = 'processing' AND o.created_at < NOW() - INTERVAL '30 minutes'
     LIMIT 20`,
    [`${REWARD_ORDER_PREFIX}%`]
  );
  for (const order of processing.rows) {
    if (alertedStuck.has(order.id)) continue;
    alertedStuck.add(order.id);
    ctx.notifyErrorChannel?.(
      `⏳ <b>Bonus yetkazilishi noaniq (processing)</b>\n\n` +
        `📦 Order: #${order.id}\n` +
        `👤 @${escapeTelegramHtml(order.recipient_username)}\n` +
        `💫 ${escapeTelegramHtml(itemLabel(order))}\n\n` +
        `Provayderda tekshiring va admin panel → Bonuslar → «Qotgan bonuslar» da hal qiling. ` +
        `Shu paytgacha user yangi bonus ololmaydi.`
    );
  }
}

const alertedStuck = new Set();

/**
 * Admin: processing'da qotgan bonus buyurtmasini hal qilish.
 *   refund    — yetkazilmagan: ⭐ qaytariladi
 *   delivered — provayderda yetkazilgani tasdiqlandi: completed
 */
export async function resolveStuckRedemption(ctx, orderId, action) {
  const { pool } = ctx;
  if (action === "refund") {
    return refundRedemption(ctx, orderId, { allowedStatuses: ["processing", "pending", "failed", "error", "expired"] });
  }
  if (action === "delivered") {
    const r = await pool.query(
      `UPDATE orders SET status = 'completed' WHERE id = $1 AND order_id LIKE $2 AND status IN ('processing', 'pending')
       RETURNING id`,
      [orderId, `${REWARD_ORDER_PREFIX}%`]
    );
    if (!r.rowCount) return false;
    alertedStuck.delete(orderId);
    return true;
  }
  return false;
}
