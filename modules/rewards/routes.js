import {
  REFERRAL_REWARD_PER_50,
  REWARD_CATALOG,
  REWARD_ORDER_PREFIX,
  getCatalogItem,
  isRewardsEnabledFor,
  normalizeRecipientUsername,
} from "./config.js";
import { getBalance, getLedger, markSeen } from "./db.js";
import { buildReferralLink } from "../users/referralLink.js";
import { RedeemError, createRedemption, finalizeRedemption } from "./service.js";

const RULES = {
  stars_per_50: 2,
  premium_per_month: 1,
  gift: [
    { up_to: 25, reward: 1 },
    { up_to: 50, reward: 2 },
    { up_to: null, reward: 3 },
  ],
  referral: { per_50_stars: REFERRAL_REWARD_PER_50, per_premium_month: 1, new_users_only: true },
};

function tgUserId(req) {
  const id = req.telegramUser?.id;
  return id ? String(id) : null;
}

/** Yetkazish faqat initData'dagi HAQIQIY username'ga (o'ziga) */
function tgUsername(req) {
  return String(req.telegramUser?.username || "").replace(/^@/, "").trim();
}

/**
 * ctx: { pool, bot, telegramAuth, authLimiter, deliverRewardOrder(order),
 *        notifyOrdersChannel, notifyErrorChannel, sendDeliveredOrderNotify, getStarsOrderType() }
 */
export function registerRewardsRoutes(app, ctx) {
  const { pool, telegramAuth, authLimiter } = ctx;

  app.get("/api/rewards/status", telegramAuth, async (req, res) => {
    const userId = tgUserId(req);
    if (!userId) return res.status(401).json({ error: "Telegram autentifikatsiya kerak" });
    try {
      const enabled = isRewardsEnabledFor(userId);
      const [balance, ledger, active, user] = await Promise.all([
        getBalance(pool, userId),
        getLedger(pool, userId, 30),
        pool.query(
          `SELECT id, order_type, type_amount, status FROM orders
           WHERE owner_user_id = $1 AND order_id LIKE $2 AND status IN ('pending', 'processing')
           ORDER BY id DESC LIMIT 1`,
          [userId, `${REWARD_ORDER_PREFIX}%`]
        ),
        pool.query(`SELECT referral_code FROM users WHERE user_id = $1`, [userId]),
      ]);
      const code = user.rows[0]?.referral_code;
      res.json({
        enabled,
        balance,
        rules: RULES,
        catalog: REWARD_CATALOG.map(({ id, kind, cost, stars, gift_id }) => ({
          id,
          kind,
          cost,
          stars,
          gift_id: gift_id || null,
          can_redeem: enabled && balance >= cost,
        })),
        ledger,
        active_redemption: active.rows[0] || null,
        referral_link: buildReferralLink(code),
        has_username: Boolean(tgUsername(req)),
      });
    } catch (err) {
      console.error("❌ /api/rewards/status:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/rewards/seen", telegramAuth, async (req, res) => {
    const userId = tgUserId(req);
    const ledgerId = Number(req.body?.ledger_id);
    if (!userId) return res.status(401).json({ error: "Telegram autentifikatsiya kerak" });
    if (!Number.isInteger(ledgerId) || ledgerId <= 0) return res.status(400).json({ error: "ledger_id kerak" });
    try {
      await markSeen(pool, userId, ledgerId);
      res.json({ success: true });
    } catch (err) {
      console.error("❌ /api/rewards/seen:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/rewards/redeem", authLimiter, telegramAuth, async (req, res) => {
    const userId = tgUserId(req);
    if (!userId) return res.status(401).json({ error: "Telegram autentifikatsiya kerak" });
    if (!isRewardsEnabledFor(userId)) return res.status(403).json({ code: "disabled", error: "Bonuslar hali yoqilmagan" });

    const item = getCatalogItem(String(req.body?.item_id || ""));
    if (!item) return res.status(400).json({ code: "bad_item", error: "Noto'g'ri tanlov" });

    // Qabul qiluvchi: user tanlagan username, ko'rsatilmasa — o'zi (initData'dagi haqiqiy username)
    const rawRecipient = String(req.body?.recipient_username || "").trim();
    let username;
    if (rawRecipient) {
      username = normalizeRecipientUsername(rawRecipient);
      if (!username) {
        return res.status(400).json({ code: "bad_recipient", error: "Username noto'g'ri" });
      }
    } else {
      username = tgUsername(req);
      if (!username) {
        return res.status(400).json({ code: "need_username", error: "Qabul qiluvchi username'ini kiriting" });
      }
    }

    let created;
    try {
      created = await createRedemption(pool, {
        userId,
        username,
        item,
        starsOrderType: ctx.getStarsOrderType(),
      });
    } catch (err) {
      if (err instanceof RedeemError) {
        return res.status(400).json({ code: err.code, error: err.message, ...err.extra });
      }
      console.error(`❌ /api/rewards/redeem (user ${userId}):`, err.message);
      return res.status(500).json({ error: "Server xatosi" });
    }

    const { order, balance } = created;
    console.log(`🎁 Bonus yechib olish: #${order.id} @${username} (${userId}) → ${item.id} (-${item.cost}⭐)`);

    // Yetkazish fonda — natija /api/rewards/status orqali kuzatiladi
    (async () => {
      try {
        await ctx.deliverRewardOrder(order);
      } catch (err) {
        console.error(`❌ Bonus yetkazish #${order.id}:`, err?.message || err);
      }
      await finalizeRedemption(ctx, order.id).catch((e) =>
        console.error(`❌ Bonus finalize #${order.id}:`, e.message)
      );
    })();

    res.json({ success: true, order_id: order.id, item_id: item.id, balance });
  });
}
