import crypto from "crypto";
import { getMissionByLevel, getMissions, getMissionVerifyMs, getMissionVerifyHours } from "./config.js";
import { verifyMissionFriends } from "./verify.js";
import {
  attachOrder,
  cancelVerifyTimer,
  clearBaseline,
  countSubscribedFriends,
  loadUserMissions,
  markClaimed,
  revertClaim,
  setBaselineIfEmpty,
  startVerifyTimer,
  fetchMissionRow,
} from "./db.js";

const clamp = (n, min, max) => Math.min(Math.max(n, min), max);

/**
 * Missiya holatini hisoblab, yon effektlarni (baseline, timer) DB ga yozadi.
 *
 * Timerlar shu yerda boshqariladi — alohida cron kerak emas, chunki holat
 * faqat user status so'raganda yoki claim qilganda ahamiyatga ega.
 */
export async function refreshMissionState(ctx, userId, { forceVerify = false } = {}) {
  const { pool } = ctx;
  const MISSIONS = getMissions();
  const verifyMs = getMissionVerifyMs();
  const byLevel = await loadUserMissions(pool, userId);

  const activeLevel = MISSIONS.find((m) => !byLevel.get(m.level)?.claimed)?.level ?? null;

  // Kutish oynasi (completed_at) davomida va claim paytida: kanaldan chiqqan do'stlarni DB dan tushiramiz
  if (activeLevel !== null) {
    const row = byLevel.get(activeLevel);
    const pendingVerify = row?.completed_at && !row?.claimed;
    if (forceVerify || pendingVerify) {
      await verifyMissionFriends(ctx, userId);
    }
  }

  const friends = await countSubscribedFriends(pool, userId);

  const missions = [];
  let prevClaimed = true; // 1-missiya doim ochiq

  for (const m of MISSIONS) {
    const unlocked = prevClaimed;
    const isActive = m.level === activeLevel;
    let row = byLevel.get(m.level) || null;
    const claimed = !!row?.claimed;

    // Aktiv missiyaning baseline'i hali yo'q bo'lsa — hozirgi do'stlar soni snapshot qilinadi
    if (isActive && (!row || row.baseline_friends === null)) {
      row = await setBaselineIfEmpty(pool, userId, m.level, friends);
      byLevel.set(m.level, row);
    }

    const baseline = row?.baseline_friends ?? null;
    const progress = baseline === null ? 0 : clamp(friends - baseline, 0, m.required);

    let completedAt = row?.completed_at ? new Date(row.completed_at) : null;
    let friendsLeft = false;

    if (isActive && baseline !== null) {
      if (progress >= m.required && !completedAt) {
        const updated = await startVerifyTimer(pool, userId, m.level);
        if (updated) {
          completedAt = new Date(updated.completed_at);
          byLevel.set(m.level, updated);
          const next = getMissionByLevel(m.level + 1);
          if (next) {
            byLevel.set(next.level, await setBaselineIfEmpty(pool, userId, next.level, friends));
          }
        } else {
          const fresh = await fetchMissionRow(pool, userId, m.level);
          if (fresh?.completed_at) {
            completedAt = new Date(fresh.completed_at);
            byLevel.set(m.level, fresh);
          }
        }
      } else if (progress < m.required && completedAt) {
        // Do'stlar kanaldan chiqib ketdi → timer bekor, keyingi baseline ham bekor
        await cancelVerifyTimer(pool, userId, m.level);
        completedAt = null;
        friendsLeft = true;
        const next = getMissionByLevel(m.level + 1);
        if (next) {
          await clearBaseline(pool, userId, next.level);
          byLevel.set(next.level, { ...(byLevel.get(next.level) || {}), baseline_friends: null });
        }
      }
    }

    const verifyAt = completedAt ? new Date(completedAt.getTime() + verifyMs) : null;
    const waiting = !claimed && !!verifyAt && Date.now() < verifyAt.getTime();
    const canClaim = unlocked && !claimed && !!verifyAt && Date.now() >= verifyAt.getTime();

    missions.push({
      level: m.level,
      required: m.required,
      gift_id: String(m.gift_id),
      gift_stars: m.stars,
      label: m.label,
      progress,
      reached: progress >= m.required,
      completed: !!completedAt,
      claimed,
      can_claim: canClaim,
      locked: !unlocked,
      waiting,
      friends_left: friendsLeft,
      verify_at: verifyAt ? verifyAt.toISOString() : null,
    });

    prevClaimed = claimed;
  }

  return {
    friends,
    activeLevel,
    allClaimed: missions.every((m) => m.claimed),
    missions,
  };
}

function telegramUserId(req) {
  const id = req.telegramUser?.id;
  return id ? String(id) : null;
}

/** Gift username'ga yuboriladi, shuning uchun DB dagi `user_<id>` fallback emas,
 *  initData'dagi HAQIQIY username kerak. */
function telegramUsername(req) {
  return String(req.telegramUser?.username || "").replace(/^@/, "").trim();
}

export function registerMissionRoutes(app, ctx) {
  const { pool, telegramAuth, authLimiter, sendGiftToUser } = ctx;

  // ======================
  // 🎯 GET /api/bonus/status
  // ======================
  app.get("/api/bonus/status", telegramAuth, async (req, res) => {
    try {
      const userId = telegramUserId(req);
      if (!userId) return res.status(400).json({ error: "Telegram user_id kerak" });

      const state = await refreshMissionState(ctx, userId);

      res.json({
        success: true,
        active_level: state.activeLevel,
        all_claimed: state.allClaimed,
        current_friends: state.friends,
        verify_hours: getMissionVerifyHours(),
        username: telegramUsername(req) || null,
        missions: state.missions,
      });
    } catch (err) {
      console.error("❌ /api/bonus/status error:", err);
      res.status(500).json({ error: "Server xato" });
    }
  });

  // ======================
  // 🎁 POST /api/bonus/claim  { level }
  // ======================
  app.post("/api/bonus/claim", authLimiter, telegramAuth, async (req, res) => {
    const userId = telegramUserId(req);
    if (!userId) return res.status(400).json({ error: "Telegram user_id kerak" });

    const level = Number(req.body?.level);
    const mission = getMissionByLevel(level);
    if (!mission) return res.status(400).json({ error: "Missiya topilmadi" });

    const username = telegramUsername(req);
    if (!username) {
      return res.status(400).json({
        need_username: true,
        error: "Sovg'ani olish uchun Telegram username o'rnating",
      });
    }

    let claimedRow = null;
    try {
      // Claim paytida do'stlar MAJBURIY qayta tekshiriladi
      const state = await refreshMissionState(ctx, userId, { forceVerify: true });
      const mine = state.missions.find((m) => m.level === level);

      if (mine.locked) {
        return res.status(400).json({
          locked: true,
          required_level: level - 1,
          error: `Avval ${level - 1}-missiyani yakunlang`,
        });
      }
      if (mine.claimed) {
        return res.status(400).json({ already_claimed: true, error: "Sovg'a allaqachon olingan" });
      }
      if (mine.friends_left) {
        return res.status(400).json({
          friends_left: true,
          progress: mine.progress,
          required: mine.required,
          error: "Ba'zi do'stlaringiz kanaldan chiqdi",
        });
      }
      if (!mine.completed) {
        return res.status(400).json({
          not_reached: true,
          progress: mine.progress,
          required: mine.required,
          error: "Do'stlar soni yetarli emas",
        });
      }
      if (mine.waiting) {
        return res.status(400).json({
          waiting: true,
          verify_at: mine.verify_at,
          error: "Tekshiruv oynasi hali tugamadi",
        });
      }

      // Atomik: parallel so'rovlardan faqat bittasi 1 qator oladi
      claimedRow = await markClaimed(pool, userId, level);
      if (!claimedRow) {
        return res.status(400).json({ already_claimed: true, error: "Sovg'a allaqachon olingan" });
      }

      const orderRes = await pool.query(
        `INSERT INTO orders
           (order_id, owner_user_id, recipient_username, recipient, order_type, type_amount,
            summ, payment_method, payment_status, status, gift_id, gift_anonymous, gift_comment, created_at)
         VALUES ($1, $2, $3, $4, 'gift', $5, 0, 'bonus', 'completed', 'pending', $6, false, $7, NOW())
         RETURNING *`,
        [crypto.randomUUID(), userId, username, username, mission.stars, String(mission.gift_id), mission.comment]
      );
      const order = orderRes.rows[0];
      await attachOrder(pool, userId, level, order.id);

      console.log(`🎯 Missiya ${level} claim: @${username} (${userId}) → gift ${mission.gift_id} (${mission.stars}⭐)`);

      // Userbot orqali real gift. Xato bo'lsa throw qiladi → claim qaytariladi.
      await sendGiftToUser(order);

      return res.json({
        success: true,
        level,
        gift_id: String(mission.gift_id),
        gift_stars: mission.stars,
        message: "Sovg'angiz yuborildi!",
      });
    } catch (err) {
      console.error(`❌ /api/bonus/claim (level ${level}, user ${userId}) error:`, err?.message || err);
      if (claimedRow) {
        // Gift ketmadi — user qayta urinib ko'ra olsin
        await revertClaim(pool, userId, level).catch((e) =>
          console.error("⚠️ revertClaim xatosi:", e.message)
        );
      }
      return res.status(500).json({
        send_failed: true,
        error: "Sovg'ani yuborib bo'lmadi, birozdan keyin qayta urinib ko'ring",
      });
    }
  });
}
