import { getCachedSettings, loadSettings, setUserbotAutoRefill } from "../settings/settingsDb.js";
import { fetchUserbotStarsBalance } from "./balance.js";
import { getUserbotRefillPublicConfig } from "./service.js";
import { listRefills } from "./db.js";

export function registerUserbotStarRefillRoutes(app, ctx) {
  const { pool, adminAuth } = ctx;

  app.get("/api/admin/userbot-refill/status", adminAuth, async (_req, res) => {
    try {
      const settings = await loadSettings(pool, true);
      const balance = await fetchUserbotStarsBalance();
      const cfg = getUserbotRefillPublicConfig();

      res.json({
        success: true,
        enabled: Boolean(settings.userbot_auto_refill_enabled),
        bot_stars_balance: balance,
        ...cfg,
      });
    } catch (err) {
      console.error("❌ GET userbot-refill/status:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/admin/userbot-refill/toggle", adminAuth, async (req, res) => {
    try {
      const { enabled } = req.body;
      if (typeof enabled !== "boolean") {
        return res.status(400).json({ error: "enabled (true/false) kerak" });
      }
      await setUserbotAutoRefill(pool, enabled);
      const balance = await fetchUserbotStarsBalance();
      res.json({
        success: true,
        enabled,
        bot_stars_balance: balance,
        ...getUserbotRefillPublicConfig(),
      });
    } catch (err) {
      console.error("❌ POST userbot-refill/toggle:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.get("/api/admin/userbot-refill/history", adminAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit, 10) || 20;
      const rows = await listRefills(pool, limit);
      res.json({ success: true, refills: rows });
    } catch (err) {
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  console.log(
    "✅ userbotStarRefill: /api/admin/userbot-refill/status, toggle, history"
  );
}
