import {
  getPublicAppConfig,
  setMaintenance,
  setStarsPurchaseMode,
  setFragmentPaymentMethod,
  toPublicAppConfig,
  loadSettings,
} from "./settingsDb.js";

/**
 * Admin va mini-app sozlamalari — barchasi `settings` jadvalidan.
 */
export function registerSettingsRoutes(app, ctx) {
  const { pool, adminAuth } = ctx;

  app.get("/api/app-config", async (_req, res) => {
    try {
      res.json(await getPublicAppConfig(pool));
    } catch (err) {
      console.error("❌ /api/app-config:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.get("/api/maintenance", async (_req, res) => {
    try {
      const cfg = await getPublicAppConfig(pool);
      res.json({ maintenance: cfg.maintenance });
    } catch (err) {
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.get("/api/admin/settings", adminAuth, async (_req, res) => {
    try {
      const settings = await loadSettings(pool, true);
      res.json({ success: true, ...toPublicAppConfig(settings) });
    } catch (err) {
      console.error("❌ GET /api/admin/settings:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/admin/maintenance", adminAuth, async (req, res) => {
    try {
      const { enabled } = req.body;
      if (typeof enabled !== "boolean") {
        return res.status(400).json({ error: "enabled (true/false) kerak" });
      }
      const settings = await setMaintenance(pool, enabled);
      console.log(`🔧 Maintenance: ${enabled ? "YOQILDI" : "O'CHIRILDI"}`);
      res.json({ success: true, ...toPublicAppConfig(settings) });
    } catch (err) {
      console.error("❌ /api/admin/maintenance:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/admin/stars-purchase-mode", adminAuth, async (req, res) => {
    try {
      const mode = req.body?.mode;
      if (mode !== "fragment" && mode !== "paymee") {
        return res.status(400).json({ error: "mode: fragment | paymee" });
      }
      const settings = await setStarsPurchaseMode(pool, mode);
      console.log(`💎 stars_purchase_mode → ${settings.stars_purchase_mode}`);
      res.json({ success: true, ...toPublicAppConfig(settings) });
    } catch (err) {
      console.error("❌ stars-purchase-mode:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.post("/api/admin/fragment-payment-method", adminAuth, async (req, res) => {
    try {
      const pm = req.body?.payment_method ?? req.body?.method;
      if (pm !== "ton" && pm !== "usdt_ton" && pm !== "usdt") {
        return res.status(400).json({ error: "payment_method: ton | usdt_ton" });
      }
      const settings = await setFragmentPaymentMethod(pool, pm);
      console.log(`💰 fragment_payment_method → ${settings.fragment_payment_method}`);
      res.json({ success: true, ...toPublicAppConfig(settings) });
    } catch (err) {
      console.error("❌ fragment-payment-method:", err.message);
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  app.get("/api/admin/stars-purchase-mode", adminAuth, async (_req, res) => {
    try {
      res.json({ success: true, ...(await getPublicAppConfig(pool)) });
    } catch (err) {
      res.status(500).json({ error: "Server xatosi" });
    }
  });

  console.log("✅ settings moduli: settings jadvali, /api/app-config, /api/admin/settings");
}
