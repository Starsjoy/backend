/**
 * `settings` jadvali — admin panel switchlari (maintenance, purchase mode, payment method).
 * Fragment cookie lar `tokens` jadvalida qoladi.
 */

export const SETTING_KEYS = {
  MAINTENANCE: "maintenance",
  STARS_PURCHASE_MODE: "stars_purchase_mode",
  FRAGMENT_PAYMENT_METHOD: "fragment_payment_method",
  USERBOT_AUTO_REFILL: "userbot_auto_refill_enabled",
};

const DEFAULTS = {
  [SETTING_KEYS.MAINTENANCE]: "false",
  [SETTING_KEYS.STARS_PURCHASE_MODE]: "robynhood",
  [SETTING_KEYS.FRAGMENT_PAYMENT_METHOD]: "ton",
  [SETTING_KEYS.USERBOT_AUTO_REFILL]: "true",
};

/** Eski `tokens` jadvalidan bir martalik ko'chirish */
const LEGACY_TOKEN_KEYS = [
  SETTING_KEYS.STARS_PURCHASE_MODE,
  SETTING_KEYS.FRAGMENT_PAYMENT_METHOD,
];

let cache = null;
let cacheAt = 0;
const CACHE_TTL_MS = 3_000;

export function invalidateSettingsCache() {
  cache = null;
  cacheAt = 0;
}

export async function ensureSettingsTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key VARCHAR(64) PRIMARY KEY,
      value TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

async function getSettingRaw(pool, key) {
  const r = await pool.query(`SELECT value FROM settings WHERE key = $1`, [key]);
  return r.rows[0]?.value != null ? String(r.rows[0].value).trim() : null;
}

export async function setSetting(pool, key, value) {
  await pool.query(
    `INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [key, String(value ?? "").trim()]
  );
  invalidateSettingsCache();
}

export function normalizeStarsPurchaseMode(mode) {
  const m = String(mode || "robynhood").trim().toLowerCase();
  if (m === "fragment") return "fragment";
  if (m === "paymee") return "paymee";
  return "robynhood";
}

export function normalizeFragmentPaymentMethod(method) {
  const m = String(method || "ton").trim().toLowerCase();
  if (m === "usdt" || m === "usd" || m === "usdt-ton" || m === "usdt_ton") {
    return "usdt_ton";
  }
  return "ton";
}

export function fragmentPaymentMethodLabel(method) {
  return normalizeFragmentPaymentMethod(method) === "usdt_ton" ? "USDT TON" : "TON";
}

export function parseMaintenance(value) {
  if (value === true || value === 1) return true;
  const s = String(value ?? "").trim().toLowerCase();
  return s === "true" || s === "1" || s === "yes" || s === "on";
}

export function parseBoolSetting(value, defaultTrue = true) {
  if (value === true || value === 1) return true;
  if (value === false || value === 0) return false;
  const s = String(value ?? "").trim().toLowerCase();
  if (s === "true" || s === "1" || s === "yes" || s === "on") return true;
  if (s === "false" || s === "0" || s === "no" || s === "off") return false;
  return defaultTrue;
}

export async function loadSettings(pool, force = false) {
  if (!force && cache && Date.now() - cacheAt < CACHE_TTL_MS) {
    return { ...cache };
  }

  const keys = Object.values(SETTING_KEYS);
  const r = await pool.query(`SELECT key, value FROM settings WHERE key = ANY($1::text[])`, [
    keys,
  ]);

  const map = { ...DEFAULTS };
  for (const row of r.rows) {
    if (row.key) map[row.key] = String(row.value ?? "").trim();
  }

  const normalized = {
    maintenance: parseMaintenance(map[SETTING_KEYS.MAINTENANCE]),
    stars_purchase_mode: normalizeStarsPurchaseMode(map[SETTING_KEYS.STARS_PURCHASE_MODE]),
    fragment_payment_method: normalizeFragmentPaymentMethod(
      map[SETTING_KEYS.FRAGMENT_PAYMENT_METHOD]
    ),
    userbot_auto_refill_enabled: parseBoolSetting(
      map[SETTING_KEYS.USERBOT_AUTO_REFILL],
      true
    ),
  };

  cache = normalized;
  cacheAt = Date.now();
  return { ...normalized };
}

export function toPublicAppConfig(settings) {
  const mode = settings.stars_purchase_mode;
  const fragment = mode === "fragment";
  const paymee = mode === "paymee";
  let starsPath = "/stars";
  let premiumPath = "/premium";
  if (fragment) {
    starsPath = "/usdtstars";
    premiumPath = "/usdtpremium";
  } else if (paymee) {
    starsPath = "/paymeestars";
    premiumPath = "/paymeepremium";
  }
  return {
    maintenance: Boolean(settings.maintenance),
    stars_purchase_mode: mode,
    stars_purchase_path: starsPath,
    premium_purchase_path: premiumPath,
    fragment_payment_method: settings.fragment_payment_method,
    fragment_payment_label: fragmentPaymentMethodLabel(settings.fragment_payment_method),
  };
}

export async function getPublicAppConfig(pool) {
  const settings = await loadSettings(pool);
  return toPublicAppConfig(settings);
}

export async function setMaintenance(pool, enabled) {
  await setSetting(pool, SETTING_KEYS.MAINTENANCE, enabled ? "true" : "false");
  return loadSettings(pool, true);
}

export async function setStarsPurchaseMode(pool, mode) {
  const m = normalizeStarsPurchaseMode(mode);
  await setSetting(pool, SETTING_KEYS.STARS_PURCHASE_MODE, m);
  return loadSettings(pool, true);
}

export async function setFragmentPaymentMethod(pool, method) {
  const pm = normalizeFragmentPaymentMethod(method);
  await setSetting(pool, SETTING_KEYS.FRAGMENT_PAYMENT_METHOD, pm);
  return loadSettings(pool, true);
}

export async function setUserbotAutoRefill(pool, enabled) {
  await setSetting(pool, SETTING_KEYS.USERBOT_AUTO_REFILL, enabled ? "true" : "false");
  return loadSettings(pool, true);
}

/** `tokens` jadvalidagi eski kalitlardan `settings` ga ko'chirish */
export async function migrateSettingsFromTokensTable(pool) {
  let moved = 0;
  for (const key of LEGACY_TOKEN_KEYS) {
    const exists = await pool.query(`SELECT 1 FROM settings WHERE key = $1`, [key]);
    if (exists.rows.length) continue;

    const legacy = await pool.query(`SELECT value FROM tokens WHERE key = $1`, [key]);
    if (!legacy.rows.length) continue;

    await setSetting(pool, key, legacy.rows[0].value);
    moved++;
  }
  if (moved > 0) {
    console.log(`📦 settings: tokens jadvalidan ${moved} ta kalit ko'chirildi`);
  }
  return moved;
}

export async function seedSettingsFromEnvIfMissing(pool) {
  let seeded = 0;

  if ((await getSettingRaw(pool, SETTING_KEYS.STARS_PURCHASE_MODE)) == null) {
    const envMode = String(process.env.STARS_PURCHASE_MODE || "robynhood")
      .trim()
      .toLowerCase();
    const mode = normalizeStarsPurchaseMode(envMode);
    await setSetting(pool, SETTING_KEYS.STARS_PURCHASE_MODE, mode);
    seeded++;
  }

  if ((await getSettingRaw(pool, SETTING_KEYS.FRAGMENT_PAYMENT_METHOD)) == null) {
    const pm = normalizeFragmentPaymentMethod(process.env.FRAGMENT_PAYMENT_METHOD);
    await setSetting(pool, SETTING_KEYS.FRAGMENT_PAYMENT_METHOD, pm);
    seeded++;
  }

  if ((await getSettingRaw(pool, SETTING_KEYS.MAINTENANCE)) == null) {
    const m =
      process.env.MAINTENANCE_MODE === "true" || process.env.MAINTENANCE === "true";
    await setSetting(pool, SETTING_KEYS.MAINTENANCE, m ? "true" : "false");
    seeded++;
  }

  if ((await getSettingRaw(pool, SETTING_KEYS.USERBOT_AUTO_REFILL)) == null) {
    const on =
      process.env.USERBOT_AUTO_REFILL_ENABLED !== "false" &&
      process.env.USERBOT_AUTO_REFILL_ENABLED !== "0";
    await setSetting(pool, SETTING_KEYS.USERBOT_AUTO_REFILL, on ? "true" : "false");
    seeded++;
  }

  if (seeded > 0) {
    console.log(`📦 settings jadvali .env dan seed: ${seeded} ta kalit`);
  }
  return seeded;
}

export function getCachedSettings() {
  if (!cache) {
    return {
      maintenance: false,
      stars_purchase_mode: "robynhood",
      fragment_payment_method: "ton",
      userbot_auto_refill_enabled: true,
    };
  }
  return { ...cache };
}

export async function bootstrapSettings(pool) {
  await ensureSettingsTable(pool);
  await migrateSettingsFromTokensTable(pool);
  await seedSettingsFromEnvIfMissing(pool);
  return loadSettings(pool, true);
}
