import { normalizeFragmentPaymentMethod } from "../settings/settingsDb.js";

/** Fragment cookie kalitlari — `tokens` jadvalida saqlanadi */
export const FRAGMENT_TOKEN_KEYS = [  "fragment_dt",
  "fragment_ssid",
  "fragment_token",
  "fragment_ton_token",
];

const DEFAULTS = {
  fragment_dt: "-300",
  fragment_ssid: "",
  fragment_token: "",
  fragment_ton_token: "",
};

let cache = null;
let cacheAt = 0;
const CACHE_TTL_MS = 30_000;

export function invalidateFragmentTokenCache() {
  cache = null;
  cacheAt = 0;
}

/**
 * `tokens` jadvalidan Fragment cookie qiymatlarini o'qish.
 */
export async function getFragmentTokens(pool) {
  if (cache && Date.now() - cacheAt < CACHE_TTL_MS) {
    return { ...cache };
  }

  const result = await pool.query(
    `SELECT key, value FROM tokens WHERE key = ANY($1::text[])`,
    [FRAGMENT_TOKEN_KEYS]
  );

  const map = { ...DEFAULTS };
  for (const row of result.rows) {
    if (row.key && row.value != null) {
      map[row.key] = String(row.value).trim();
    }
  }

  cache = map;
  cacheAt = Date.now();
  return { ...map };
}

export function fragmentTokensReady(tokens) {
  return Boolean(tokens?.fragment_ssid && tokens?.fragment_token);
}

/** Server `.env` dagi Fragment cookie (FRAGMENT_* / STEL_*). */
export function getFragmentTokensFromEnv() {
  return {
    fragment_dt: (
      process.env.FRAGMENT_DT ||
      process.env.STEL_DT ||
      DEFAULTS.fragment_dt
    ).trim(),
    fragment_ssid: (
      process.env.FRAGMENT_SSID ||
      process.env.STEL_SSID ||
      ""
    ).trim(),
    fragment_token: (
      process.env.FRAGMENT_TOKEN ||
      process.env.STEL_TOKEN ||
      ""
    ).trim(),
    fragment_ton_token: (
      process.env.FRAGMENT_TON_TOKEN ||
      process.env.STEL_TON_TOKEN ||
      ""
    ).trim(),
  };
}

/**
 * @param {"env"|"db"|"auto"} source — `env`: faqat .env; `db`: tokens jadvali; `auto`: .env to'liq bo'lsa env, aks holda DB
 */
export async function resolveFragmentTokens(pool, source = "auto") {
  const envTokens = getFragmentTokensFromEnv();
  if (source === "env") {
    return { tokens: envTokens, source: "env" };
  }
  const dbTokens = await getFragmentTokens(pool);
  if (source === "db") {
    return { tokens: dbTokens, source: "db" };
  }
  if (fragmentTokensReady(envTokens)) {
    return { tokens: envTokens, source: "env" };
  }
  return { tokens: dbTokens, source: "db" };
}

/** Admin panel: .env kalitlari holati (maskalangan). */
export function getFragmentEnvDiagnostics() {
  let databaseHost = "(noma'lum)";
  try {
    databaseHost =
      new URL(process.env.DATABASE_URL || "").hostname || databaseHost;
  } catch {
    /* ignore */
  }

  const proxyRaw = (process.env.FRAGMENT_HTTP_PROXY || "").trim();
  return {
    has_seed: Boolean(process.env.SEED?.trim()),
    has_api_key: Boolean(process.env.API_KEY?.trim()),
    has_database_url: Boolean(process.env.DATABASE_URL?.trim()),
    database_host: databaseHost,
    wallet_type: (process.env.WALLET_TYPE || "").trim() || null,
    fragment_dt: process.env.FRAGMENT_DT || process.env.STEL_DT || DEFAULTS.fragment_dt,
    fragment_ssid: maskTokenValue(
      process.env.FRAGMENT_SSID || process.env.STEL_SSID
    ),
    fragment_token: maskTokenValue(
      process.env.FRAGMENT_TOKEN || process.env.STEL_TOKEN
    ),
    fragment_ton_token: maskTokenValue(
      process.env.FRAGMENT_TON_TOKEN || process.env.STEL_TON_TOKEN
    ),
    fragment_http_proxy: proxyRaw
      ? proxyRaw.replace(/:[^:@/]+@/, ":***@")
      : null,
  };
}

export function maskTokenValue(val, show = 4) {
  const v = String(val || "").trim();
  if (!v) return "(yo'q)";
  if (v.length <= show * 2) return `len=${v.length}`;
  return `${v.slice(0, show)}...${v.slice(-show)} (len=${v.length})`;
}

export function maskFragmentTokens(tokens) {
  return {
    fragment_dt: tokens.fragment_dt || DEFAULTS.fragment_dt,
    fragment_ssid: maskTokenValue(tokens.fragment_ssid),
    fragment_token: maskTokenValue(tokens.fragment_token),
    fragment_ton_token: maskTokenValue(tokens.fragment_ton_token),
  };
}

/** Lokal vs server token bir xilmi — uzunlik va bosh/oxir belgilar */
export function fragmentTokenFingerprint(tokens) {
  const fp = (v) => {
    const s = String(v || "").trim();
    if (!s) return { len: 0, head: "", tail: "" };
    return {
      len: s.length,
      head: s.slice(0, 6),
      tail: s.slice(-6),
    };
  };
  return {
    fragment_dt: tokens.fragment_dt || DEFAULTS.fragment_dt,
    fragment_ssid: fp(tokens.fragment_ssid),
    fragment_token: fp(tokens.fragment_token),
    fragment_ton_token: fp(tokens.fragment_ton_token),
    has_ton_token: Boolean(String(tokens.fragment_ton_token || "").trim()),
  };
}

/**
 * Jadval bo'sh bo'lsa .env dan bir martalik seed (migratsiya).
 */
/** DB da fragment cookie bo'sh, .env da to'liq bo'lsa — DB ga yozish (yetkazish uchun). */
export async function syncFragmentTokensFromEnvIfMissing(pool) {
  const db = await getFragmentTokens(pool);
  if (fragmentTokensReady(db)) return false;

  const env = getFragmentTokensFromEnv();
  if (!fragmentTokensReady(env)) return false;

  await setFragmentTokens(pool, env);
  console.log("📦 Fragment cookie .env dan tokens jadvaliga nusxalandi");
  return true;
}

export async function seedFragmentTokensFromEnvIfEmpty(pool) {
  const countRes = await pool.query("SELECT COUNT(*)::int AS c FROM tokens");
  if (countRes.rows[0].c > 0) {
    await syncFragmentTokensFromEnvIfMissing(pool);
    return false;
  }

  const envMap = {
    fragment_dt: process.env.FRAGMENT_DT || process.env.STEL_DT || DEFAULTS.fragment_dt,
    fragment_ssid: process.env.FRAGMENT_SSID || process.env.STEL_SSID || "",
    fragment_token: process.env.FRAGMENT_TOKEN || process.env.STEL_TOKEN || "",
    fragment_ton_token:
      process.env.FRAGMENT_TON_TOKEN || process.env.STEL_TON_TOKEN || "",
  };

  for (const key of FRAGMENT_TOKEN_KEYS) {
    await pool.query(
      `INSERT INTO tokens (key, value, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO NOTHING`,
      [key, envMap[key] || ""]
    );
  }

  invalidateFragmentTokenCache();
  console.log("📦 tokens jadvali .env dan birinchi marta to'ldirildi");
  return true;
}

export async function setFragmentTokens(pool, data) {
  for (const key of FRAGMENT_TOKEN_KEYS) {
    if (data[key] === undefined) continue;
    await pool.query(
      `INSERT INTO tokens (key, value, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [key, String(data[key] ?? "").trim()]
    );
  }
  invalidateFragmentTokenCache();
}

/** Python subprocess uchun env obyekti */
export function fragmentTokensToProcessEnv(baseEnv, tokens, paymentMethod) {
  const pm = normalizeFragmentPaymentMethod(
    paymentMethod ?? baseEnv.FRAGMENT_PAYMENT_METHOD
  );
  return {
    ...baseEnv,
    FRAGMENT_DT: tokens.fragment_dt || DEFAULTS.fragment_dt,
    FRAGMENT_SSID: tokens.fragment_ssid || "",
    FRAGMENT_TOKEN: tokens.fragment_token || "",
    FRAGMENT_TON_TOKEN: tokens.fragment_ton_token || "",
    FRAGMENT_USE_DB_TOKENS: "1",
    FRAGMENT_PAYMENT_METHOD: pm,
  };
}

export async function ensureTokensTable(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tokens (
      key VARCHAR(64) PRIMARY KEY,
      value TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

