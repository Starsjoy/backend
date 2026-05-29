import fetch from "node-fetch";

function getBaseUrl() {
  return String(process.env.STARS_PAYMEE_API_URL || "").replace(/\/$/, "");
}

function getApiKey() {
  return String(process.env.STARS_PAYMEE_API_KEY || "").trim();
}

export function paymeeConfigured() {
  return Boolean(getBaseUrl() && getApiKey());
}

function looksLikeHtml(text) {
  const t = String(text || "").trim().toLowerCase();
  return t.startsWith("<!doctype") || t.startsWith("<html") || t.includes("<head>");
}

function parsePartnerJson(rawText) {
  const raw = String(rawText || "").trim();
  if (!raw) return {};
  if (looksLikeHtml(raw)) {
    const err = new Error(
      "Partner API HTML qaytardi. STARS_PAYMEE_API_URL=https://starspaymee.starstg.uz/api/purchase/v1 " +
        "bo'lishi kerak (starstg.uz emas — docs-partner-api.md §2.2)."
    );
    err.status = 502;
    err.body = { _html: true, _raw: raw.slice(0, 200) };
    throw err;
  }
  try {
    return JSON.parse(raw);
  } catch {
    const err = new Error(`Partner API JSON emas: ${raw.slice(0, 120)}`);
    err.status = 502;
    err.body = { _raw: raw.slice(0, 300) };
    throw err;
  }
}

const PARTNER_FETCH_TIMEOUT_MS = 120_000;

/**
 * StarsPaymee Partner API — docs-partner-api.md
 */
export async function partnerRequest(path, options = {}) {
  const base = getBaseUrl();
  const apiKey = getApiKey();

  if (!base || !apiKey) {
    const err = new Error("STARS_PAYMEE_API_URL yoki STARS_PAYMEE_API_KEY .env da yo'q");
    err.status = 503;
    throw err;
  }

  if (/starstg\.uz/i.test(base) && !/starspaymee\.starstg\.uz/i.test(base)) {
    console.warn(
      "⚠️ STARS_PAYMEE_API_URL starstg.uz ga ishora qiladi — starspaymee.starstg.uz ishlating"
    );
  }

  const url = `${base}${path.startsWith("/") ? path : `/${path}`}`;
  const res = await fetch(url, {
    ...options,
    redirect: "follow",
    timeout: PARTNER_FETCH_TIMEOUT_MS,
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-API-Key": apiKey,
      ...(options.headers || {}),
    },
  });

  const rawText = await res.text();
  const data = parsePartnerJson(rawText);

  if (!res.ok) {
    const err = new Error(
      data.error || data.message || `HTTP ${res.status}${data._raw ? ` — ${data._raw}` : ""}`
    );
    err.status = res.status;
    err.body = data;
    console.error(`❌ Paymee API ${res.status} ${path}:`, JSON.stringify(data).slice(0, 500));
    throw err;
  }

  if (data.success === false) {
    const err = new Error(
      data.error ||
        data.error_message ||
        `Partner status=${data.status || "failed"} (order_id=${data.order_id ?? "?"})`
    );
    err.status = res.status;
    err.body = data;
    console.error(`❌ Paymee API 200 success=false ${path}:`, JSON.stringify(data).slice(0, 500));
    throw err;
  }

  return data;
}

/** Muvaffaqiyat: success:true yoki completed + transaction_id */
export function isPartnerPurchaseSuccess(data) {
  if (!data || typeof data !== "object") return false;
  if (data.success === true) return true;
  if (data.status === "completed" && data.transaction_id) return true;
  return false;
}

export function shouldRetryPaymeePurchase(err) {
  if (!err) return false;
  if (err.status === 502 || err.status === 500) return true;
  if (err.status === 200 && err.body?.status === "failed") return true;
  return false;
}

export async function checkPaymeeHealth() {
  return partnerRequest("/health");
}

/** Ishga tushishda: URL haqiqatan Partner API ekanini tekshiradi */
export async function verifyPaymeeApiReachable() {
  if (!paymeeConfigured()) {
    return { ok: false, error: "STARS_PAYMEE_API_URL yoki API_KEY yo'q" };
  }
  const base = getBaseUrl();
  try {
    const health = await checkPaymeeHealth();
    if (health?.success !== true) {
      return {
        ok: false,
        error: `Health javob noto'g'ri: ${JSON.stringify(health).slice(0, 200)}`,
        url: base,
      };
    }
    return { ok: true, url: base, fragment_ready: health.fragment_ready };
  } catch (err) {
    return { ok: false, error: err.message, url: base, body: err.body };
  }
}

export async function getPaymeeBalance() {
  return partnerRequest("/balance");
}

export async function getPaymeePricing() {
  return partnerRequest("/pricing");
}

/** Paymee USDT kreditidan nechta stars yetadi — GET /pricing `stars.usdt_per_star` */
export function availableStarsFromPaymeeBalance(balanceUsdt, usdtPerStar) {
  const bal = Number(balanceUsdt);
  const rate = Number(usdtPerStar);
  if (!Number.isFinite(bal) || bal <= 0 || !Number.isFinite(rate) || rate <= 0) {
    return 0;
  }
  return Math.floor(bal / rate);
}

export async function getPaymeeWalletSummary() {
  if (!paymeeConfigured()) {
    return { configured: false };
  }
  try {
    const [balance, pricing] = await Promise.all([
      getPaymeeBalance(),
      getPaymeePricing(),
    ]);
    const balanceUsdt = Number(balance.balance_usdt) || 0;
    const usdtPerStar = Number(pricing?.stars?.usdt_per_star) || 0;
    const availableStars = availableStarsFromPaymeeBalance(balanceUsdt, usdtPerStar);
    return {
      configured: true,
      success: true,
      balance_usdt: balanceUsdt,
      currency: balance.currency || "USDT",
      usdt_per_star: usdtPerStar,
      available_stars: availableStars,
      stars_min: pricing?.stars?.min ?? 50,
      stars_max: pricing?.stars?.max ?? 10000,
    };
  } catch (err) {
    return {
      configured: true,
      success: false,
      error: err.message,
      status: err.status,
    };
  }
}

export async function deliverStarsViaPaymeeApi(username, stars, orderId, idempotencyKey) {
  const clean = String(username || "").replace(/^@/, "").trim();
  const key = idempotencyKey || `paymee-stars-${orderId}`;
  return partnerRequest("/stars", {
    method: "POST",
    body: JSON.stringify({
      username: clean,
      stars: Number(stars),
      idempotency_key: key,
    }),
  });
}

export async function deliverPremiumViaPaymeeApi(username, months, orderId, idempotencyKey) {
  const clean = String(username || "").replace(/^@/, "").trim();
  const key = idempotencyKey || `paymee-premium-${orderId}`;
  return partnerRequest("/premium", {
    method: "POST",
    body: JSON.stringify({
      username: clean,
      months: Number(months),
      idempotency_key: key,
    }),
  });
}

export function isPaymeeBalanceError(err) {
  return err?.status === 402;
}

export function isPaymeeConfigError(err) {
  return err?.status === 401 || err?.status === 503;
}

export function isPaymeeRetryableError(err) {
  return err?.status === 502 || err?.status === 500;
}
