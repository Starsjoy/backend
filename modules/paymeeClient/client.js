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
      "Partner API HTML qaytardi (frontend sahifa). STARS_PAYMEE_API_URL provider backend bo'lishi kerak — " +
        "masalan https://PROVIDER_HOST/api/purchase/v1 (starstg.uz faqat misol, nginx proxy kerak)."
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

/**
 * StarsPaymee Partner API (docs.md §4)
 */
export async function partnerRequest(path, options = {}) {
  const base = getBaseUrl();
  const apiKey = getApiKey();

  if (!base || !apiKey) {
    const err = new Error("STARS_PAYMEE_API_URL yoki STARS_PAYMEE_API_KEY .env da yo'q");
    err.status = 503;
    throw err;
  }

  const url = `${base}${path.startsWith("/") ? path : `/${path}`}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
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

export async function deliverStarsViaPaymeeApi(username, stars, orderId, idempotencyKey) {
  const clean = String(username || "").replace(/^@/, "").trim();
  const key = idempotencyKey || `starsjoy-stars-${orderId}`;
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
  const key = idempotencyKey || `starsjoy-premium-${orderId}`;
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
