import fetch from "node-fetch";

const DEFAULT_BASE = "https://robynhood.parssms.info";
const ROBYN_FETCH_TIMEOUT_MS = 120_000;

function getBaseUrl() {
  return String(process.env.ROBYNHOOD_API_URL || DEFAULT_BASE).replace(/\/$/, "");
}

function getApiKey() {
  return String(process.env.ROB_API_KEY || "").trim();
}

export function robynhoodConfigured() {
  return Boolean(getApiKey());
}

function parseRobynJson(rawText) {
  const raw = String(rawText || "").trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    const err = new Error(`RobynHood API JSON emas: ${raw.slice(0, 120)}`);
    err.status = 502;
    err.body = { _raw: raw.slice(0, 300) };
    throw err;
  }
}

/**
 * RobynHood Merchant API — POST/GET /api/purchase*
 */
export async function robynRequest(method, path, options = {}) {
  const apiKey = getApiKey();
  if (!apiKey) {
    const err = new Error("ROB_API_KEY .env da yo'q");
    err.status = 503;
    throw err;
  }

  const base = getBaseUrl();
  const url = `${base}${path.startsWith("/") ? path : `/${path}`}`;
  const init = {
    method,
    redirect: "follow",
    timeout: ROBYN_FETCH_TIMEOUT_MS,
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-API-Key": apiKey,
      ...(options.headers || {}),
    },
  };

  if (options.body !== undefined) {
    init.body =
      typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }

  let res;
  try {
    res = await fetch(url, init);
  } catch (fetchErr) {
    const err = new Error(`RobynHood tarmoq xatosi: ${fetchErr.message}`);
    err.status = 502;
    err.cause = fetchErr;
    throw err;
  }

  const rawText = await res.text();
  const data = parseRobynJson(rawText);

  if (!res.ok) {
    const err = new Error(
      data.error ||
        data.message ||
        data.detail ||
        `HTTP ${res.status}${data._raw ? ` — ${data._raw}` : ""}`
    );
    err.status = res.status;
    err.body = data;
    throw err;
  }

  return data;
}

export function robynIdempotencyKey(productType, orderId) {
  const t = String(productType || "stars").toLowerCase();
  return `starsjoy-robyn-${t}-${orderId}`;
}

export function isRobynPurchaseSuccess(data) {
  if (!data || typeof data !== "object") return false;
  if (!data.transaction_id) return false;
  const st = String(data.status || "completed").toLowerCase();
  if (st === "failed" || st === "error") return false;
  return true;
}

export function isRobynPurchaseFailed(data) {
  if (!data || typeof data !== "object") return false;
  const st = String(data.status || "").toLowerCase();
  return st === "failed" || st === "error";
}

function isRecoverableRobynError(err) {
  if (!err) return false;
  if (err.status === 502 || err.status === 500 || err.status === 504) return true;
  if (!err.status && /tarmoq|timeout|ECONNRESET|ETIMEDOUT/i.test(err.message)) return true;
  return false;
}

/** GET /api/purchase/by-idempotency-key/{key} — 404 → null */
export async function getPurchaseByIdempotencyKey(key) {
  const encoded = encodeURIComponent(String(key));
  try {
    return await robynRequest(
      "GET",
      `/api/purchase/by-idempotency-key/${encoded}`
    );
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
}

/** GET /api/purchase/transaction/{id} */
export async function getRobynTransaction(transactionId) {
  const encoded = encodeURIComponent(String(transactionId));
  return robynRequest("GET", `/api/purchase/transaction/${encoded}`);
}

/** GET /api/purchase/history?limit=&offset= */
export async function getRobynPurchaseHistory(limit = 50, offset = 0) {
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.max(Number(offset) || 0, 0);
  return robynRequest(
    "GET",
    `/api/purchase/history?limit=${lim}&offset=${off}`
  );
}

export async function getRobynBalance() {
  return robynRequest("GET", "/api/balance");
}

export async function getRobynStarsPrice(quantity = 50) {
  return robynRequest(
    "GET",
    `/api/prices?product_type=stars&quantity=${Number(quantity) || 50}`
  );
}

/**
 * POST /api/purchase + timeout da GET by-idempotency-key orqali tiklash.
 */
export async function executeRobynPurchase(purchaseBody, idempotencyKey) {
  const key = idempotencyKey || purchaseBody.idempotency_key;
  if (!key) {
    const err = new Error("idempotency_key majburiy");
    err.status = 400;
    throw err;
  }

  const existing = await getPurchaseByIdempotencyKey(key);
  if (existing) {
    if (isRobynPurchaseSuccess(existing)) {
      return { ...existing, _recovered: "idempotency_lookup" };
    }
    if (isRobynPurchaseFailed(existing)) {
      const err = new Error(
        existing.error_message || existing.error || "RobynHood purchase failed"
      );
      err.status = 400;
      err.body = existing;
      throw err;
    }
  }

  const body = { ...purchaseBody, idempotency_key: key };

  try {
    const data = await robynRequest("POST", "/api/purchase", { body });
    if (isRobynPurchaseSuccess(data)) return data;
    if (isRobynPurchaseFailed(data)) {
      const err = new Error(
        data.error_message || data.error || "RobynHood purchase failed"
      );
      err.status = 400;
      err.body = data;
      throw err;
    }
    if (!data.transaction_id) {
      const err = new Error(
        data.error_message || data.error || JSON.stringify(data).slice(0, 200)
      );
      err.status = 400;
      err.body = data;
      throw err;
    }
    return data;
  } catch (postErr) {
    if (!isRecoverableRobynError(postErr)) throw postErr;
    console.warn(
      `⚠️ Robyn POST xato (${postErr.message}), idempotency tekshirilmoqda: ${key}`
    );
    const recovered = await getPurchaseByIdempotencyKey(key);
    if (recovered && isRobynPurchaseSuccess(recovered)) {
      return { ...recovered, _recovered: "after_post_error" };
    }
    throw postErr;
  }
}

export async function purchaseRobynStars(orderId, recipient, quantity) {
  const key = robynIdempotencyKey("stars", orderId);
  return executeRobynPurchase(
    {
      product_type: "stars",
      recipient: String(recipient),
      quantity: String(quantity),
    },
    key
  );
}

export async function purchaseRobynPremium(orderId, recipient, months) {
  const key = robynIdempotencyKey("premium", orderId);
  return executeRobynPurchase(
    {
      product_type: "premium",
      recipient: String(recipient),
      months: String(months),
    },
    key
  );
}

export async function purchaseRobynGift(orderId, recipient, giftId, quantity) {
  const key = robynIdempotencyKey("gift", orderId);
  return executeRobynPurchase(
    {
      product_type: "gift",
      recipient: String(recipient),
      gift_id: giftId,
      quantity: String(quantity),
    },
    key
  );
}

/** Buyurtma turi → Robyn product_type */
export function robynProductTypeForOrder(order) {
  const ot = String(order?.order_type || "").toLowerCase();
  if (ot.includes("premium")) return "premium";
  if (ot.includes("gift")) return "gift";
  return "stars";
}

export async function syncRobynOrderFromProvider(order) {
  const productType = robynProductTypeForOrder(order);
  const key = robynIdempotencyKey(productType, order.id);
  const remote = await getPurchaseByIdempotencyKey(key);
  if (!remote) {
    return { found: false, idempotency_key: key, remote: null };
  }
  return {
    found: true,
    idempotency_key: key,
    remote,
    completed: isRobynPurchaseSuccess(remote),
    failed: isRobynPurchaseFailed(remote),
  };
}

export async function verifyRobynhoodApiReachable() {
  if (!robynhoodConfigured()) {
    return { ok: false, error: "ROB_API_KEY yo'q" };
  }
  try {
    const balance = await getRobynBalance();
    return { ok: true, url: getBaseUrl(), balance };
  } catch (err) {
    return { ok: false, error: err.message, url: getBaseUrl(), body: err.body };
  }
}
