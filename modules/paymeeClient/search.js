import { partnerRequest, paymeeConfigured } from "./client.js";

/**
 * Partner API `found.photo` — HTML <img src="..."> yoki to'g'ridan URL.
 */
export function extractPhotoUrl(photoField) {
  if (!photoField) return null;
  const raw = String(photoField).trim();
  if (!raw) return null;
  if (/^https?:\/\//i.test(raw)) return raw;
  const match = raw.match(/src=["']([^"']+)["']/i);
  return match ? match[1] : null;
}

/**
 * @param {object} data — Partner { success, found: { name, photo, recipient, myself?, premium? } }
 * @param {string} cleanUsername
 */
export function mapPaymeeSearchToProfile(data, cleanUsername) {
  // Partner API yangi format: { success: true, found: {...} }.
  // Eski `ok` maydonini ham qabul qilamiz (orqaga moslik uchun).
  if ((data?.success !== true && data?.ok !== true) || !data?.found) {
    return null;
  }
  const found = data.found;
  const name = found.name || cleanUsername;
  const recipient = found.recipient || cleanUsername;
  const imageUrl = extractPhotoUrl(found.photo);

  return {
    username: cleanUsername,
    fullName: name,
    imageUrl,
    recipient,
    myself: Boolean(found.myself),
    // Premium qidiruvida: profil allaqachon Premium'ga egami (null = aniqlanmadi)
    premium: found.premium ?? null,
  };
}

/**
 * POST /search — Partner API (stars | premium)
 */
export async function searchPaymeeRecipient({
  productType,
  query,
  quantity,
  months,
}) {
  if (!paymeeConfigured()) {
    const err = new Error("STARS_PAYMEE_API_URL yoki STARS_PAYMEE_API_KEY .env da yo'q");
    err.status = 503;
    throw err;
  }

  const clean = String(query || "")
    .trim()
    .replace(/^@/, "");
  if (!clean) {
    const err = new Error("query (username) kerak");
    err.status = 400;
    throw err;
  }

  const body = {
    product_type: productType,
    query: clean,
  };

  if (productType === "stars") {
    const q = Number(quantity);
    body.quantity = String(Number.isFinite(q) && q >= 50 ? q : 50);
  } else if (productType === "premium") {
    const m = Number(months);
    body.months = String([3, 6, 12].includes(m) ? m : 3);
  }

  const data = await partnerRequest("/search", {
    method: "POST",
    body: JSON.stringify(body),
  });

  return { data, cleanUsername: clean };
}
