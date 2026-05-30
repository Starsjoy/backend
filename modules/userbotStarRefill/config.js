/** Userbot stars minimal balans (.env GIFT_BALANCE) */
export function getGiftBalanceMin() {
  const n = parseInt(process.env.GIFT_BALANCE, 10);
  return Number.isFinite(n) && n > 0 ? n : 200;
}

export function getRefillStarsAmount() {
  const n = parseInt(process.env.GIFT_REFILL_STARS, 10);
  return Number.isFinite(n) && n >= 50 ? n : 50;
}

export function getRefillRecipientUsername() {
  const raw = String(process.env.GIFT_REFILL_USERNAME || "StarsjoySupport")
    .trim()
    .replace(/^@/, "");
  return raw || "StarsjoySupport";
}

export function getRefillCooldownMs() {
  const n = parseInt(process.env.GIFT_REFILL_COOLDOWN_MS, 10);
  return Number.isFinite(n) && n >= 60_000 ? n : 3 * 60 * 1000;
}

export function getBalanceCheckerUrl() {
  return process.env.BALANCE_CHECKER_URL || "http://localhost:5002";
}

export function getInternalSecret() {
  return process.env.INTERNAL_API_SECRET || "";
}
