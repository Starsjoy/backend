import fetch from "node-fetch";
import { getBalanceCheckerUrl, getInternalSecret } from "./config.js";

/**
 * GramJS userbot stars balansi (balanceChecker).
 * @returns {Promise<number|null>}
 */
export async function fetchUserbotStarsBalance() {
  const secret = getInternalSecret();
  if (!secret) {
    console.warn("⚠️ userbot balance: INTERNAL_API_SECRET yo'q");
    return null;
  }

  try {
    const url = `${getBalanceCheckerUrl()}/api/userbot/stars-balance`;
    const response = await fetch(url, {
      method: "GET",
      headers: { "X-Internal-Key": secret },
    });
    const data = await response.json();
    if (!data?.success) {
      console.warn("⚠️ userbot balance:", data?.error || "success=false");
      return null;
    }
    const bal = Number(data.stars_balance);
    return Number.isFinite(bal) ? Math.floor(bal) : null;
  } catch (err) {
    console.error("❌ fetchUserbotStarsBalance:", err.message);
    return null;
  }
}
