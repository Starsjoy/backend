import {
  mapPaymeeSearchToProfile,
  searchPaymeeRecipient,
} from "../paymeeClient/index.js";

/**
 * POST /api/paymee-stars/search — StarsPaymee Partner API profil (rasm + ism)
 */
export async function paymeeStarsSearch(req, res) {
  try {
    const { username, stars } = req.body;
    if (!username) {
      return res.status(400).json({ error: "username kerak" });
    }

    const starsNum = parseInt(stars, 10);
    const quantity = Number.isInteger(starsNum) ? starsNum : 50;

    const { data, cleanUsername } = await searchPaymeeRecipient({
      productType: "stars",
      query: username,
      quantity,
    });

    const profile = mapPaymeeSearchToProfile(data, cleanUsername);
    if (!profile) {
      return res.status(404).json({
        error: "Foydalanuvchi topilmadi",
        details: data,
      });
    }

    return res.json(profile);
  } catch (err) {
    console.error("❌ /api/paymee-stars/search:", err.message);
    const status = err.status && err.status >= 400 && err.status < 600 ? err.status : 500;
    return res.status(status).json({
      error: err.message || "Qidiruvda xato",
    });
  }
}
