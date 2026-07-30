const VALID_LANGUAGES = ["uz", "en", "ru"];

export function normalizeLanguage(code) {
  const lang = String(code || "uz").trim().toLowerCase();
  return VALID_LANGUAGES.includes(lang) ? lang : "uz";
}

export async function ensureUserPreferenceColumns(pool) {
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS language_selected BOOLEAN DEFAULT false`
  );
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT false`
  );
  await pool.query(
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS bonus_ad_shown BOOLEAN DEFAULT false`
  );
}

export async function grandfatherExistingUserPreferences(pool) {
  try {
    const flag = await pool.query(
      `SELECT value FROM settings WHERE key = 'user_prefs_grandfathered'`
    );
    if (!flag.rows.length) {
      await pool.query(`
        UPDATE users
        SET language_selected = true,
            onboarding_completed = true
      `);
      await pool.query(
        `INSERT INTO settings (key, value, updated_at)
         VALUES ('user_prefs_grandfathered', 'true', NOW())
         ON CONFLICT (key) DO NOTHING`
      );
      console.log("✅ Mavjud foydalanuvchilar uchun til/onboarding bir martalik belgilandi");
    }

    // Mustaqil flag: agar yuqoridagi grandfather allaqachon (oldinroq) ishlab bo'lgan bo'lsa ham,
    // bonus reklama ustuni YANGI qo'shilgani uchun mavjud userlarga alohida bir marta belgilanadi —
    // aks holda ular "yangi user" sifatida reklamani ko'rib qolar edi.
    const bonusFlag = await pool.query(
      `SELECT value FROM settings WHERE key = 'bonus_ad_grandfathered'`
    );
    if (!bonusFlag.rows.length) {
      await pool.query(`UPDATE users SET bonus_ad_shown = true`);
      await pool.query(
        `INSERT INTO settings (key, value, updated_at)
         VALUES ('bonus_ad_grandfathered', 'true', NOW())
         ON CONFLICT (key) DO NOTHING`
      );
      console.log("✅ Mavjud foydalanuvchilar uchun bonus reklama bir martalik belgilandi");
    }
  } catch (err) {
    console.warn("⚠️ user_prefs grandfather:", err.message);
  }
}

export async function getUserPreferences(pool, userId) {
  const uid = String(userId || "").trim();
  if (!uid) {
    return {
      language: "uz",
      language_selected: false,
      onboarding_completed: false,
      bonus_ad_shown: false,
      exists: false,
    };
  }

  const r = await pool.query(
    `SELECT language, language_selected, onboarding_completed, bonus_ad_shown
     FROM users WHERE user_id = $1`,
    [uid]
  );

  if (!r.rows.length) {
    return {
      language: "uz",
      language_selected: false,
      onboarding_completed: false,
      bonus_ad_shown: false,
      exists: false,
    };
  }

  const row = r.rows[0];
  return {
    language: normalizeLanguage(row.language),
    language_selected: Boolean(row.language_selected),
    onboarding_completed: Boolean(row.onboarding_completed),
    bonus_ad_shown: Boolean(row.bonus_ad_shown),
    exists: true,
  };
}

export async function setUserLanguage(pool, userId, language) {
  const uid = String(userId || "").trim();
  const lang = normalizeLanguage(language);
  if (!uid) return null;

  const r = await pool.query(
    `UPDATE users
     SET language = $1, language_selected = true
     WHERE user_id = $2
     RETURNING language, language_selected, onboarding_completed`,
    [lang, uid]
  );
  return r.rows[0] || null;
}

export async function setOnboardingCompleted(pool, userId) {
  const uid = String(userId || "").trim();
  if (!uid) return null;

  const r = await pool.query(
    `UPDATE users
     SET onboarding_completed = true
     WHERE user_id = $1
     RETURNING language, language_selected, onboarding_completed`,
    [uid]
  );
  return r.rows[0] || null;
}

export async function setBonusAdShown(pool, userId) {
  const uid = String(userId || "").trim();
  if (!uid) return null;

  const r = await pool.query(
    `UPDATE users
     SET bonus_ad_shown = true
     WHERE user_id = $1
     RETURNING bonus_ad_shown`,
    [uid]
  );
  return r.rows[0] || null;
}
