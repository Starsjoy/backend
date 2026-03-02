import pkg from "pg";
import dotenv from "dotenv";
dotenv.config();
const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function fixTotalReferrals() {
  try {
    console.log("🔄 Barcha userlar referral sonini tekshirish boshlandi...\n");

    // Har bir userning haqiqiy referral sonini hisoblash
    const result = await pool.query(`
      SELECT u.username,
             u.total_referrals AS eski_son,
             COALESCE(r.real_count, 0) AS haqiqiy_son
      FROM users u
      LEFT JOIN (
        SELECT referrer_username, COUNT(*) AS real_count
        FROM users
        WHERE referrer_username IS NOT NULL
        GROUP BY referrer_username
      ) r ON r.referrer_username = u.username
      WHERE u.total_referrals != COALESCE(r.real_count, 0)
      ORDER BY COALESCE(r.real_count, 0) DESC
    `);

    if (result.rows.length === 0) {
      console.log("✅ Barcha userlarning total_referrals to'g'ri — o'zgartirish kerak emas.");
      await pool.end();
      return;
    }

    console.log(`⚠️  ${result.rows.length} ta userda noto'g'ri total_referrals topildi:\n`);
    console.log("Username".padEnd(25) + "Eski".padEnd(8) + "Haqiqiy");
    console.log("-".repeat(41));

    for (const row of result.rows) {
      console.log(
        row.username.padEnd(25) +
        String(row.eski_son).padEnd(8) +
        String(row.haqiqiy_son)
      );
    }

    // Barchasini bir SQL bilan yangilash
    const updateResult = await pool.query(`
      UPDATE users u
      SET total_referrals = COALESCE(sub.real_count, 0)
      FROM (
        SELECT u2.username,
               COALESCE(r.real_count, 0) AS real_count
        FROM users u2
        LEFT JOIN (
          SELECT referrer_username, COUNT(*) AS real_count
          FROM users
          WHERE referrer_username IS NOT NULL
          GROUP BY referrer_username
        ) r ON r.referrer_username = u2.username
      ) sub
      WHERE u.username = sub.username
        AND u.total_referrals != sub.real_count
    `);

    console.log(`\n✅ ${updateResult.rowCount} ta user yangilandi!`);


    // Natijani ko'rsatish
    const topUsers = await pool.query(`
      SELECT username, total_referrals
      FROM users
      WHERE total_referrals > 0
      ORDER BY total_referrals DESC
      LIMIT 20
    `);

    if (topUsers.rows.length > 0) {
      console.log("📊 Top referrallar:\n");
      console.log("Username".padEnd(25) + "Do'stlar");
      console.log("-".repeat(35));
      for (const row of topUsers.rows) {
        console.log(
          row.username.padEnd(25) +
          String(row.total_referrals)
        );
      }
    }

    await pool.end();
    console.log("\n🏁 Script tugadi.");
  } catch (err) {
    console.error("❌ Xatolik:", err.message);
    await pool.end();
    process.exit(1);
  }
}

fixTotalReferrals();
