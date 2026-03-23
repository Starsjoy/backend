require('dotenv').config();
const { Pool } = require('pg');
const readline = require('readline');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

async function main() {
  try {
    console.log("Ma'lumotlar bazasiga ulanmoqda...");

    // Pending holatidagi orderlarni sanash
    const countQuery = await pool.query(
      "SELECT COUNT(*) FROM orders WHERE payment_status = 'pending' OR status = 'pending'"
    );
    
    const count = parseInt(countQuery.rows[0].count, 10);

    console.log(`\n📊 Jami kutayotgan (pending) orderlar soni: ${count} ta`);

    if (count === 0) {
      console.log("✅ O'zgartirish uchun pending orderlar topilmadi.");
      pool.end();
      rl.close();
      return;
    }

    rl.question("\nBarcha pending orderlarni 'expired' qilib belgilashni xohlaysizmi? (ha/yo'q): ", async (answer) => {
      if (answer.trim().toLowerCase() === 'ha') {
        console.log("\n⏳ Barcha pending orderlar bekor qilinmoqda...");
        
        const updateQuery = await pool.query(
          "UPDATE orders SET payment_status = 'expired', status = 'expired' WHERE payment_status = 'pending' OR status = 'pending'"
        );
        
        console.log(`✅ Muvaffaqiyatli bajarildi! ${updateQuery.rowCount} ta order expired qattiq rejimga o'tkazildi.`);
      } else {
        console.log("\n❌ Bekor qilindi. Hech narsa o'zgartirilmadi.");
      }
      
      pool.end();
      rl.close();
    });

  } catch (error) {
    console.error("❌ Xatolik yuz berdi:", error.message);
    pool.end();
    rl.close();
  }
}

main();
