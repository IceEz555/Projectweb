import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import { dirname } from "path";
import pg from "pg";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const secret = "mysecret";
const port = 8000;

// ===== Database Connection =====
const { Pool } = pg;
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'bookstore',
  password: '081081',
  port: 5432,
});

// ===== Middleware =====
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(__dirname + "/public"));
app.use(cors({
  credentials: true,
  origin: ["http://localhost:8000", "http://127.0.0.1:8000"]
}));

// ===== Authentication Middleware =====
const checkAuth = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Not have token" });

  try {
    const decoded = jwt.verify(token, secret);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Token expired" });
  }
};

const checkAdmin = (req, res, next) => {
  if (req.userRole !== "admin") {
    return res.status(403).json({ message: "Not have permission" });
  }
  next();
};

// ===== Routes =====

// 🔹 หน้าเว็บหลัก
app.get('/', (req, res) => res.sendFile(__dirname + "/public/index.html"));
app.get('/login', (req, res) => res.sendFile(__dirname + "/public/login.html"));
app.get('/register', (req, res) => res.sendFile(__dirname + "/public/register.html"));
app.get('/products', checkAuth, (req, res) => {
  if (req.userRole !== "admin") return res.redirect("/");
  res.sendFile(__dirname + "/public/adminbook.html");
});

// 🔹 Register
app.post('/api/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const hashPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (email, password, role) VALUES ($1, $2, $3)",
      [email, hashPassword, "customer"]
    );
    res.json({ message: "Register successful" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Database error", error: error.message });
  }
});

// 🔹 Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (!result.rows.length) return res.status(404).json({ message: "User not found" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Incorrect password" });

    const token = jwt.sign(
      { userId: user.user_id, email: user.email, role: user.role },
      secret,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      maxAge: 3600000,
      httpOnly: true,
      secure: false, // ปิดตอนทดสอบ local
      sameSite: "lax"
    });

    res.json({ message: "Login successful", user: { id: user.user_id, role: user.role } });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal error", error: error.message });
  }
});

// 🔹 Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout success" });
});

// 🔹 ดึงข้อมูล user ปัจจุบัน
app.get("/api/user/auth", checkAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT user_id, email, role FROM users WHERE user_id = $1", [req.userId]);
    if (!result.rows.length) return res.status(404).json({ message: "User not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// 🔹 ดึงหนังสือหน้า Home (public)
app.get('/api/books', async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM products ORDER BY book_id ASC");
    res.json({ books: result.rows });
  } catch (error) {
    console.error("Fetch books error:", error);
    res.status(500).json({ error: "Failed to fetch books" });
  }
});

// ===== ADMIN ROUTES =====
const adminRouter = express.Router();
adminRouter.use(checkAuth, checkAdmin);

// ✅ GET — แสดงสินค้าทั้งหมด
adminRouter.get("/products", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM products ORDER BY book_id ASC");
    res.json({ products: result.rows });
  } catch (error) {
    console.error("Fetch products error:", error);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

// ✅ POST — เพิ่มหนังสือใหม่
adminRouter.post("/products", async (req, res) => {
  try {
    const { book_name, book_type, book_price, old_price, image_url, description, author, stock } = req.body;
    if (!book_name || !book_type || !book_price || !image_url || !description || !author || !stock) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const result = await pool.query(
      `INSERT INTO products (book_name, book_type, book_price, old_price, image_url, description, author, stock)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [book_name, book_type, book_price, old_price, image_url, description, author, stock]
    );

    res.status(201).json({ message: "Insert Product Success", products: result.rows[0] });
  } catch (error) {
    console.error("Insert error:", error);
    res.status(500).json({ error: "Failed to insert product" });
  }
});

// ✅ PUT — แก้ไขข้อมูลหนังสือ
adminRouter.put("/products/:id", async (req, res) => {
  const { id } = req.params;
  const { book_name, author, description, book_type, book_price, stock, image_url, old_price } = req.body;

  try {
    await pool.query(
      `UPDATE products 
       SET book_name=$1, author=$2, description=$3, book_type=$4, book_price=$5, stock=$6, image_url=$7, old_price=$8
       WHERE book_id=$9`,
      [book_name, author, description, book_type, book_price, stock, image_url, old_price, id]
    );
    res.json({ message: "Book updated successfully" });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ error: "Failed to update book" });
  }
});

// ✅ DELETE — ลบหนังสือ
adminRouter.delete("/products/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM products WHERE book_id = $1", [id]);
    res.json({ message: "Book deleted successfully" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ error: "Failed to delete book" });
  }
});

app.use("/api/admin", adminRouter);

// ===== Start Server =====
app.listen(port, () => console.log(`✅ Server running on http://localhost:${port}`));
