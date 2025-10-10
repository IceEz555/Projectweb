import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import cors from "cors";
import 'dotenv/config';
import express from "express";
import jwt from "jsonwebtoken";
import { dirname } from "path";
import pg from "pg";
import Stripe from "stripe";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const secret = process.env.JWT_SECRET;
const port = 8000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY , {
  apiVersion: "2022-11-15",
});
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

// ===== Database Connection =====
const { Pool } = pg;
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: 5432,
});

// ===== Middleware (ที่ไม่ใช่ express.json) =====
app.use(cookieParser());
app.use(express.static(__dirname + "/public"));
app.use(cors({
  credentials: true,
  origin: ["http://localhost:8000", "http://127.0.0.1:8000"]
}));

// ======================= STRIPE WEBHOOK =======================
// ⚠️ ต้องอยู่ก่อน express.json()
app.post(
  "/api/stripe-webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
      event = stripe.webhooks.constructEvent(req.body, sig, stripeWebhookSecret);
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "payment_intent.succeeded") {
      const paymentIntent = event.data.object;
      const metadata = paymentIntent.metadata; // ✅ ดึง metadata ออกมา
      const userId = metadata.userId;

      if (!userId) {
        return res.status(400).json({ error: "Missing userId in metadata" });
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const paymentIntentId = paymentIntent.id.split('_secret_')[0];
        const existingOrder = await client.query(
          "SELECT order_id FROM orders WHERE stripe_payment_intent_id = $1", [paymentIntentId]
        );

        if (existingOrder.rows.length === 0) {
          const cartRes = await client.query(
            `SELECT ci.product_id, ci.cart_item_quantity, p.book_price FROM cart_item ci 
             JOIN products p ON ci.product_id = p.book_id WHERE ci.user_id = $1`, [userId]
          );
          if (cartRes.rows.length === 0) throw new Error("Cart is empty for order creation");
          
          const totalAmount = paymentIntent.amount / 100;

          // ✅ ใช้ข้อมูลจาก metadata ในการสร้าง Order
          const orderInsertRes = await client.query(
            `INSERT INTO orders (user_id, total_amount, stripe_payment_intent_id, status, recipient_name, recipient_phone, shipping_address) 
             VALUES ($1, $2, $3, 'paid', $4, $5, $6) RETURNING order_id`,
            [
              userId,
              totalAmount,
              paymentIntentId,
              metadata.recipient_name,  // <-- ใช้ข้อมูลจากฟอร์ม
              metadata.recipient_phone, // <-- ใช้ข้อมูลจากฟอร์ม
              metadata.shipping_address // <-- ใช้ข้อมูลจากฟอร์ม
            ]
          );
          const newOrderId = orderInsertRes.rows[0].order_id;
          
          const orderItemPromises = cartRes.rows.map((item) => {
            return client.query(
              "INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES ($1, $2, $3, $4)",
              [newOrderId, item.product_id, item.cart_item_quantity, item.book_price]
            );
          });
          await Promise.all(orderItemPromises);
          await client.query("DELETE FROM cart_item WHERE user_id = $1", [userId]);
          console.log(`Order ${newOrderId} created via webhook. Cart cleared.`);
        }
        await client.query("COMMIT");
      } catch (err) {
        await client.query("ROLLBACK");
        console.error("Error in webhook order processing:", err);
        return res.status(500).json({ error: "Failed to process order." });
      } finally {
        client.release();
      }
    }
    res.status(200).json({ received: true });
  }
);


// ===== 🔥 ตอนนี้ถึงใส่ express.json() และ bodyParser =====
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

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

// 📹 หน้าเว็บหลัก
app.get('/', (req, res) => res.sendFile(__dirname + "/public/index.html"));
app.get('/login', (req, res) => res.sendFile(__dirname + "/public/login.html"));
app.get('/register', (req, res) => res.sendFile(__dirname + "/public/register.html"));
app.get('/checkout', (req, res) => res.sendFile(__dirname + "/public/checkout.html"));
app.get('/successpay', (req, res) => res.sendFile(__dirname + "/public/successpay.html"));
app.get('/order', (req, res) => res.sendFile(__dirname + "/public/order.html"));
app.get('/manage_order', (req, res) => res.sendFile(__dirname + "/public/manage_order.html"));
app.get('/overview', (req, res) => res.sendFile(__dirname + "/public/overview.html"));
app.get('/products', checkAuth, (req, res) => {
  if (req.userRole !== "admin") return res.redirect("/");
  res.sendFile(__dirname + "/public/adminbook.html");
});
app.get('/userprofile',checkAuth,(req,res) =>{
  res.sendFile(__dirname + "/public/userprofile.html")
});

// 📹 Register
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

// 📹 Login
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
      secure: false,
      sameSite: "lax"
    });

    res.json({ message: "Login successful", user: { id: user.user_id, role: user.role } });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal error", error: error.message });
  }
});

// 📹 Logout
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout success" });
});

// 📹 ดึงข้อมูล user ปัจจุบัน
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

// 📹 ดึงหนังสือหน้า Home (public)
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

adminRouter.get("/products", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM products ORDER BY book_id ASC");
    res.json({ products: result.rows });
  } catch (error) {
    console.error("Fetch products error:", error);
    res.status(500).json({ error: "Failed to fetch products" });
  }
});

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

adminRouter.get("/manageorder", async (req, res) => {
    try {
        // ✅ แก้ไข: u.email และ o.created_at
        const result = await pool.query(
            `SELECT o.order_id, u.email, o.total_amount, o.tracking_number, o.created_at, o.status
             FROM orders o 
             JOIN users u ON o.user_id = u.user_id 
             WHERE o.status = 'paid' 
             ORDER BY o.created_at DESC` 
        );
        res.json(result.rows);
    } catch (error) {
        console.error("Get paid orders error:", error);
        res.status(500).json({ error: "Failed to get paid orders" });
    }
});

adminRouter.get("/shipped-order", async (req, res) => {
    try {
        // ✅ แก้ไข: u.email และ o.created_at
        const result = await pool.query(
            `SELECT o.order_id, u.email, o.total_amount, o.tracking_number, o.created_at, o.status
             FROM orders o 
             JOIN users u ON o.user_id = u.user_id 
             WHERE o.status = 'shipped' 
             ORDER BY o.created_at DESC` // DESC คือใหม่ไปเก่า
        );
        res.json(result.rows);
    } catch (error) {
        console.error("Get shipped orders error:", error);
        res.status(500).json({ error: "Failed to get shipped orders" });
    }
});

adminRouter.put("/order/:orderId/tracking", async (req, res) => {
    try {
        const { orderId } = req.params;
        const { trackingNumber } = req.body;
        if (!trackingNumber) {
            return res.status(400).json({ message: "Tracking number is required" });
        }

        const result = await pool.query(
            `UPDATE orders SET tracking_number = $1, status = 'shipped' 
             WHERE order_id = $2`,
            [trackingNumber, orderId]
        );

        // ✅ แก้ไข: ใช้ result.rowCount ในการตรวจสอบ
        if (result.rowCount === 0) {
            return res.status(404).json({ message: "Order not found" });
        }
        
        res.status(200).json({ message: "Order has been marked as shipped" });

    } catch (error) {
        console.error("Update tracking error:", error);
        res.status(500).json({ error: "Failed to update tracking number" });
    }
});

adminRouter.get("/order/:orderId", async (req, res) => {
    try {
        const { orderId } = req.params;

        // 1. ดึงข้อมูล Order หลัก
        const orderResult = await pool.query(
            `SELECT * FROM orders WHERE order_id = $1`,
            [orderId]
        );

        if (orderResult.rows.length === 0) {
            return res.status(404).json({ message: "Order not found" });
        }

        // 2. ดึงข้อมูลสินค้าใน Order นั้น
        const itemsResult = await pool.query(
            `SELECT oi.quantity, oi.price_at_purchase, p.book_name, p.image_url 
             FROM order_items oi 
             JOIN products p ON oi.product_id = p.book_id 
             WHERE oi.order_id = $1`,
            [orderId]
        );

        res.json({
            order: orderResult.rows[0],
            items: itemsResult.rows
        });

    } catch (error) {
        console.error("Get order details error:", error);
        res.status(500).json({ error: "Failed to get order details" });
    }
});

adminRouter.get("/dashboard-summary", async (req, res) => {
    try {
        const [booksRes, ordersRes, usersRes, revenueRes] = await Promise.all([
            pool.query("SELECT COUNT(*) FROM products"),
            pool.query("SELECT COUNT(*) FROM orders"),
            pool.query("SELECT COUNT(*) FROM users"),
            pool.query("SELECT SUM(total_amount) FROM orders WHERE status = 'paid' OR status = 'shipped'")
        ]);

        res.json({
            totalBooks: parseInt(booksRes.rows[0].count) || 0,
            totalOrders: parseInt(ordersRes.rows[0].count) || 0,
            totalUsers: parseInt(usersRes.rows[0].count) || 0,
            totalRevenue: parseFloat(revenueRes.rows[0].sum) || 0,
        });
    } catch (error) {
        console.error("Get dashboard summary error:", error);
        res.status(500).json({ error: "Failed to get summary" });
    }
});

// 2. Endpoint สำหรับดึงข้อมูลคำสั่งซื้อล่าสุด 5 รายการ
adminRouter.get("/recent-orders", async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT o.order_id, u.email, o.total_amount, o.status, o.created_at
             FROM orders o
             JOIN users u ON o.user_id = u.user_id
             ORDER BY o.created_at DESC
             LIMIT 5`
        );
        res.json(result.rows);
    } catch (error) {
        console.error("Get recent orders error:", error);
        res.status(500).json({ error: "Failed to get recent orders" });
    }
});

// ===== USERS Profile =====
app.get('/api/profile', checkAuth, async(req,res)=>{
    try {
        const result = await pool.query('SELECT firstname, lastname, email, phone, address FROM users WHERE user_id = $1 ',[req.userId])
        res.json(result.rows[0])
    } catch (error) {
      console.error("Query profile error:", error);
      res.status(500).json({ error: "Server error cannot query profile" });
    }
})

app.put("/api/profile",checkAuth, async(req,res)=>{
  try {
    const{firstname, lastname,phone,address} = req.body;
    if(!firstname||!lastname||!phone||!address){
      return res.status(400).json({ message: "Input full fill" });
    }
    await pool.query(
  'UPDATE users SET firstname = $1, lastname = $2, phone = $3, address = $4 WHERE user_id = $5',
  [firstname, lastname, phone, address, req.userId]
);

    res.json({message:"Update Succesfull"})
  } catch (error) {
      console.error("Update profile error:", error);
      res.status(500).json({ error: "Server error cannot update profile" });
  }
})

// ===== CART =====
app.get('/api/cart',checkAuth, async(req,res)=>{
  try {
    const result = await pool.query(`SELECT c.product_id,c.cart_item_quantity,p.book_name,p.book_price,p.image_url FROM cart_item c JOIN products p 
        ON c.product_id = p.book_id WHERE c.user_id = $1 AND p.is_active = TRUE`,[req.userId])
        res.json(result.rows)
  } catch (error) {
    console.error("Query Cart error:", error);
      res.status(500).json({ error: "Server error cannot query cart" });
  }
})

app.post('/api/cart',checkAuth, async(req,res)=>{
  try {
    const {product_id,quantity} = req.body
    const result = await pool.query(`INSERT INTO cart_item (user_id,product_id,cart_item_quantity)
    VALUES ($1,$2,$3) ON CONFLICT(user_id,product_id) DO UPDATE SET cart_item_quantity = cart_item.cart_item_quantity + EXCLUDED.cart_item_quantity RETURNING *`,[req.userId,product_id,quantity])
    res.status(201).json({message:"Successfull"})
  } catch (error) {
    console.error("Add Cart error:", error);
      res.status(500).json({ error: "Server error cannot add cart" });
  }
})

app.put('/api/cart/:product_id', checkAuth, async (req, res) => {
  try {
    const { product_id } = req.params;
    const { quantity } = req.body;

    if (!quantity || quantity <= 0) {
      return res.status(400).json({ error: "Invalid quantity" });
    }

    const result = await pool.query(
      `UPDATE cart_item
       SET cart_item_quantity = $1 
       WHERE user_id = $2 AND product_id = $3 
       RETURNING *`,
      [quantity, req.userId, product_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Item not found in cart" });
    }

    res.json({ message: "Cart item updated", item: result.rows[0] });
  } catch (error) {
    console.error("Update Cart error:", error);
    res.status(500).json({ error: "Server error cannot update cart" });
  }
});

app.delete('/api/cart/:product_id', checkAuth, async (req, res) => {
  try {
    const { product_id } = req.params;

    const result = await pool.query(
      `DELETE FROM cart_item 
       WHERE user_id = $1 AND product_id = $2 
       RETURNING *`,
      [req.userId, product_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Item not found in cart" });
    }

    res.json({ message: "Cart item removed", removed: result.rows[0] });
  } catch (error) {
    console.error("Delete Cart error:", error);
    res.status(500).json({ error: "Server error cannot delete cart" });
  }
});

// ======================= PAYMENT INTENT =======================
app.post("/api/create-payment-intent", checkAuth, async (req, res) => {
  try {
    // ✅ 1. รับ shippingDetails จาก req.body
    const { shippingDetails } = req.body;
    if (!shippingDetails || !shippingDetails.name || !shippingDetails.address || !shippingDetails.phone) {
        return res.status(400).json({ error: "Shipping details are required." });
    }

    const result = await pool.query(
      `SELECT SUM(p.book_price * ci.cart_item_quantity) AS total
       FROM cart_item ci
       JOIN products p ON ci.product_id = p.book_id
       WHERE ci.user_id = $1 AND p.is_active = TRUE`,
      [req.userId]
    );

    const total = result.rows[0]?.total ?? 0;
    if (total <= 0) return res.status(400).json({ error: "Cart is empty" });

    const totalAmountWithShipping = total + 0; // เพิ่มค่าส่ง (ถ้ามี)
    
    const intent = await stripe.paymentIntents.create({
      amount: Math.round(totalAmountWithShipping * 100),
      currency: "thb",
      // ✅ 2. แนบข้อมูลการจัดส่งและ userId ไปกับ metadata
      metadata: { 
          userId: String(req.userId),
          recipient_name: shippingDetails.name,
          recipient_phone: shippingDetails.phone,
          shipping_address: shippingDetails.address
      },
    });

    res.json({ clientSecret: intent.client_secret });
  } catch (err) {
    console.error("Create payment intent error:", err);
    res.status(500).json({ error: "Payment intent creation failed" });
  }
});

app.get("/api/order/by-payment-intent/:pi_id", checkAuth, async (req, res) => {
  try {
    const { pi_id } = req.params;
    const result = await pool.query(
      "SELECT order_id FROM orders WHERE stripe_payment_intent_id = $1 AND user_id = $2 ORDER BY created_at DESC LIMIT 1",
      [pi_id, req.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Order not found yet. Please wait a moment." });
    }
    res.json({ orderId: result.rows[0].order_id });
  } catch (err) {
    console.error("Error fetching order by PI ID:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Orderdetail
app.get("/api/orders", checkAuth, async (req, res) => {
    try {
        // ✅ แก้ไข: ORDER BY created_at
        const result = await pool.query(
            `SELECT order_id, total_amount, status, tracking_number, created_at, recipient_name, recipient_phone, shipping_address 
             FROM orders 
             WHERE user_id = $1
             ORDER BY created_at DESC`, 
            [req.userId]
        );
        const orders = result.rows;
        
        if (orders.length === 0) {
            // ตอบกลับเป็น array ว่างตามปกติ ไม่ต้องเป็น 404
            return res.json([]); 
        }

        // ✅ แก้ไข: เปลี่ยนชื่อตัวแปรจาก orders เป็น order เพื่อไม่ให้ซ้ำซ้อน
        const orderDetailsPromises = orders.map(async (order) => {
            // ✅ แก้ไข: ON oi.product_id = p.book_id และ p.book_name
            const itemsResult = await pool.query(
                `SELECT oi.quantity, oi.price_at_purchase, p.book_name, p.image_url 
                 FROM order_items oi 
                 JOIN products p ON oi.product_id = p.book_id 
                 WHERE oi.order_id = $1`, 
                [order.order_id]
            );
            // ✅ แก้ไข: return {...order, ...}
            return { ...order, items: itemsResult.rows };
        });

        const fullOrders = await Promise.all(orderDetailsPromises);
        res.json(fullOrders);

    } catch (error) {
        console.error("Query orders error:", error);
        res.status(500).json({ error: "Server error cannot query order" });
    }
});


// ===== Start Server =====
app.listen(port, () => console.log(`✅ Server running on http://localhost:${port}`));