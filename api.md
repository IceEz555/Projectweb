# BookStore API Documentation

เอกสารสรุป API Endpoints ทั้งหมดสำหรับโปรเจกต์ BookStore

## Authentication (การยืนยันตัวตน)

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/register` | `POST` | ลงทะเบียนผู้ใช้ใหม่ | `{ "email": "user@example.com", "password": "password123" }` |
| `/api/login` | `POST` | เข้าสู่ระบบเพื่อรับ Token Cookie | `{ "email": "user@example.com", "password": "password123" }` |
| `/api/logout` | `POST` | ออกจากระบบ (ลบ Token Cookie) | *(None)* |
| `/api/user/auth` | `GET` | ดึงข้อมูลผู้ใช้ที่กำลัง login อยู่ (ต้องมี Token) | *(None)* |

## Public (สำหรับทุกคน)

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/books` | `GET` | ดึงรายการหนังสือทั้งหมดสำหรับแสดงหน้าแรก | *(None)* |

## User Profile (ข้อมูลผู้ใช้)

*Endpoints กลุ่มนี้ต้องมีการ Login (`checkAuth`)*

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/profile` | `GET` | ดึงข้อมูลโปรไฟล์ของผู้ใช้ที่ login อยู่ | *(None)* |
| `/api/profile` | `PUT` | อัปเดตข้อมูลโปรไฟล์ (ชื่อ, โทรศัพท์, ที่อยู่) | `{ "firstname": "...", "lastname": "...", "phone": "...", "address": "..." }` |

## Cart (ตะกร้าสินค้า)

*Endpoints กลุ่มนี้ต้องมีการ Login (`checkAuth`)*

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/cart` | `GET` | ดึงรายการสินค้าทั้งหมดในตะกร้าของผู้ใช้ | *(None)* |
| `/api/cart` | `POST` | เพิ่มสินค้าลงในตะกร้า (ถ้ามีอยู่แล้วจะเพิ่มจำนวน) | `{ "product_id": 1, "quantity": 1 }` |
| `/api/cart/:product_id` | `PUT` | อัปเดตจำนวนสินค้าในตะกร้า | `{ "quantity": 3 }` |
| `/api/cart/:product_id` | `DELETE`| ลบสินค้าออกจากตะกร้า | *(None)* |

## Payment (การชำระเงิน)

*Endpoints กลุ่มนี้ต้องมีการ Login (`checkAuth`)*

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/create-payment-intent`| `POST` | สร้างรายการชำระเงินกับ Stripe | `{ "shippingDetails": { "name": "...", "address": "...", "phone": "..." } }` |
| `/api/order/by-payment-intent/:pi_id` | `GET` | ค้นหา `order_id` จาก `payment_intent_id` | *(None)* |

## Order (ประวัติการสั่งซื้อ)

*Endpoints กลุ่มนี้ต้องมีการ Login (`checkAuth`)*

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/orders` | `GET` | ดึงประวัติการสั่งซื้อทั้งหมดของผู้ใช้ (พร้อมรายการสินค้า) | *(None)* |

## Admin (สำหรับผู้ดูแลระบบ)

*Endpoints กลุ่มนี้ต้อง Login เป็น Admin (`checkAuth` และ `checkAdmin`)*

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/admin/products` | `GET` | ดึงรายการหนังสือทั้งหมด (สำหรับหน้าจัดการ) | *(None)* |
| `/api/admin/products` | `POST` | เพิ่มหนังสือเล่มใหม่ | `{ "book_name": "...", "author": "...", ... }` |
| `/api/admin/products/:id` | `PUT` | แก้ไขข้อมูลหนังสือ | `{ "book_name": "...", "author": "...", ... }` |
| `/api/admin/products/:id` | `DELETE`| ลบหนังสือ | *(None)* |
| `/api/admin/manageorder` | `GET` | ดึง Order ที่มีสถานะ 'paid' (รอจัดส่ง) | *(None)* |
| `/api/admin/shipped-order` | `GET` | ดึง Order ที่มีสถานะ 'shipped' (จัดส่งแล้ว) | *(None)* |
| `/api/admin/order/:orderId/tracking` | `PUT` | อัปเดตเลขพัสดุและสถานะ Order | `{ "trackingNumber": "TH123..." }` |
| `/api/admin/order/:orderId` | `GET` | ดึงรายละเอียดของ Order เดียว (พร้อมรายการสินค้า) | *(None)* |
| `/api/admin/dashboard-summary` | `GET` | ดึงข้อมูลสรุปสำหรับหน้า Dashboard | *(None)* |
| `/api/admin/recent-orders` | `GET` | ดึงรายการคำสั่งซื้อล่าสุด 5 รายการ | *(None)* |

## Stripe Webhook

| Endpoint | Method | Description | Body (JSON) |
| :--- | :--- | :--- | :--- |
| `/api/stripe-webhook` | `POST` | Endpoint สำหรับรับสัญญาณจาก Stripe (ห้ามเรียกใช้โดยตรง) | *(Stripe Event Object)* |