const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const UPLOAD_DIR = path.join(ROOT, "public", "uploads");

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, "store.db"));
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  slug TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT DEFAULT '',
  category_id INTEGER,
  price REAL NOT NULL DEFAULT 0,
  discount_price REAL,
  stock INTEGER NOT NULL DEFAULT 0,
  brand TEXT DEFAULT '',
  sku TEXT DEFAULT '',
  specifications TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'available',
  rating REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS product_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wishlist (
  user_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, product_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  customer_name TEXT NOT NULL,
  customer_email TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  city TEXT NOT NULL,
  pincode TEXT NOT NULL,
  total REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER,
  product_name TEXT NOT NULL,
  price REAL NOT NULL,
  quantity INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE SET NULL
);
`);

const defaultCategories = [
  "Electronics","Mobile & Accessories","Clothing & Fashion","Shoes",
  "Home & Kitchen","Beauty & Personal Care","Grocery","Books",
  "Computer & Accessories","Toys","Sports","Other Products"
];

const insertCat = db.prepare("INSERT OR IGNORE INTO categories(name,slug) VALUES(?,?)");
for (const c of defaultCategories) insertCat.run(c, slugify(c));

const adminEmail = process.env.ADMIN_EMAIL || "admin@example.com";
const adminPassword = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const existingAdmin = db.prepare("SELECT id FROM users WHERE email=?").get(adminEmail);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'admin')")
    .run("Store Admin", adminEmail, hash);
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { files: 6, fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error("Only image files are allowed."));
  }
});

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-session-secret-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(express.static(path.join(ROOT, "public")));

function slugify(s) {
  return String(s).toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || `item-${Date.now()}`;
}
function publicProduct(row) {
  const imgs = db.prepare("SELECT filename FROM product_images WHERE product_id=? ORDER BY id").all(row.id)
    .map(x => `/uploads/${x.filename}`);
  return { ...row, images: imgs };
}
function auth(req,res,next) {
  if (!req.session.user) return res.status(401).json({error:"Login required"});
  next();
}
function adminOnly(req,res,next) {
  if (!req.session.user || req.session.user.role !== "admin") return res.status(403).json({error:"Admin access required"});
  next();
}

app.get("/api/me", (req,res) => {
  if (!req.session.user) return res.json({user:null});
  const u = db.prepare("SELECT id,name,email,role FROM users WHERE id=?").get(req.session.user.id);
  res.json({user:u || null});
});

app.post("/api/auth/register", async (req,res) => {
  const {name,email,password} = req.body;
  if (!name || !email || !password || password.length < 6)
    return res.status(400).json({error:"Name, valid email and a 6+ character password are required."});
  try {
    const hash = await bcrypt.hash(password,12);
    const result = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)")
      .run(name.trim(), email.trim().toLowerCase(), hash);
    req.session.user = {id:Number(result.lastInsertRowid), role:"customer"};
    res.json({ok:true});
  } catch {
    res.status(400).json({error:"Email is already registered."});
  }
});

app.post("/api/auth/login", async (req,res) => {
  const {email,password} = req.body;
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(String(email||"").trim().toLowerCase());
  if (!u || !(await bcrypt.compare(password || "", u.password_hash)))
    return res.status(401).json({error:"Invalid email or password."});
  req.session.user = {id:u.id, role:u.role};
  res.json({ok:true, role:u.role});
});
app.post("/api/auth/logout", (req,res) => req.session.destroy(()=>res.json({ok:true})));

app.get("/api/categories", (_,res) => res.json(db.prepare("SELECT * FROM categories ORDER BY name").all()));

app.get("/api/products", (req,res) => {
  const {q="",category="",min="",max="",brand="",sort="newest"} = req.query;
  let sql = `SELECT p.*, c.name category_name FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.status='available'`;
  const args=[];
  if(q){ sql += " AND (p.name LIKE ? OR p.brand LIKE ? OR p.sku LIKE ?)"; const x=`%${q}%`; args.push(x,x,x); }
  if(category){ sql += " AND p.category_id=?"; args.push(Number(category)); }
  if(min!==""){ sql += " AND COALESCE(p.discount_price,p.price)>=?"; args.push(Number(min)); }
  if(max!==""){ sql += " AND COALESCE(p.discount_price,p.price)<=?"; args.push(Number(max)); }
  if(brand){ sql += " AND p.brand LIKE ?"; args.push(`%${brand}%`); }
  const order = {
    "price-low":"COALESCE(p.discount_price,p.price) ASC",
    "price-high":"COALESCE(p.discount_price,p.price) DESC",
    "rating":"p.rating DESC",
    "newest":"p.created_at DESC"
  }[sort] || "p.created_at DESC";
  sql += ` ORDER BY ${order}`;
  const rows = db.prepare(sql).all(...args).map(publicProduct);
  res.json(rows);
});

app.get("/api/products/:id", (req,res) => {
  const row = db.prepare(`SELECT p.*, c.name category_name FROM products p LEFT JOIN categories c ON c.id=p.category_id WHERE p.id=?`)
    .get(Number(req.params.id));
  if(!row) return res.status(404).json({error:"Product not found"});
  res.json(publicProduct(row));
});

app.post("/api/wishlist/:productId", auth, (req,res) => {
  const pid=Number(req.params.productId);
  const exists=db.prepare("SELECT 1 FROM wishlist WHERE user_id=? AND product_id=?").get(req.session.user.id,pid);
  if(exists) db.prepare("DELETE FROM wishlist WHERE user_id=? AND product_id=?").run(req.session.user.id,pid);
  else db.prepare("INSERT OR IGNORE INTO wishlist(user_id,product_id) VALUES(?,?)").run(req.session.user.id,pid);
  res.json({saved:!exists});
});
app.get("/api/wishlist", auth, (req,res) => {
  const rows=db.prepare(`SELECT p.*,c.name category_name FROM wishlist w JOIN products p ON p.id=w.product_id LEFT JOIN categories c ON c.id=p.category_id WHERE w.user_id=? ORDER BY w.rowid DESC`)
    .all(req.session.user.id).map(publicProduct);
  res.json(rows);
});

app.post("/api/orders", auth, (req,res) => {
  const {customer_name,customer_email,phone,address,city,pincode,items} = req.body;
  if(!customer_name||!customer_email||!phone||!address||!city||!pincode||!Array.isArray(items)||!items.length)
    return res.status(400).json({error:"Complete checkout details and cart items are required."});

  const createOrder=db.transaction(() => {
    let total=0;
    const clean=[];
    for(const item of items){
      const p=db.prepare("SELECT * FROM products WHERE id=? AND status='available'").get(Number(item.product_id));
      const qty=Math.max(1,Math.min(99,Number(item.quantity)||1));
      if(!p || p.stock<qty) throw new Error(`Stock unavailable for product ${item.product_id}`);
      const price=Number(p.discount_price ?? p.price);
      total += price*qty;
      clean.push({p,qty,price});
    }
    const order=db.prepare(`INSERT INTO orders(user_id,customer_name,customer_email,phone,address,city,pincode,total) VALUES(?,?,?,?,?,?,?,?)`)
      .run(req.session.user.id,customer_name,customer_email,phone,address,city,pincode,total);
    const orderId=Number(order.lastInsertRowid);
    const addItem=db.prepare("INSERT INTO order_items(order_id,product_id,product_name,price,quantity) VALUES(?,?,?,?,?)");
    const reduce=db.prepare("UPDATE products SET stock=stock-?, status=CASE WHEN stock-?<=0 THEN 'out_of_stock' ELSE status END WHERE id=?");
    for(const x of clean){ addItem.run(orderId,x.p.id,x.p.name,x.price,x.qty); reduce.run(x.qty,x.qty,x.p.id); }
    return orderId;
  });
  try { res.json({ok:true,orderId:createOrder()}); }
  catch(e){ res.status(400).json({error:e.message}); }
});

app.get("/api/orders/my", auth, (req,res) => {
  const orders=db.prepare("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC").all(req.session.user.id);
  for(const o of orders) o.items=db.prepare("SELECT * FROM order_items WHERE order_id=?").all(o.id);
  res.json(orders);
});

/* Admin */
app.get("/api/admin/stats", adminOnly, (req,res) => {
  const stats={
    products: db.prepare("SELECT COUNT(*) c FROM products").get().c,
    orders: db.prepare("SELECT COUNT(*) c FROM orders").get().c,
    customers: db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,
    sales: db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders WHERE status!='cancelled'").get().s,
    lowStock: db.prepare("SELECT COUNT(*) c FROM products WHERE stock<=5").get().c
  };
  res.json(stats);
});
app.get("/api/admin/products", adminOnly, (req,res) => {
  res.json(db.prepare(`SELECT p.*,c.name category_name FROM products p LEFT JOIN categories c ON c.id=p.category_id ORDER BY p.id DESC`)
    .all().map(publicProduct));
});
app.post("/api/admin/products", adminOnly, upload.array("images",6), (req,res) => {
  const b=req.body;
  if(!b.name || !b.price) return res.status(400).json({error:"Product name and price are required."});
  let slug=slugify(b.name);
  if(db.prepare("SELECT 1 FROM products WHERE slug=?").get(slug)) slug += `-${Date.now()}`;
  const result=db.prepare(`INSERT INTO products(name,slug,description,category_id,price,discount_price,stock,brand,sku,specifications,status,rating)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      b.name.trim(),slug,b.description||"",Number(b.category_id)||null,Number(b.price)||0,
      b.discount_price===""?null:Number(b.discount_price),Number(b.stock)||0,b.brand||"",b.sku||"",
      b.specifications||"",b.status||"available",Number(b.rating)||0
  );
  const id=Number(result.lastInsertRowid);
  const add=db.prepare("INSERT INTO product_images(product_id,filename) VALUES(?,?)");
  for(const f of (req.files||[])) add.run(id,f.filename);
  res.json({ok:true,id});
});
app.put("/api/admin/products/:id", adminOnly, (req,res) => {
  const b=req.body;
  db.prepare(`UPDATE products SET name=?,description=?,category_id=?,price=?,discount_price=?,stock=?,brand=?,sku=?,specifications=?,status=?,rating=? WHERE id=?`)
    .run(b.name,b.description||"",Number(b.category_id)||null,Number(b.price)||0,b.discount_price===""?null:Number(b.discount_price),
      Number(b.stock)||0,b.brand||"",b.sku||"",b.specifications||"",b.status||"available",Number(b.rating)||0,Number(req.params.id));
  res.json({ok:true});
});
app.delete("/api/admin/products/:id", adminOnly, (req,res) => {
  const imgs=db.prepare("SELECT filename FROM product_images WHERE product_id=?").all(Number(req.params.id));
  for(const x of imgs){ try{fs.unlinkSync(path.join(UPLOAD_DIR,x.filename));}catch{} }
  db.prepare("DELETE FROM products WHERE id=?").run(Number(req.params.id));
  res.json({ok:true});
});

app.post("/api/admin/categories", adminOnly, (req,res) => {
  const name=String(req.body.name||"").trim();
  if(!name) return res.status(400).json({error:"Category name required"});
  try{
    db.prepare("INSERT INTO categories(name,slug) VALUES(?,?)").run(name,slugify(name));
    res.json({ok:true});
  }catch{res.status(400).json({error:"Category already exists."});}
});
app.put("/api/admin/categories/:id", adminOnly, (req,res) => {
  const name=String(req.body.name||"").trim();
  db.prepare("UPDATE categories SET name=?,slug=? WHERE id=?").run(name,slugify(name),Number(req.params.id));
  res.json({ok:true});
});
app.delete("/api/admin/categories/:id", adminOnly, (req,res) => {
  db.prepare("DELETE FROM categories WHERE id=?").run(Number(req.params.id));
  res.json({ok:true});
});

app.get("/api/admin/orders", adminOnly, (req,res) => {
  const orders=db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
  for(const o of orders) o.items=db.prepare("SELECT * FROM order_items WHERE order_id=?").all(o.id);
  res.json(orders);
});
app.put("/api/admin/orders/:id", adminOnly, (req,res) => {
  const allowed=["new","processing","shipped","delivered","cancelled"];
  if(!allowed.includes(req.body.status)) return res.status(400).json({error:"Invalid status"});
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,Number(req.params.id));
  res.json({ok:true});
});

app.get("/api/admin/customers", adminOnly, (req,res) => {
  res.json(db.prepare(`SELECT id,name,email,created_at FROM users WHERE role='customer' ORDER BY id DESC`).all());
});

app.post("/api/admin/change-password", adminOnly, async (req,res) => {
  const {currentPassword,newPassword}=req.body;
  if(!newPassword || newPassword.length<8) return res.status(400).json({error:"New password must be at least 8 characters."});
  const u=db.prepare("SELECT password_hash FROM users WHERE id=?").get(req.session.user.id);
  if(!(await bcrypt.compare(currentPassword||"",u.password_hash))) return res.status(400).json({error:"Current password is incorrect."});
  const hash=await bcrypt.hash(newPassword,12);
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,req.session.user.id);
  res.json({ok:true});
});

app.get("/admin", (req,res) => {
  res.sendFile(path.join(ROOT,"public","admin.html"));
});
app.use((err,req,res,next)=>{
  console.error(err);
  res.status(400).json({error:err.message || "Request failed"});
});

app.listen(PORT,()=>console.log(`Store running on http://localhost:${PORT}`));
