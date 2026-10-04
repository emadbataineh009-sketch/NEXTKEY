const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '2b2deb6eb1cb3506c8cd2a167064e5951c18cecda3e8c640a1034862ccd9abd9';
const MONGODB_URI = process.env.MONGODB_URI;

const sessions = new Set();
let productsCollection;

// الاتصال بقاعدة بيانات MongoDB Atlas
async function connectDB() {
  if (!MONGODB_URI) {
    console.error('CRITICAL: MONGODB_URI is not set in environment variables!');
    return;
  }
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    const db = client.db('nextkey_db');
    productsCollection = db.collection('products');
    console.log('Successfully connected to MongoDB Atlas!');
  } catch (err) {
    console.error('MongoDB Connection Error:', err);
  }
}
connectDB();

function hash(value) { 
  return crypto.createHash('sha256').update(value).digest('hex'); 
}

function json(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': '*'
  });
  res.end(body);
}

function body(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
  });
}

function authorized(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') && sessions.has(h.slice(7));
}

function safeProduct(input) {
  return {
    id: Date.now() + Math.floor(Math.random() * 1000),
    name: String(input.name || '').trim(),
    category: String(input.category || 'gaming'),
    price: Number(input.price),
    image: String(input.image || '').trim() || `https://placehold.co/400x250/121217/D4AF37?text=${encodeURIComponent(String(input.name || 'NEXTKEY'))}`,
    desc: String(input.desc || '').trim()
  };
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS'
    });
    return res.end();
  }

  try {
    // 1. جلب المنتجات والعروض من MongoDB
    if (url.pathname === '/api/products' && req.method === 'GET') {
      if (!productsCollection) return json(res, 500, { error: 'Database not connected' });
      const products = await productsCollection.find({}).project({ _id: 0 }).toArray();
      return json(res, 200, products);
    }

    // 2. تسجيل دخول الأدمن
    if (url.pathname === '/api/admin/login' && req.method === 'POST') {
      const data = await body(req);
      const a = Buffer.from(hash(String(data.password || '')));
      const b = Buffer.from(ADMIN_PASSWORD_HASH);
      const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
      if (!ok) return json(res, 401, { error: 'رمز المرور غير صحيح' });
      
      const token = crypto.randomBytes(32).toString('hex');
      sessions.add(token);
      return json(res, 200, { token });
    }

    // 3. إضافة منتج جديد إلى MongoDB
    if (url.pathname === '/api/products' && req.method === 'POST') {
      if (!authorized(req)) return json(res, 401, { error: 'غير مصرح' });
      if (!productsCollection) return json(res, 500, { error: 'Database not connected' });
      
      const data = await body(req);
      if (!data.name || !Number.isFinite(Number(data.price))) {
        return json(res, 400, { error: 'بيانات المنتج غير مكتملة' });
      }
      
      const product = safeProduct(data);
      await productsCollection.insertOne(product);
      return json(res, 201, product);
    }

    // 4. حذف منتج من MongoDB
    if (url.pathname.startsWith('/api/products/') && req.method === 'DELETE') {
      if (!authorized(req)) return json(res, 401, { error: 'غير مصرح' });
      if (!productsCollection) return json(res, 500, { error: 'Database not connected' });
      
      const id = Number(url.pathname.split('/').pop());
      await productsCollection.deleteOne({ id: id });
      return json(res, 200, { ok: true });
    }

    // 5. خدمة الملفات الثابتة (Public Files)
    let filePath = url.pathname === '/' ? path.join(PUBLIC, 'index.html') : path.join(PUBLIC, url.pathname);
    if (!filePath.startsWith(PUBLIC)) return json(res, 403, { error: 'Forbidden' });
    if (!fs.existsSync(filePath)) return json(res, 404, { error: 'Not found' });
    
    const ext = path.extname(filePath);
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.json': 'application/json; charset=utf-8'
    };
    
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);

  } catch (e) {
    console.error(e);
    json(res, 500, { error: 'Server error' });
  }
});

server.listen(PORT, () => console.log(`NEXTKEY running on port ${PORT}`));
