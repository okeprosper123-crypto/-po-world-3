const express = require('express'), cors = require('cors'), bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'), Database = require('better-sqlite3'), path = require('path');
const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const ADMIN = (process.env.ADMIN_EMAIL || '').toLowerCase();
const db = new Database(process.env.DB_PATH || './poworld.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, hash TEXT, bio TEXT DEFAULT '', role TEXT DEFAULT 'user', created INTEGER);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, seller INTEGER, title TEXT, descr TEXT, price INTEGER, img TEXT, stock INTEGER, created INTEGER);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, buyer INTEGER, product INTEGER, qty INTEGER, total INTEGER, status TEXT DEFAULT 'pending', created INTEGER);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, author INTEGER, body TEXT, img TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS likes(post INTEGER, user INTEGER, PRIMARY KEY(post,user));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, post INTEGER, author INTEGER, body TEXT, created INTEGER);
CREATE TABLE IF NOT EXISTS follows(a INTEGER, b INTEGER, PRIMARY KEY(a,b));
CREATE TABLE IF NOT EXISTS scores(id INTEGER PRIMARY KEY, user INTEGER, game TEXT, score INTEGER, created INTEGER);
`);
const app = express(); app.use(cors()); app.use(express.json({ limit: '2mb' }));
const now = () => Date.now(), wrap = f => (q, s) => { try { f(q, s) } catch (e) { s.status(400).json({ error: e.message }) } };
const sign = u => jwt.sign({ id: u.id, role: u.role }, SECRET, { expiresIn: '30d' });
const auth = (q, s, n) => { try { q.user = jwt.verify((q.headers.authorization || '').slice(7), SECRET); n() } catch { s.status(401).json({ error: 'Login required' }) } };
const admin = (q, s, n) => q.user.role === 'admin' ? n() : s.status(403).json({ error: 'Admins only' });
const str = (v, max) => String(v || '').trim().slice(0, max);

app.post('/api/register', wrap((q, s) => {
  const name = str(q.body.name, 40), email = str(q.body.email, 120).toLowerCase(), pw = String(q.body.password || '');
  if (!name || !email.includes('@') || pw.length < 6) throw new Error('Name, valid email and 6+ char password required');
  const role = email === ADMIN ? 'admin' : 'user';
  const r = db.prepare('INSERT INTO users(name,email,hash,role,created) VALUES(?,?,?,?,?)').run(name, email, bcrypt.hashSync(pw, 10), role, now());
  s.json({ token: sign({ id: r.lastInsertRowid, role }), user: { id: r.lastInsertRowid, name, role } });
}));
app.post('/api/login', wrap((q, s) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(str(q.body.email, 120).toLowerCase());
  if (!u || !bcrypt.compareSync(String(q.body.password || ''), u.hash)) throw new Error('Wrong email or password');
  s.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role } });
}));
app.get('/api/me', auth, (q, s) => s.json(db.prepare('SELECT id,name,email,bio,role FROM users WHERE id=?').get(q.user.id)));
app.get('/api/users/:id', (q, s) => s.json({
  ...db.prepare('SELECT id,name,bio FROM users WHERE id=?').get(q.params.id),
  followers: db.prepare('SELECT COUNT(*) c FROM follows WHERE b=?').get(q.params.id).c,
  posts: db.prepare('SELECT COUNT(*) c FROM posts WHERE author=?').get(q.params.id).c }));
app.post('/api/follow/:id', auth, wrap((q, s) => {
  const id = +q.params.id; if (id === q.user.id) throw new Error('Cannot follow yourself');
  const had = db.prepare('DELETE FROM follows WHERE a=? AND b=?').run(q.user.id, id).changes;
  if (!had) db.prepare('INSERT INTO follows VALUES(?,?)').run(q.user.id, id); s.json({ following: !had });
}));

// Social
app.get('/api/posts', (q, s) => {
  let uid = 0; try { uid = jwt.verify((q.headers.authorization || '').slice(7), SECRET).id } catch {}
  s.json(db.prepare(`SELECT p.*, u.name, (SELECT COUNT(*) FROM likes WHERE post=p.id) likes,
    (SELECT COUNT(*) FROM likes WHERE post=p.id AND user=?) liked,
    (SELECT COUNT(*) FROM comments WHERE post=p.id) comments FROM posts p JOIN users u ON u.id=p.author ORDER BY p.id DESC LIMIT 50`).all(uid));
});
app.post('/api/posts', auth, wrap((q, s) => {
  const body = str(q.body.body, 1000); if (!body) throw new Error('Write something');
  const img = String(q.body.img || '').startsWith('data:image/') ? q.body.img.slice(0, 1500000) : '';
  s.json({ id: db.prepare('INSERT INTO posts(author,body,img,created) VALUES(?,?,?,?)').run(q.user.id, body, img, now()).lastInsertRowid });
}));
app.delete('/api/posts/:id', auth, (q, s) => {
  const p = db.prepare('SELECT author FROM posts WHERE id=?').get(q.params.id);
  if (!p || (p.author !== q.user.id && q.user.role !== 'admin')) return s.status(403).json({ error: 'Not allowed' });
  db.prepare('DELETE FROM posts WHERE id=?').run(q.params.id); s.json({ ok: 1 });
});
app.post('/api/posts/:id/like', auth, (q, s) => {
  const had = db.prepare('DELETE FROM likes WHERE post=? AND user=?').run(q.params.id, q.user.id).changes;
  if (!had) db.prepare('INSERT INTO likes VALUES(?,?)').run(q.params.id, q.user.id); s.json({ liked: !had });
});
app.get('/api/posts/:id/comments', (q, s) => s.json(db.prepare('SELECT c.*,u.name FROM comments c JOIN users u ON u.id=c.author WHERE post=? ORDER BY c.id').all(q.params.id)));
app.post('/api/posts/:id/comments', auth, wrap((q, s) => {
  const b = str(q.body.body, 500); if (!b) throw new Error('Empty comment');
  db.prepare('INSERT INTO comments(post,author,body,created) VALUES(?,?,?,?)').run(q.params.id, q.user.id, b, now()); s.json({ ok: 1 });
}));

// Marketplace
app.get('/api/products', (q, s) => s.json(db.prepare('SELECT p.*,u.name seller_name FROM products p JOIN users u ON u.id=p.seller WHERE stock>0 AND (title LIKE ? OR descr LIKE ?) ORDER BY p.id DESC').all(`%${q.query.q || ''}%`, `%${q.query.q || ''}%`)));
app.post('/api/products', auth, wrap((q, s) => {
  const b = q.body, price = Math.round(+b.price), stock = Math.round(+b.stock);
  if (!str(b.title, 80) || !(price > 0) || !(stock >= 0)) throw new Error('Title, price (₦) and stock required');
  const img = String(b.img || '').startsWith('data:image/') ? b.img.slice(0, 1500000) : '';
  s.json({ id: db.prepare('INSERT INTO products(seller,title,descr,price,img,stock,created) VALUES(?,?,?,?,?,?,?)').run(q.user.id, str(b.title, 80), str(b.descr, 500), price, img, stock, now()).lastInsertRowid });
}));
app.get('/api/my/products', auth, (q, s) => s.json(db.prepare('SELECT * FROM products WHERE seller=? ORDER BY id DESC').all(q.user.id)));
app.delete('/api/products/:id', auth, (q, s) => {
  const r = db.prepare('DELETE FROM products WHERE id=? AND (seller=? OR ?)').run(q.params.id, q.user.id, q.user.role === 'admin' ? 1 : 0);
  s.json({ deleted: r.changes });
});
app.post('/api/orders', auth, wrap((q, s) => {
  const qty = Math.max(1, Math.round(+q.body.qty || 1));
  const tx = db.transaction(() => {
    const p = db.prepare('SELECT * FROM products WHERE id=?').get(q.body.product);
    if (!p || p.stock < qty) throw new Error('Out of stock');
    if (p.seller === q.user.id) throw new Error('You cannot buy your own product');
    db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(qty, p.id);
    return db.prepare('INSERT INTO orders(buyer,product,qty,total,created) VALUES(?,?,?,?,?)').run(q.user.id, p.id, qty, p.price * qty, now()).lastInsertRowid;
  });
  s.json({ id: tx() });
}));
app.get('/api/orders', auth, (q, s) => s.json(db.prepare(`SELECT o.*,p.title FROM orders o JOIN products p ON p.id=o.product WHERE o.buyer=? ORDER BY o.id DESC`).all(q.user.id)));
app.get('/api/sales', auth, (q, s) => s.json(db.prepare(`SELECT o.*,p.title,u.name buyer_name FROM orders o JOIN products p ON p.id=o.product JOIN users u ON u.id=o.buyer WHERE p.seller=? ORDER BY o.id DESC`).all(q.user.id)));
app.post('/api/orders/:id/status', auth, wrap((q, s) => {
  const st = q.body.status; if (!['pending', 'shipped', 'delivered', 'cancelled'].includes(st)) throw new Error('Bad status');
  const r = db.prepare('UPDATE orders SET status=? WHERE id=? AND product IN (SELECT id FROM products WHERE seller=?)').run(st, q.params.id, q.user.id);
  s.json({ updated: r.changes });
}));

// Games leaderboard
app.post('/api/scores', auth, wrap((q, s) => {
  const g = str(q.body.game, 20), sc = Math.round(+q.body.score);
  if (!g || !(sc >= 0) || sc > 1e6) throw new Error('Bad score');
  db.prepare('INSERT INTO scores(user,game,score,created) VALUES(?,?,?,?)').run(q.user.id, g, sc, now()); s.json({ ok: 1 });
}));
app.get('/api/scores/:game', (q, s) => s.json(db.prepare('SELECT u.name, MAX(sc.score) score FROM scores sc JOIN users u ON u.id=sc.user WHERE game=? GROUP BY sc.user ORDER BY score DESC LIMIT 10').all(q.params.game)));

// Admin
app.get('/api/admin/stats', auth, admin, (q, s) => s.json(Object.fromEntries(['users', 'products', 'orders', 'posts'].map(t => [t, db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c]))));
app.get('/api/admin/users', auth, admin, (q, s) => s.json(db.prepare('SELECT id,name,email,role,created FROM users ORDER BY id DESC').all()));

app.get('/api/health', (q, s) => s.json({ ok: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.listen(process.env.PORT || 3000, () => console.log('PO WORLD 3.0 running'));
