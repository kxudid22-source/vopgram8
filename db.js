const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'vopgram.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE,
  username TEXT UNIQUE,
  name TEXT,
  bio TEXT DEFAULT '',
  avatar_url TEXT DEFAULT '',
  password_hash TEXT,
  balance INTEGER DEFAULT 100,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  last_seen INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  device_info TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  confirmed INTEGER DEFAULT 1,
  created_at INTEGER DEFAULT (strftime('%s','now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT DEFAULT 'private',
  title TEXT DEFAULT '',
  created_at INTEGER DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS chat_members (
  chat_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  role TEXT DEFAULT 'member',
  joined_at INTEGER DEFAULT (strftime('%s','now')),
  PRIMARY KEY(chat_id, user_id),
  FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  chat_id INTEGER NOT NULL,
  sender_id INTEGER NOT NULL,
  text TEXT NOT NULL,
  type TEXT DEFAULT 'text',
  created_at INTEGER DEFAULT (strftime('%s','now')),
  FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE,
  FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS gifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  icon TEXT NOT NULL,
  price INTEGER NOT NULL,
  market INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS user_gifts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  gift_id INTEGER NOT NULL,
  purchased_at INTEGER DEFAULT (strftime('%s','now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(gift_id) REFERENCES gifts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS verification_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  code TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS anonymous_numbers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE NOT NULL,
  telegram_user_id TEXT,
  issued_at INTEGER DEFAULT (strftime('%s','now')),
  used INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS device_confirmations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  session_id INTEGER,
  device_info TEXT DEFAULT '',
  ip TEXT DEFAULT '',
  status TEXT DEFAULT 'pending',
  created_at INTEGER DEFAULT (strftime('%s','now')),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// migrations for new columns
function tryAlter(sql) { try { db.exec(sql); } catch (e) {} }
tryAlter('ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0');
tryAlter('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0');
tryAlter('ALTER TABLE users ADD COLUMN major INTEGER DEFAULT 0');
tryAlter('ALTER TABLE messages ADD COLUMN gift_id INTEGER');
tryAlter('ALTER TABLE chats ADD COLUMN channel INTEGER DEFAULT 0');
tryAlter('ALTER TABLE chats ADD COLUMN subscribers INTEGER DEFAULT 0');

// seed gifts if empty
const giftCount = db.prepare('SELECT COUNT(*) as c FROM gifts').get().c;
if (giftCount < 15) {
  db.prepare('DELETE FROM user_gifts').run();
  db.prepare('DELETE FROM gifts').run();
  const insert = db.prepare('INSERT INTO gifts (name, icon, price, market) VALUES (?,?,?,?)');
  const gifts = [
    ['Роза', '🌹', 15, 0],
    ['Торт', '🎂', 50, 0],
    ['Конфета', '🍬', 25, 0],
    ['Сердце', '❤️', 35, 0],
    ['Звезда', '⭐', 40, 0],
    ['Ракета', '🚀', 100, 1],
    ['Алмаз', '💎', 150, 1],
    ['Трофей', '🏆', 200, 0],
    ['Кольцо', '💍', 430, 1],
    ['Корона', '👑', 500, 1],
    ['Единорог', '🦄', 350, 1],
    ['Дракон', '🐉', 700, 1],
    ['Пламя', '🔥', 60, 0],
    ['Подарок', '🎁', 80, 0],
    ['Шампанское', '🍾', 120, 1],
  ];
  for (const g of gifts) insert.run(...g);
}

// seed demo users if empty
const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
if (userCount === 0) {
  const bcrypt = require('bcryptjs');
  const insert = db.prepare('INSERT INTO users (phone, username, name, bio, balance) VALUES (?,?,?,?,?)');
  // service account
  insert.run('+42777 00 00 00', 'vopgram', 'Vopgram', 'Служебные уведомления', 0);
  insert.run('+888 100 00 01', 'cat_cap', 'Кот в кепке', 'Главный кот Vopgram', 500);
  insert.run('+888 100 00 02', 'anime_girl', 'Аниме Девушка', 'Kawaii~', 300);
  insert.run('+888 100 00 03', 'meme_lord', 'Мем Лорд', 'Мемы — это жизнь', 150);
  // create a general chat
  const chat = db.prepare('INSERT INTO chats (type, title) VALUES (?,?)').run('group', 'Vopgram News');
  const cid = chat.lastInsertRowid;
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?,?)').run(cid, 1);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?,?)').run(cid, 2);
  db.prepare('INSERT INTO chat_members (chat_id, user_id) VALUES (?,?)').run(cid, 3);
  db.prepare('INSERT INTO messages (chat_id, sender_id, text) VALUES (?,?,?)').run(cid, 1, 'Добро пожаловать в Vopgram! 🎉');
  db.prepare('INSERT INTO messages (chat_id, sender_id, text) VALUES (?,?,?)').run(cid, 2, 'Привет всем! 👋');
  db.prepare("UPDATE users SET verified=1, major=1, balance=0 WHERE username='vopgram'").run();
}

module.exports = db;
