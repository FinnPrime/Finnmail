const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const session = require("express-session");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const csurf = require("csurf");

const app = express();
const db = new sqlite3.Database("database.db");
const SALT_ROUNDS = 10;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

const csrfProtection = csurf();

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user TEXT NOT NULL,
      to_user TEXT NOT NULL,
      text TEXT NOT NULL
    )
  `);
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send("Нужен вход");
  }
  next();
}

app.get("/", (req, res) => {
  res.send("Сервер работает 🚀");
});

app.get("/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post("/register", csrfProtection, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).send("Нет данных");
    }

    if (username.length < 3) {
      return res.status(400).send("Логин слишком короткий");
    }

    if (password.length < 4) {
      return res.status(400).send("Пароль слишком короткий");
    }

    db.get(
      "SELECT id FROM users WHERE username = ?",
      [username],
      async (selectErr, existingUser) => {
        if (selectErr) {
          return res.status(500).send("Ошибка сервера");
        }

        if (existingUser) {
          return res.status(409).send("Пользователь уже существует");
        }

        try {
          const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

          db.run(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [username, hashedPassword],
            function (insertErr) {
              if (insertErr) {
                return res.status(500).send("Ошибка регистрации");
              }

              res.send("Пользователь создан ✅");
            }
          );
        } catch {
          res.status(500).send("Ошибка хеширования");
        }
      }
    );
  } catch {
    res.status(500).send("Ошибка сервера");
  }
});

app.post("/login", csrfProtection, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Нет данных");
  }

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        return res.status(500).send("Ошибка сервера");
      }

      if (!user) {
        return res.status(401).send("Неверный логин или пароль");
      }

      try {
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
          return res.status(401).send("Неверный логин или пароль");
        }

        req.session.user = {
          id: user.id,
          username: user.username
        };

        res.send("Вход выполнен ✅");
      } catch {
        res.status(500).send("Ошибка сервера");
      }
    }
  );
});

app.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ loggedIn: false });
  }

  res.json({
    loggedIn: true,
    user: req.session.user
  });
});

app.post("/logout", csrfProtection, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Ошибка выхода");
    }

    res.clearCookie("connect.sid");
    res.send("Выход выполнен");
  });
});

app.post("/send-local", requireAuth, csrfProtection, (req, res) => {
  const { to, subject, text } = req.body;
  const from = req.session.user.username;

  if (!to || !subject || !text) {
    return res.status(400).send("Нет данных");
  }

  db.get(
    "SELECT id FROM users WHERE username = ?",
    [to],
    (userErr, targetUser) => {
      if (userErr) {
        return res.status(500).send("Ошибка сервера");
      }

      if (!targetUser) {
        return res.status(404).send("Получатель не найден");
      }

      db.run(
        "INSERT INTO messages (from_user, to_user, subject, text) VALUES (?, ?, ?, ?)",
        [from, to, subject, text],
        (msgErr) => {
          if (msgErr) {
            return res.status(500).send("Ошибка отправки");
          }

          res.send("Сообщение отправлено ✅");
        }
      );
    }
  );
});

app.get("/inbox", requireAuth, (req, res) => {
  const username = req.session.user.username;

  db.all(
    "SELECT * FROM messages WHERE to_user = ? ORDER BY id DESC",
    [username],
    (err, rows) => {
      if (err) {
        return res.status(500).json([]);
      }

      res.json(rows);
    }
  );
});
app.get("/conversation/:username", requireAuth, (req, res) => {
  const currentUser = req.session.user.username;
  const otherUser = req.params.username;

  db.all(
    `SELECT id, from_user, to_user, subject, text
     FROM messages
     WHERE (from_user = ? AND to_user = ?)
        OR (from_user = ? AND to_user = ?)
     ORDER BY id ASC`,
    [currentUser, otherUser, otherUser, currentUser],
    (err, rows) => {
      if (err) {
        return res.status(500).json([]);
      }

      res.json(rows);
    }
  );
});
app.get("/conversations", requireAuth, (req, res) => {
  const currentUser = req.session.user.username;

  db.all(
    `SELECT 
        CASE
          WHEN from_user = ? THEN to_user
          ELSE from_user
        END AS username,
        MAX(id) as last_message_id
     FROM messages
     WHERE from_user = ? OR to_user = ?
     GROUP BY username
     ORDER BY last_message_id DESC`,
    [currentUser, currentUser, currentUser],
    (err, rows) => {
      if (err) {
        return res.status(500).json([]);
      }

      res.json(rows);
    }
  );
});
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).send("Неверный CSRF токен");
  }
  next(err);
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});