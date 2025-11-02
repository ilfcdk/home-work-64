// Реалізація EXPRESS сервера відповідно до завдання, описаного у файлі ASSIGNMENT.md

// Імпортуємо необхідні модулі
import express from 'express';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import pug from 'pug';
import ejs from 'ejs';
import bcrypt from 'bcryptjs';
import favicon from 'serve-favicon';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';

// Створюємо EXPRESS сервер
const app = express();

/**
 * ====== РЕЖИМИ СУМІСНОСТІ (ENV) ======
 * DELETE_MODE:
 *   - 'text' → повертати 200 і фразу "Delete ... by Id route: {id}"
 *   - інше → RESTful 204 No Content (за замовчуванням)
 */
const DELETE_MODE = process.env.DELETE_MODE === 'text' ? 'text' : '204';

// ===== Мідлвари базового рівня =====

// Cookies → до сесій
app.use(cookieParser());

// JSON / forms
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Акуратний 400 для кривого JSON
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    res.type('text/plain; charset=utf-8');
    return res.status(400).send('Bad Request');
  }
  return next(err);
});

// Сесії (для Passport; у продакшні використовуйте зовнішній стор)
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'dev-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,      // не доступний з JS
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production', // у продакшні через HTTPS
    maxAge: 7 * 24 * 3600 * 1000, // 7 днів
  }
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());

// Примітивний кореляційний ID для логів
let rid = 0;
app.use((req, _res, next) => {
  req.id = (++rid).toString().padStart(6, '0');
  next();
});

// ---- View engines + статика ----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.resolve(path.dirname(__filename));

app.engine('pug', pug.__express);
app.engine('ejs', ejs.__express);

app.set('views', [
  path.join(__dirname, 'views', 'pug'),
  path.join(__dirname, 'views', 'ejs'),
]);

// Статика
app.use('/public', express.static(path.join(__dirname, 'public'), {
  fallthrough: true,
  maxAge: '7d',
}));

// Favicon
const favPath = path.join(__dirname, 'public', 'favicon.ico');
if (fs.existsSync(favPath)) {
  app.use(favicon(favPath));
} else {
  app.get('/favicon.ico', (_req, res) => res.status(204).end());
}

// ---- Контент-неґоціація: HTML vs text/plain ----
function wantsHtml(req) {
  const accept = String(req.headers['accept'] || '').toLowerCase();
  if (accept.includes('text/html')) return true;
  const ua = String(req.headers['user-agent'] || '').toLowerCase();
  if (/(mozilla|chrome|safari|edg|firefox|opera)/i.test(ua)) return true;
  return false; // CLI / тести → text/plain
}

app.use((req, res, next) => {
  res.type(wantsHtml(req) ? 'text/html; charset=utf-8' : 'text/plain; charset=utf-8');
  next();
});

// --------- УТИЛІТИ/ВАЛІДАЦІЯ ---------
function logRequests(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    console.log(`${new Date().toISOString()} [${req.id}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
}

const isPositiveInt = (v) => /^\d+$/.test(String(v));
function validateIdParam(paramName) {
  return (req, res, next) => {
    const id = req.params[paramName];
    if (!isPositiveInt(id)) {
      return res.status(404).send('Not Found');
    }
    next();
  };
}

function validateUserBody(req, res, next) {
  const b = req.body ?? {};
  const hasPerson =
    typeof b.surname === 'string' && b.surname.trim() !== '' &&
    typeof b.firstName === 'string' && b.firstName.trim() !== '';
  const hasName = typeof b.name === 'string' && b.name.trim() !== '';
  if (hasPerson || hasName) return next();
  return res.status(400).send('Bad Request');
}

function validateArticleBody(req, res, next) {
  const { title } = req.body ?? {};
  if (typeof title !== 'string' || title.trim() === '') {
    return res.status(400).send('Bad Request');
  }
  next();
}

// --------- "МОДЕЛІ" (in-memory) ---------
const users = new Map();
const articles = new Map();
let userSeq = 1;
let articleSeq = 1;

// системні записи id=0 (не показуються у списках)
if (!users.has(0)) {
  users.set(0, { id: 0, surname: '', firstName: '', email: '', info: '', name: 'System User' });
}
if (!articles.has(0)) {
  articles.set(0, { id: 0, title: 'System Article' });
}

// Дуже просте in-memory сховище обліковок (email → { id, email, passHash, role })
const authUsers = new Map();

// Улюблена тема з cookies → у шаблони (PUG/EJS)
app.use((req, res, next) => {
  res.locals.theme = req.cookies?.theme || 'light';
  next();
});

// Поточний користувач (Passport) → у шаблони
app.use((req, res, next) => {
  res.locals.currentUser = req.user ? { id: req.user.id, email: req.user.email, role: req.user.role } : null;
  next();
});

// --------- Passport Local Strategy ---------
passport.use(new LocalStrategy(
  {
    usernameField: 'email', // беремо email як "username"
    passwordField: 'password',
    passReqToCallback: false
  },
  async (email, password, done) => {
    try {
      const rec = authUsers.get(String(email).toLowerCase().trim());
      if (!rec) return done(null, false, { message: 'Невірні облікові дані' });
      const ok = await bcrypt.compare(password, rec.passHash);
      if (!ok) return done(null, false, { message: 'Невірні облікові дані' });
      return done(null, { id: rec.id, email: rec.email, role: rec.role });
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id); // кладемо в сесію лише id
});

passport.deserializeUser((id, done) => {
  // знаходимо користувача за id
  for (const rec of authUsers.values()) {
    if (rec.id === id) {
      return done(null, { id: rec.id, email: rec.email, role: rec.role });
    }
  }
  return done(null, false);
});

// --------- ХЕЛПЕРИ ДЛЯ 401/ДОСТУПУ ---------
function flashAndRedirectHome(req, res, message) {
  if (wantsHtml(req)) {
    req.session.flash = message;
    return res.redirect(303, '/');
  }
  return res.status(401).send('Unauthorize');
}

function ensureAuthenticatedView(req, res, next) {
  if (!wantsHtml(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return flashAndRedirectHome(req, res, 'Необхідна авторизація');
}

function ensureAuthenticatedApi(req, res, next) {
  if (wantsHtml(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).send('Unauthorize');
}

function ensureAuthenticatedAny(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return flashAndRedirectHome(req, res, 'Необхідна авторизація');
}

// ---------- МАРШРУТИ ----------

// Головна
app.get('/', logRequests, (req, res) => {
  if (!wantsHtml(req)) {
    return res.status(200).send('Get root route');
  }
  const msg = req.session.flash || null;
  delete req.session.flash;
  return res.status(200).render('main.pug', { title: 'Main', msg });
});

// ====== Аутентифікація через Passport (Local) ======

// Форма логіну / реєстрації
app.get('/auth/login', (req, res) => {
  if (!wantsHtml(req)) return res.status(404).send('Not Found');
  const msg = req.session.flash || null;
  delete req.session.flash;
  return res.status(200).render('auth-login.pug', { title: 'Login', msg });
});

app.get('/auth/register', (req, res) => {
  if (!wantsHtml(req)) return res.status(404).send('Not Found');
  const msg = req.session.flash || null;
  delete req.session.flash;
  return res.status(200).render('auth-register.pug', { title: 'Register', msg });
});

// POST /auth/register — створюємо обліковку (in-memory)
app.post('/auth/register', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').toLowerCase().trim();
    const password = String(req.body?.password || '');
    const role = String(req.body?.role || 'user').toLowerCase().trim();
    if (!email || !password) return res.status(400).send('Bad Request');
    if (authUsers.has(email)) return res.status(400).send('Bad Request');
    const passHash = await bcrypt.hash(password, 10);
    const id = `auth-${authUsers.size + 1}`;
    authUsers.set(email, { id, email, passHash, role });

    if (wantsHtml(req)) {
      req.session.flash = 'Registered';
      return res.redirect(303, '/auth/login');
    }
    return res.status(201).send('Registered');
  } catch (e) {
    next(e);
  }
});

// POST /auth/login — автентифікація через Passport
app.post('/auth/login',
  passport.authenticate('local', { failureRedirect: '/', failureMessage: true }),
  (req, res) => {
    if (wantsHtml(req)) {
      req.session.flash = 'Logged in';
      return res.redirect(303, '/');
    }
    return res.status(200).send('Logged in');
  }
);

// POST /auth/logout — вихід (очищаємо сесію)
app.post('/auth/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => {
      res.clearCookie('sid');
      if (wantsHtml(req)) return res.redirect(303, '/');
      return res.status(204).end();
    });
  });
});

// ====== Налаштування теми (cookies) ======
app.post('/preferences/theme', (req, res) => {
  const allowed = new Set(['light', 'dark', 'auto']);
  const theme = String(req.body?.theme || '').toLowerCase().trim();
  if (!allowed.has(theme)) return res.status(400).send('Bad Request');

  res.cookie('theme', theme, {
    httpOnly: false,
    sameSite: 'lax',
    maxAge: 90 * 24 * 3600 * 1000,
  });

  const back = req.get('referer') || '/';
  if (wantsHtml(req)) return res.redirect(303, back);
  return res.status(200).send('Theme saved');
});

// ===== USERS (PUG для HTML, text/plain для API/CLI) =====
const usersRouter = express.Router();

usersRouter.get('/', ensureAuthenticatedView, (req, res) => {
  if (!wantsHtml(req)) {
    return res.status(200).send('Get users route');
  }
  const list = Array.from(users.values())
    .filter(u => u.id !== 0)
    .sort((a, b) => a.id - b.id);

  const msg = req.session.flash || null;
  delete req.session.flash;

  return res.status(200).render('users-index.pug', {
    title: 'Users',
    users: list,
    msg,
  });
});

usersRouter.post('/', ensureAuthenticatedApi, validateUserBody, (req, res) => {
  const b = req.body ?? {};
  const id = userSeq++;

  let record;
  if ((b.surname && b.firstName) || wantsHtml(req)) {
    const surname = String(b.surname || '').trim();
    const firstName = String(b.firstName || '').trim();
    const email = String(b.email || '').trim();
    const info = String(b.info || '').trim();
    const displayName = `${surname} ${firstName}`.trim() || String(b.name || '').trim();
    record = { id, surname, firstName, email, info, name: displayName };
  } else {
    const name = String(b.name || '').trim();
    record = { id, name };
  }

  users.set(id, record);

  if (wantsHtml(req)) {
    req.session.flash = 'Post users route';
    return res.redirect(303, '/users');
  }
  return res.status(201).send('Post users route');
});

usersRouter.get('/:userId', ensureAuthenticatedView, validateIdParam('userId'), (req, res) => {
  const { userId } = req.params;
  const id = Number(userId);
  const exists = users.has(id);

  if (!wantsHtml(req)) {
    return res.status(200).send(`Get user by Id route: ${userId}`);
  }

  if (!exists) {
    return res.status(404).render('users-not-found.pug', {
      title: 'User not found',
      userId: id,
    });
  }

  const entity = users.get(id);
  return res.status(200).render('users-show.pug', {
    title: `User ${id}`,
    user: entity,
  });
});

usersRouter.put('/:userId', ensureAuthenticatedApi, validateIdParam('userId'), validateUserBody, (req, res) => {
  const { userId } = req.params;
  const b = req.body ?? {};
  const id = Number(userId);

  if (b.surname && b.firstName) {
    const surname = String(b.surname || '').trim();
    const firstName = String(b.firstName || '').trim();
    const email = String(b.email || '').trim();
    const info = String(b.info || '').trim();
    const displayName = `${surname} ${firstName}`.trim();
    users.set(id, { id, surname, firstName, email, info, name: displayName });
  } else {
    const name = String(b.name || '').trim();
    users.set(id, { id, name });
  }

  res.status(200).send(`Put user by Id route: ${userId}`);
});

usersRouter.delete('/:userId', ensureAuthenticatedApi, validateIdParam('userId'), (req, res) => {
  const { userId } = req.params;
  const id = Number(userId);
  if (id !== 0) users.delete(id);
  if (DELETE_MODE === 'text') {
    return res.status(200).send(`Delete user by Id route: ${userId}`);
  }
  return res.status(204).end();
});

app.use('/users', usersRouter);

// ===== ARTICLES (EJS для HTML, text/plain для API/CLI) =====
const articlesRouter = express.Router();

articlesRouter.get('/', ensureAuthenticatedView, async (req, res) => {
  try {
    if (!wantsHtml(req)) {
      return res.status(200).send('Get articles route');
    }

    const list = Array.from(articles.values())
      .filter(a => a.id !== 0)
      .sort((a, b) => a.id - b.id);

    const msg = req.session.flash || null;
    delete req.session.flash;

    const contentHtml = await new Promise((resolve, reject) => {
      ejs.renderFile(
        path.join(__dirname, 'views', 'ejs', 'articles-index.ejs'),
        { title: 'Articles', articles: list, msg },
        (err, html) => (err ? reject(err) : resolve(html))
      );
    });

    return res.status(200).render('layout.ejs', { title: 'Articles', body: contentHtml });
  } catch (err) {
    console.error('[GET /articles] render error:', err);
    return res.status(500).type('text/plain; charset=utf-8').send('Internal Server Error');
  }
});

articlesRouter.post('/', ensureAuthenticatedApi, validateArticleBody, (req, res) => {
  const { title } = req.body;
  const id = articleSeq++;
  articles.set(id, { id, title: title.trim() });

  if (wantsHtml(req)) {
    req.session.flash = 'Post articles route';
    return res.redirect(303, '/articles');
  }
  return res.status(201).send('Post articles route');
});

articlesRouter.get('/:articleId', ensureAuthenticatedView, validateIdParam('articleId'), (req, res) => {
  const { articleId } = req.params;
  const id = Number(articleId);
  const exists = articles.has(id);

  if (!wantsHtml(req)) {
    return res.status(200).send(`Get article by Id route: ${articleId}`);
  }

  if (!exists) {
    return ejs.renderFile(
      path.join(__dirname, 'views', 'ejs', 'articles-not-found.ejs'),
      { title: 'Article not found', articleId: id },
      (err, html) => {
        if (err) { console.error(err); return res.status(500).send('Internal Server Error'); }
        return res.status(404).render('layout.ejs', { title: 'Article not found', body: html });
      }
    );
  }

  const entity = articles.get(id);
  return ejs.renderFile(
    path.join(__dirname, 'views', 'ejs', 'articles-show.ejs'),
    { title: `Article ${id}`, article: entity },
    (err, html) => {
      if (err) { console.error(err); return res.status(500).send('Internal Server Error'); }
      return res.status(200).render('layout.ejs', { title: `Article ${id}`, body: html });
    }
  );
});

articlesRouter.put('/:articleId', ensureAuthenticatedApi, validateIdParam('articleId'), validateArticleBody, (req, res) => {
  const { articleId } = req.params;
  const { title } = req.body;
  const id = Number(articleId);
  articles.set(id, { id, title: title.trim() }); // upsert
  res.status(200).send(`Put article by Id route: ${articleId}`);
});

articlesRouter.delete('/:articleId', ensureAuthenticatedApi, validateIdParam('articleId'), (req, res) => {
  const { articleId } = req.params;
  const id = Number(articleId);
  if (id !== 0) articles.delete(id);
  if (DELETE_MODE === 'text') {
    return res.status(200).send(`Delete article by Id route: ${articleId}`);
  }
  return res.status(204).end();
});

app.use('/articles', articlesRouter);

// ===== PROTECTED (Passport-сесія обов'язкова) =====
app.get('/protected', ensureAuthenticatedAny, (req, res) => {
  if (!wantsHtml(req)) {
    return res.status(200).send(`Protected content for ${req.user.email}`);
  }
  return res.status(200).render('main.pug', { title: 'Protected', msg: `Вітаю, ${req.user.email}! Це захищена сторінка.` });
});

// ---------- ГЛОБАЛЬНІ ОБРОБНИКИ ----------
app.use((req, res) => {
  res.status(404).send('Not Found');
});

app.use((err, req, res, next) => {
  console.error(err?.stack || err);
  res.status(500).send('Internal Server Error');
});

// ---------- СТВОРЕННЯ СЕРВЕРА ----------
const PORT = process.env.PORT ? Number(process.env.PORT) : 3000; // порт 3000
const HOST = process.env.HOST || '0.0.0.0';
const server = app.listen(PORT, HOST, () => {
  console.log(`[boot] server listening on http://${HOST}:${PORT}`);
});

// Експорт для тестів
export { server, app };
