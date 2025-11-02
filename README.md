# Авторизація з Passport (Local Strategy) на Express-сервері

Цей етап (№5) розширює попередній проєкт: інтегровано **Passport** з локальною стратегією (email + пароль), **сесії** через `express-session`, збереження `sid` у **httpOnly** cookies, а також додано **захищений маршрут** `/protected`. Збережено попередній функціонал PUG/EJS, статичні файли (favicon, CSS), теми (cookies), users/articles.

---

## Зміст
- [Можливості](#можливості)
- [Вимоги](#вимоги)
- [Встановлення](#встановлення)
- [Запуск](#запуск)
- [Налаштування середовища (ENV)](#налаштування-середовища-env)
- [Структура проєкту](#структура-проєкту)
- [Як працює авторизація (Passport + сесії)](#як-працює-авторизація-passport--сесії)
- [Маршрути](#маршрути)
  - [/ (головна)](#-головна)
  - [/auth/* (реєстрація/вхід/вихід)](#auth-реєстраціявхідвихід)
  - [/users (PUG)](#users-pug)
  - [/articles (EJS)](#articles-ejs)
  - [/protected](#protected)
  - [/preferences/theme](#preferencestheme)
- [Валідація, статуси, помилки](#валідація-статуси-помилки)
- [Приклади (cURL)](#приклади-curl)
- [Поради та усунення проблем](#поради-та-усунення-проблем)
- [Що далі (необов’язково)](#що-далі-необовязково)

---

## Можливості
- **Passport (Local Strategy)** з перевіркою `email + password`.
- **Сесійна авторизація**: `express-session` + `passport.session()`; cookie `sid` — httpOnly, `sameSite=lax`, у продакшні `secure=true`.
- **Захищений маршрут** `/protected` (лише для залогінених).
- **Захист HTML-сторінок `/users`, `/articles`** — лише залогіненим.
- **Content negotiation**: HTML для браузера, `text/plain` для CLI.
- **PUG** для `users`, **EJS** для `articles`, **favicon** і **CSS** зі `/public`.
- **Теми** (light/dark/auto) зберігаються у cookies.

---

## Вимоги
- Node.js 18+
- npm або yarn

---

## Встановлення
```bash
npm install
# або
yarn
```
Необхідні пакети: `express`, `express-session`, `cookie-parser`, `serve-favicon`, `passport`, `passport-local`, `bcryptjs`, `pug`, `ejs`.

---

## Запуск
```bash
node src/server.mjs
# або автоперезапуск (Node 18+)
node --watch src/server.mjs
```
За замовчуванням сервер слухає **порт 3000**.

Відкрити у браузері:
- Головна: `http://localhost:3000/`
- Реєстрація/Вхід: `http://localhost:3000/auth/register`, `http://localhost:3000/auth/login`
- Users (PUG): `http://localhost:3000/users`
- Articles (EJS): `http://localhost:3000/articles`
- Захищено: `http://localhost:3000/protected`

---

## Налаштування середовища (ENV)
- `PORT` — порт сервера (дефолт `3000`).
- `SESSION_SECRET` — секрет для підпису сесій (дефолт: `dev-session-secret`).
- `NODE_ENV=production` — увімкне `cookie.secure=true` (HTTPS обов’язковий).
- `DELETE_MODE` — якщо `text`, тоді DELETE повертає **200 OK** з текстом; інакше — **204 No Content**.

**Приклад (Windows CMD):**
```bat
set PORT=3000
set SESSION_SECRET=super-secret
node src\server.mjs
```

---

## Структура проєкту
```
src/
├─ server.mjs
├─ views/
│  ├─ pug/
│  │  ├─ layout.pug
│  │  ├─ main.pug
│  │  ├─ users-index.pug
│  │  ├─ users-show.pug
│  │  └─ users-not-found.pug
│  └─ ejs/
│     ├─ layout.ejs
│     ├─ articles-index.ejs
│     ├─ articles-show.ejs
│     └─ articles-not-found.ejs
└─ public/
   ├─ favicon.ico
   └─ css/
      └─ styles.css
```
> Дані (users/articles/акаунти) зберігаються **in-memory** та зникають після перезапуску.

---

## Як працює авторизація (Passport + сесії)
1. **Реєстрація** (`/auth/register`): створюється запис у пам’яті — `{ id, email, passHash, role }` (пароль хешується `bcryptjs`).
2. **Вхід** (`/auth/login`): `passport-local` перевіряє `email` та пароль (`bcrypt.compare`).
3. **Сесія**: `passport.serializeUser` зберігає `user.id` у сесії; `passport.deserializeUser` відновлює користувача за `id`.
4. **Cookie `sid`**: браузер зберігає ідентифікатор сесії (httpOnly). За `NODE_ENV=production` — тільки по HTTPS.
5. **Доступ**: мідлвари перевіряють `req.isAuthenticated()` і не пускають незалогінених на HTML-сторінки `/users`, `/articles` та `/protected` (редірект на `/` з повідомленням). Для CLI/API повертається `401 Unauthorize`.

---

## Маршрути

### `/` (головна)
- **GET /**  
  - HTML: `main.pug` (навігація + повідомлення)  
  - text: `Get root route`

### `/auth/*` (реєстрація/вхід/вихід)
- **GET /auth/register** — форма реєстрації (HTML).
- **POST /auth/register** — створює обліковку.  
  HTML: редірект на `/auth/login` · text: `201 Registered`.
- **GET /auth/login** — форма входу (HTML).
- **POST /auth/login** — перевірка email/пароля через Passport, встановлення сесії.  
  HTML: редірект на `/` · text: `200 Logged in`.
- **POST /auth/logout** — очищення сесії та cookie.  
  HTML: редірект на `/` · text: `204`.

> Невдала авторизація (HTML) → редірект на `/` із повідомленням «Unauthorize».  
> Для API/CLI → `401 Unauthorize`.

### `/users` (PUG)
> **HTML-сторінки лише для залогінених** (API GET лишається текстовим).

- **GET /users** — список + форма створення. HTML / text: `Get users route`.
- **POST /users** *(логін)* — HTML-форма або JSON API (`{ "name": "..." }`). HTML → редірект на `/users`; text → `201 Post users route`.
- **GET /users/:userId** *(логін для HTML)* — деталі або 404 (HTML); text → `Get user by Id route: {userId}`.
- **PUT /users/:userId** *(логін)* → `200 Put user by Id route: {userId}`.
- **DELETE /users/:userId** *(логін)* → `204` або `200` (за `DELETE_MODE`).

### `/articles` (EJS)
> **HTML-сторінки лише для залогінених**.

- **GET /articles** — список + форма створення. HTML / text: `Get articles route`.
- **POST /articles** *(логін)* — HTML → редірект на `/articles`; text → `201 Post articles route`.
- **GET /articles/:articleId** *(логін для HTML)* — деталі або 404 (HTML); text → `Get article by Id route: {articleId}`.
- **PUT /articles/:articleId** *(логін)* → `200 Put article by Id route: {articleId}`.
- **DELETE /articles/:articleId** *(логін)* → `204` або `200` (за `DELETE_MODE`).

### `/protected`
- **GET /protected** — лише для залогінених.  
  HTML: проста сторінка «захищено»; text: `Protected content for <email>`.

### `/preferences/theme`
- **POST /preferences/theme** — зберігає тему `light|dark|auto` у cookie `theme`.  
  HTML: редірект назад; text: `200 Theme saved`.

---

## Валідація, статуси, помилки
- **ID**: позитивне ціле (в т.ч. `0` — системний, у списках прихований).
- **Users**: HTML-форма — `surname`*, `firstName`* (+ `email?`, `info?`); або JSON `{ "name": "..." }`. Некоректні дані → `400`.
- **Articles**: `title`*; некоректні дані → `400`.
- **Статуси**: GET (text) → `200`; POST → `201`; PUT → `200`; DELETE → `204` або `200` (`DELETE_MODE=text`).
- Глобально: `404 Not Found`, `500 Internal Server Error` (міжмаршрутні мідлвари підключені після всіх маршрутів).

---

## Приклади (cURL)

**Реєстрація**
```bash
curl -i -X POST http://localhost:3000/auth/register   -H "Content-Type: application/json"   -d '{"email":"admin@example.com","password":"secret","role":"admin"}'
```

**Вхід** (запам’ятайте cookie `sid`)
```bash
curl -i -X POST http://localhost:3000/auth/login   -H "Content-Type: application/json"   -d '{"email":"admin@example.com","password":"secret"}'
```

**Захищений маршрут (передайте cookie з попередньої відповіді)**
```bash
curl -i http://localhost:3000/protected   -H "Cookie: sid=<СКОПІЙОВАНЕ_З_LOGIN>"
```

**Створення користувача (API)**
```bash
curl -i -X POST http://localhost:3000/users   -H "Content-Type: application/json"   -H "Cookie: sid=<…>"   -d '{"name":"Ada Lovelace"}'
```

**Створення статті (API)**
```bash
curl -i -X POST http://localhost:3000/articles   -H "Content-Type: application/json"   -H "Cookie: sid=<…>"   -d '{"title":"Hello from EJS"}'
```

---

## Поради та усунення проблем
- Незалогінений доступ до HTML `/users`, `/articles`, `/protected` → редірект на `/` з повідомленням «Unauthorize»; для API → `401 Unauthorize`.
- У продакшні вмикайте `NODE_ENV=production` — cookie стає `secure=true`, потрібен HTTPS.
- Дані зберігаються в пам’яті — після перезапуску порожні.
- Перевіряйте, що `public/favicon.ico` існує, а стилі підключені у `layout.pug`/`layout.ejs`.
- Якщо DELETE має повертати текст, встановіть `DELETE_MODE=text`.

---

Готово! Проєкт працює на **порті 3000**, з **Passport-сесіями**, захищеними сторінками і збереженням теми у cookies.
