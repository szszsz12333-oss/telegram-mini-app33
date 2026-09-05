import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
loadEnv(join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 3000);
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_IDS = new Set((process.env.ADMIN_IDS || '').split(',').map((value) => value.trim()).filter(Boolean));
const PAYMENT_DETAILS = (process.env.PAYMENT_DETAILS || '').replace(/\\n/g, '\n');
const APP_ORIGIN = process.env.APP_ORIGIN || '';
const MAX_INIT_DATA_AGE_SECONDS = Number(process.env.INIT_DATA_MAX_AGE_SECONDS || 86400);
const STATIC_DIR = resolve(__dirname);
const DATA_DIR = resolve(process.env.DATA_DIR || join(__dirname, 'runtime'));
const STATE_FILE = join(DATA_DIR, 'state.json');

const TARIFFS = Object.freeze({
  '30': { days: 30, price: 1500 },
  '60': { days: 60, price: 2899 },
  '90': { days: 90, price: 4299 },
  '120': { days: 120, price: 5699 },
});

mkdirSync(DATA_DIR, { recursive: true });
let state = loadState();
let updateOffset = 0;

function loadEnv(filename) {
  if (!existsSync(filename)) return;
  for (const rawLine of readFileSync(filename, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const separator = line.indexOf('=');
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim().replace(/^['"]|['"]$/g, '');
    if (!(key in process.env)) process.env[key] = value;
  }
}

function loadState() {
  if (!existsSync(STATE_FILE)) return { orders: {}, access: {} };
  try {
    const parsed = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
    return { orders: parsed.orders || {}, access: parsed.access || {} };
  } catch {
    throw new Error('Не удалось прочитать runtime/state.json. Исправьте JSON или восстановите файл.');
  }
}

function persistState() {
  const temporary = `${STATE_FILE}.tmp`;
  writeFileSync(temporary, JSON.stringify(state, null, 2), 'utf8');
  renameSync(temporary, STATE_FILE);
}

function json(response, status, payload) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

function setCors(request, response) {
  const origin = request.headers.origin;
  if (origin && (!APP_ORIGIN || origin === APP_ORIGIN)) {
    response.setHeader('Access-Control-Allow-Origin', origin);
    response.setHeader('Vary', 'Origin');
    response.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
}

async function readJson(request) {
  let raw = '';
  for await (const chunk of request) {
    raw += chunk;
    if (raw.length > 32_768) throw new Error('Завеликий запит.');
  }
  try { return JSON.parse(raw); } catch { throw new Error('Некоректний JSON.'); }
}

function telegramUserFromInitData(initData) {
  if (!BOT_TOKEN) throw new Error('BOT_TOKEN не налаштований на сервері.');
  const params = new URLSearchParams(initData);
  const receivedHash = params.get('hash');
  const authDate = Number(params.get('auth_date'));
  if (!receivedHash || !authDate) throw new Error('Telegram не передав дані авторизації.');
  if (Math.abs(Date.now() / 1000 - authDate) > MAX_INIT_DATA_AGE_SECONDS) throw new Error('Сесію Telegram завершено. Відкрийте Mini App ще раз.');

  params.delete('hash');
  const dataCheckString = [...params.entries()]
    .sort(([keyA], [keyB]) => keyA.localeCompare(keyB))
    .map(([key, value]) => `${key}=${value}`)
    .join('\n');
  const secret = createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
  const expectedHash = createHmac('sha256', secret).update(dataCheckString).digest('hex');
  const received = Buffer.from(receivedHash, 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (received.length !== expected.length || !timingSafeEqual(received, expected)) throw new Error('Не вдалося перевірити Telegram-підпис.');

  const rawUser = params.get('user');
  if (!rawUser) throw new Error('Telegram не передав користувача. Відкрийте застосунок у приватному чаті з ботом.');
  const user = JSON.parse(rawUser);
  if (!user?.id) throw new Error('Некоректні дані користувача Telegram.');
  return user;
}

function makeOrderId() {
  const suffix = randomBytes(4).toString('hex').toUpperCase();
  return `ORD-${Date.now().toString(36).toUpperCase()}-${suffix}`;
}

async function telegramApi(method, payload) {
  if (!BOT_TOKEN) throw new Error('BOT_TOKEN не налаштований.');
  const response = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const result = await response.json();
  if (!response.ok || !result.ok) throw new Error(result.description || `Telegram API: ${method} failed`);
  return result.result;
}

async function sendPaymentInstructions(order) {
  const tariff = TARIFFS[order.tariffId];
  const text = [
    `Заявка № ${order.id}`,
    '',
    'Послуга: Відстрочка',
    `Термін доступу: ${tariff.days} днів`,
    `До сплати: ${tariff.price.toLocaleString('uk-UA')} грн`,
    '',
    'Актуальні реквізити для оплати:',
    PAYMENT_DETAILS,
    '',
    'Після переказу очікуйте ручного підтвердження. Доступ до бота буде активовано автоматично після підтвердження адміністратором.',
  ].join('\n');
  await telegramApi('sendMessage', { chat_id: order.userId, text });
}

function currentAccess(userId) {
  const access = state.access[String(userId)];
  return access && new Date(access.validUntil) > new Date() ? access : null;
}

function confirmOrder(orderId, adminId) {
  const order = state.orders[orderId];
  if (!order) throw new Error('Заявку не знайдено.');
  if (order.status !== 'pending') throw new Error(`Заявка вже має статус: ${order.status}.`);

  const tariff = TARIFFS[order.tariffId];
  const existing = state.access[String(order.userId)];
  const now = new Date();
  const startDate = existing && new Date(existing.validUntil) > now ? new Date(existing.validUntil) : now;
  startDate.setUTCDate(startDate.getUTCDate() + tariff.days);

  state.access[String(order.userId)] = {
    userId: order.userId,
    validUntil: startDate.toISOString(),
    lastOrderId: order.id,
  };
  order.status = 'paid';
  order.confirmedAt = now.toISOString();
  order.confirmedBy = String(adminId);
  persistState();
  return { order, validUntil: startDate };
}

function isAdmin(userId) { return ADMIN_IDS.has(String(userId)); }

function formatDate(date) {
  return new Intl.DateTimeFormat('uk-UA', { day: '2-digit', month: 'long', year: 'numeric', timeZone: 'Europe/Kyiv' }).format(date);
}

async function handleBotMessage(message) {
  const text = message.text?.trim();
  const userId = message.from?.id;
  if (!text || !userId) return;

  if (text === '/status') {
    const access = currentAccess(userId);
    const reply = access
      ? `Ваш доступ активний до ${formatDate(new Date(access.validUntil))}.`
      : 'Активного доступу немає. Відкрийте Mini App, щоб створити заявку.';
    await telegramApi('sendMessage', { chat_id: userId, text: reply });
    return;
  }

  if (!isAdmin(userId)) return;
  const [command, rawOrderId] = text.split(/\s+/, 2);
  const orderId = rawOrderId?.toUpperCase();

  if (command === '/confirm') {
    if (!orderId) throw new Error('Використовуйте: /confirm ORD-...');
    const { order, validUntil } = confirmOrder(orderId, userId);
    await telegramApi('sendMessage', {
      chat_id: order.userId,
      text: `Оплату за заявкою № ${order.id} підтверджено. Доступ до бота активний до ${formatDate(validUntil)}.`,
    });
    await telegramApi('sendMessage', { chat_id: userId, text: `Готово. Доступ активний до ${formatDate(validUntil)}.` });
    return;
  }

  if (command === '/reject') {
    if (!orderId) throw new Error('Використовуйте: /reject ORD-...');
    const order = state.orders[orderId];
    if (!order) throw new Error('Заявку не знайдено.');
    if (order.status !== 'pending') throw new Error(`Заявка вже має статус: ${order.status}.`);
    order.status = 'cancelled';
    order.cancelledAt = new Date().toISOString();
    order.cancelledBy = String(userId);
    persistState();
    await telegramApi('sendMessage', { chat_id: order.userId, text: `Заявку № ${order.id} скасовано. Зверніться до адміністратора, якщо це помилка.` });
    await telegramApi('sendMessage', { chat_id: userId, text: `Заявку ${order.id} скасовано.` });
    return;
  }

  if (command === '/orders') {
    const pending = Object.values(state.orders).filter((order) => order.status === 'pending').slice(-20);
    const textResponse = pending.length
      ? pending.map((order) => `${order.id} — ${TARIFFS[order.tariffId].days} днів, ${TARIFFS[order.tariffId].price} грн`).join('\n')
      : 'Активних заявок немає.';
    await telegramApi('sendMessage', { chat_id: userId, text: textResponse });
  }
}

async function pollUpdates() {
  if (!BOT_TOKEN) return;
  try {
    const updates = await telegramApi('getUpdates', { offset: updateOffset, timeout: 25, allowed_updates: ['message'] });
    for (const update of updates) {
      updateOffset = update.update_id + 1;
      if (update.message) {
        try { await handleBotMessage(update.message); }
        catch (error) {
          if (update.message.chat?.id) await telegramApi('sendMessage', { chat_id: update.message.chat.id, text: error.message || 'Сталася помилка.' });
        }
      }
    }
  } catch (error) {
    console.error('Помилка отримання повідомлень Telegram:', error.message);
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 5000));
  }
  setImmediate(pollUpdates);
}

function staticFile(response, pathname) {
  const requested = pathname === '/' ? '/index.html' : pathname;
  const filePath = resolve(STATIC_DIR, `.${normalize(requested)}`);
  if (!filePath.startsWith(STATIC_DIR) || !existsSync(filePath)) return false;
  const mimeTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
  response.writeHead(200, { 'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
  response.end(readFileSync(filePath));
  return true;
}

const server = createServer(async (request, response) => {
  setCors(request, response);
  if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return; }
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  if (request.method === 'GET' && url.pathname === '/api/health') {
    json(response, 200, { ok: true, botConfigured: Boolean(BOT_TOKEN), paymentConfigured: Boolean(PAYMENT_DETAILS) });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/orders') {
    try {
      if (!PAYMENT_DETAILS) throw new Error('Реквізити для оплати не налаштовані. Зверніться до адміністратора.');
      const body = await readJson(request);
      if (body.serviceId !== 'vidstrochka' || !TARIFFS[body.tariffId]) throw new Error('Оберіть коректний тариф.');
      const user = telegramUserFromInitData(String(body.initData || ''));
      const order = {
        id: makeOrderId(),
        userId: user.id,
        serviceId: 'vidstrochka',
        tariffId: body.tariffId,
        status: 'pending',
        createdAt: new Date().toISOString(),
      };
      state.orders[order.id] = order;
      persistState();
      await sendPaymentInstructions(order);
      json(response, 201, { orderId: order.id });
    } catch (error) {
      const clientMessage = error.message || 'Не вдалося створити заявку.';
      const status = /Telegram-підпис|сесію|Telegram не передав|BOT_TOKEN/.test(clientMessage) ? 401 : 400;
      json(response, status, { message: clientMessage });
    }
    return;
  }

  if (request.method === 'GET' && staticFile(response, url.pathname)) return;
  json(response, 404, { message: 'Не знайдено.' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Mini App server started: http://localhost:${PORT}`);
  if (!BOT_TOKEN) console.warn('BOT_TOKEN не задано: створення заявок і команди бота вимкнені.');
  if (!ADMIN_IDS.size) console.warn('ADMIN_IDS не задано: команди /confirm, /reject і /orders нікому не доступні.');
});

pollUpdates();
