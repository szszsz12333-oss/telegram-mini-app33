import { createServer } from 'node:http';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
loadEnv(join(__dirname, '.env'));

const PORT = Number(process.env.PORT || 3000);
const BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_IDS = new Set((process.env.ADMIN_IDS || '').split(',').map((value) => value.trim()).filter(Boolean));
const PAYMENT_DETAILS = (process.env.PAYMENT_DETAILS || '').replace(/\\n/g, '\n');
const CRYPTO_PAYMENT_DETAILS = (process.env.CRYPTO_PAYMENT_DETAILS || '').replace(/\\n/g, '\n');
const PAYMENT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET || '';
const APP_ORIGIN = process.env.APP_ORIGIN || '';
const MINI_APP_URL = process.env.MINI_APP_URL || 'https://telegram-mini-app33.onrender.com/';
const ABOUT_IMAGE_URL = 'https://i.ibb.co/yBFsxMbm/about-service.jpg';
const SUPPORT_USERNAME = (process.env.SUPPORT_USERNAME || 'rezervmanage').replace(/^@/, '').trim();
const ALLOW_DEMO_ORDERS = process.env.ALLOW_DEMO_ORDERS === 'true';
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
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Payment-Webhook-Secret');
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

function isAuthorizedPaymentWebhook(request) {
  const receivedSecret = request.headers['x-payment-webhook-secret'];
  if (!PAYMENT_WEBHOOK_SECRET || typeof receivedSecret !== 'string') return false;
  const received = Buffer.from(receivedSecret, 'utf8');
  const expected = Buffer.from(PAYMENT_WEBHOOK_SECRET, 'utf8');
  return received.length === expected.length && timingSafeEqual(received, expected);
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
    `🧾 Заявка № ${order.id}`,
    '',
    'Послуга: Відстрочка',
    `📅 Термін доступу: ${tariff.days} днів`,
    `💳 До сплати: ${tariff.price.toLocaleString('uk-UA')} грн`,
    '',
    'Оберіть зручний спосіб оплати нижче.',
  ].join('\n');
  await telegramApi('sendMessage', {
    chat_id: order.userId,
    text,
    reply_markup: {
      inline_keyboard: [
        [{ text: '💠 Crypto', callback_data: `payment_crypto:${order.id}` }],
        [{ text: '💳 Картка — тимчасово не працює', callback_data: 'payment_card_unavailable' }],
      ],
    },
  });
}

async function replaceWithCryptoPaymentInstructions(query, order) {
  const tariff = TARIFFS[order.tariffId];
  const text = [
    `🧾 Заявка № ${order.id}`,
    '',
    `💠 До сплати у Crypto: еквівалент ${tariff.price.toLocaleString('uk-UA')} грн`,
    '',
    'Crypto-реквізити:',
    CRYPTO_PAYMENT_DETAILS,
    '',
    '🔔 Після переказу натисніть кнопку «Я оплатив(ла)». Система перевірить оплату та активує доступ.',
  ].join('\n');
  await replaceBotMessage(query, text, {
    inline_keyboard: [[{ text: '✅ Я оплатив(ла)', callback_data: `payment_report:${order.id}` }]],
  });
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

function customerDetails(order, fallbackUser) {
  const customer = order.customer || {};
  const firstName = customer.firstName || fallbackUser?.first_name || '';
  const lastName = customer.lastName || fallbackUser?.last_name || '';
  const username = customer.username || fallbackUser?.username || '';
  return {
    name: [firstName, lastName].filter(Boolean).join(' ') || 'не вказано',
    username: username ? `@${username.replace(/^@/, '')}` : 'не вказано',
  };
}

async function notifyAdminsAboutPayment(order, telegramUser) {
  if (!ADMIN_IDS.size) throw new Error('Адміністратори не налаштовані. Спробуйте пізніше.');
  const tariff = TARIFFS[order.tariffId];
  const customer = customerDetails(order, telegramUser);
  const text = [
    '🔔 Клієнт повідомив про оплату',
    '',
    `🧾 Заявка: ${order.id}`,
    `👤 Клієнт: ${customer.name}`,
    `📱 Username: ${customer.username}`,
    `🆔 Telegram ID: ${order.userId}`,
    `💳 Тариф: ${tariff.days} днів — ${tariff.price.toLocaleString('uk-UA')} грн`,
  ].join('\n');
  const notifiedAdminIds = new Set(order.paymentNotifiedAdminIds || []);
  for (const adminId of ADMIN_IDS) {
    if (notifiedAdminIds.has(adminId)) continue;
    await telegramApi('sendMessage', { chat_id: adminId, text });
    notifiedAdminIds.add(adminId);
    order.paymentNotifiedAdminIds = [...notifiedAdminIds];
    persistState();
  }
}

function aboutServiceText() {
  return [
    'ℹ️ Про послугу «Відстрочка»',
    '',
    'Як оформити послугу:',
    '',
    '1. 🛒 Натисніть у навігації бота кнопку «Оформити замовлення».',
    '2. ✅ Оберіть одну підставу.',
    '3. 📝 Заповніть дані заявника у формі.',
    '4. 📅 Оберіть термін доступу до додатку.',
    '5. 💳 Отримайте реквізити та номер заявки.',
    '',
    '🔔 Після автоматичної перевірки оплати доступ активується.',
    '',
    '🙏 Дякуємо за ваше замовлення.',
    '',
    'На фото демонструється приблизний вигляд нашого застосунку❗️— усе стилізовано під оригінал.',
  ].join('\n');
}

function mainMenu() {
  const rows = [];
  rows.push([{ text: 'ℹ️ Про послугу', callback_data: 'about_service' }]);
  rows.push([{ text: '👤 Особистий профіль', callback_data: 'customer_profile' }]);
  if (SUPPORT_USERNAME) rows.push([{ text: `🆘 Підтримка: @${SUPPORT_USERNAME}`, url: `https://t.me/${SUPPORT_USERNAME}` }]);
  if (MINI_APP_URL) rows.push([{ text: '🛒 Оформити замовлення', web_app: { url: MINI_APP_URL } }]);
  return { inline_keyboard: rows };
}

function backToMainMenu() {
  return { inline_keyboard: [[{ text: '⬅️ Повернутися до головного меню', callback_data: 'main_menu' }]] };
}

function aboutMenu() {
  return backToMainMenu();
}

function customerProfileText(user) {
  const access = currentAccess(user.id);
  const orders = Object.values(state.orders)
    .filter((order) => String(order.userId) === String(user.id))
    .slice(-5)
    .reverse();
  const username = user.username ? `@${user.username}` : 'не вказано';
  const orderLines = orders.length
    ? orders.map((order) => {
      const tariff = TARIFFS[order.tariffId];
      const status = order.status === 'paid' ? '✅ оплачено' : order.status === 'cancelled' ? '❌ скасовано' : '⏳ очікує оплати';
      return `• ${order.id}: ${tariff?.days || order.tariffId} днів — ${status}`;
    })
    : ['Заявок ще немає.'];
  return [
    '👤 Особистий профіль',
    '',
    `📱 Ваш Telegram: ${username}`,
    access ? `✅ Доступ: активний до ${formatDate(new Date(access.validUntil))}` : '❌ Доступ: неактивний',
    '',
    '📋 Ваші замовлення:',
    ...orderLines,
  ].join('\n');
}

async function replaceBotMessage(query, text, replyMarkup) {
  await telegramApi('editMessageText', {
    chat_id: query.message.chat.id,
    message_id: query.message.message_id,
    text,
    reply_markup: replyMarkup,
  });
}
async function showAboutService(query) {
  await telegramApi('deleteMessage', {
    chat_id: query.message.chat.id,
    message_id: query.message.message_id,
  });

  await telegramApi('sendPhoto', {
    chat_id: query.message.chat.id,
    photo: ABOUT_IMAGE_URL,
    caption: aboutServiceText(),
    reply_markup: aboutMenu(),
  });
}

async function showMainMenu(query) {
  await telegramApi('deleteMessage', {
    chat_id: query.message.chat.id,
    message_id: query.message.message_id,
  });

  await telegramApi('sendMessage', {
    chat_id: query.message.chat.id,
    text: 'Головне меню. Оберіть потрібну дію.',
    reply_markup: mainMenu(),
  });
}
async function handleCallbackQuery(query) {
 if (query.data === 'about_service' && query.message?.chat?.id) {
  await telegramApi('answerCallbackQuery', {
    callback_query_id: query.id,
  });
  await showAboutService(query);
  return;
}

  if (query.data === 'customer_profile' && query.message?.chat?.id && query.from?.id) {
    await telegramApi('answerCallbackQuery', { callback_query_id: query.id });
    await replaceBotMessage(query, customerProfileText(query.from), backToMainMenu());
    return;
  }

 if (query.data === 'main_menu' && query.message?.chat?.id) {
  await telegramApi('answerCallbackQuery', {
    callback_query_id: query.id,
  });
  await showMainMenu(query);
  return;
}

  if (query.data === 'payment_card_unavailable') {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: query.id,
      text: 'Оплата карткою тимчасово не працює. Оберіть Crypto.',
      show_alert: true,
    });
    return;
  }

  if (query.data?.startsWith('payment_crypto:')) {
    const orderId = query.data.slice('payment_crypto:'.length).toUpperCase();
    const order = state.orders[orderId];
    if (!order || String(order.userId) !== String(query.from?.id)) {
      await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Заявку не знайдено.', show_alert: true });
      return;
    }
    if (order.status !== 'pending') {
      await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Ця заявка вже неактивна.', show_alert: true });
      return;
    }
    if (!CRYPTO_PAYMENT_DETAILS) {
      await telegramApi('answerCallbackQuery', {
        callback_query_id: query.id,
        text: 'Crypto-реквізити ще не додані. Спробуйте пізніше.',
        show_alert: true,
      });
      return;
    }
    order.paymentMethod = 'crypto';
    persistState();
    await replaceWithCryptoPaymentInstructions(query, order);
    await telegramApi('answerCallbackQuery', { callback_query_id: query.id });
    return;
  }

  if (!query.data?.startsWith('payment_report:')) return;
  const orderId = query.data.slice('payment_report:'.length).toUpperCase();
  const order = state.orders[orderId];
  if (!order || String(order.userId) !== String(query.from?.id)) {
    await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Заявку не знайдено.', show_alert: true });
    return;
  }
  if (order.status === 'paid') {
    await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Оплату вже зараховано.' });
    return;
  }
  if (order.status !== 'pending') {
    await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Ця заявка вже неактивна.', show_alert: true });
    return;
  }
  if (order.paymentReportedAt) {
    await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Ми вже отримали повідомлення про оплату.' });
    return;
  }

  await notifyAdminsAboutPayment(order, query.from);
  order.paymentReportedAt = new Date().toISOString();
  persistState();
  await replaceBotMessage(query, '✅ Повідомлення про оплату надіслано. Очікуйте на автоматичну перевірку платежу.', backToMainMenu());
  await telegramApi('answerCallbackQuery', { callback_query_id: query.id, text: 'Дякуємо! Повідомлення про оплату надіслано.' });
}

async function handleBotMessage(message) {
  const text = message.text?.trim();
  const userId = message.from?.id;
  if (!text || !userId) return;

  if (text === '/start') {
    await telegramApi('sendMessage', {
      chat_id: userId,
      text: '🤖 RezBot\n\nШвидке отримання Фейк документів та «відстрочки» у Резерв+ ⚡\n\nЗручний сервіс, оформлення в кілька кроків.\n\n🤝 Підтримка на кожному етапі оформлення.\n\n❗️Допомагає в 99% випадків❗️',
      reply_markup: mainMenu(),
    });
    return;
  }

  if (text === '/about') {
    await telegramApi('sendMessage', { chat_id: userId, text: aboutServiceText(), reply_markup: aboutMenu() });
    return;
  }

  if (text === '/profile') {
    await telegramApi('sendMessage', { chat_id: userId, text: customerProfileText(message.from), reply_markup: backToMainMenu() });
    return;
  }

  if (text === '/support') {
    const reply = SUPPORT_USERNAME ? `Підтримка: https://t.me/${SUPPORT_USERNAME}` : 'Підтримка ще не налаштована.';
    await telegramApi('sendMessage', { chat_id: userId, text: reply });
    return;
  }

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

  if (command === '/o') {
    if (!orderId) throw new Error('Використовуйте: /o ORD-...');
    const order = state.orders[orderId];
    if (!order) throw new Error('Заявку не знайдено.');
    if (order.status !== 'pending') throw new Error(`Заявка вже має статус: ${order.status}.`);

    order.processingAt = new Date().toISOString();
    order.processingBy = String(userId);
    persistState();
    await telegramApi('sendMessage', {
      chat_id: order.userId,
      text: `⏳ Ваш платіж за заявкою № ${order.id} обробляється. Ми повідомимо вас після завершення перевірки.`,
    });
    await telegramApi('sendMessage', { chat_id: userId, text: `⏳ Клієнта повідомлено: платіж за заявкою ${order.id} обробляється.` });
    return;
  }

  if (command === '/confirm') {
    if (!orderId) throw new Error('Використовуйте: /confirm ORD-...');
    const { order, validUntil } = confirmOrder(orderId, userId);
    await telegramApi('sendMessage', {
      chat_id: order.userId,
      text: `✅ Оплату за заявкою № ${order.id} підтверджено. Доступ до бота активний до ${formatDate(validUntil)}.`,
    });
    await telegramApi('sendMessage', { chat_id: userId, text: `✅ Готово. Доступ активний до ${formatDate(validUntil)}.` });
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
      ? pending.map((order) => `${order.id} — ${TARIFFS[order.tariffId].days} днів, ${TARIFFS[order.tariffId].price} грн${order.processingAt ? ' ⏳ в обробці' : ''}`).join('\n')
      : 'Активних заявок немає.';
    await telegramApi('sendMessage', { chat_id: userId, text: textResponse });
  }
}

async function pollUpdates() {
  if (!BOT_TOKEN) return;
  try {
    const updates = await telegramApi('getUpdates', { offset: updateOffset, timeout: 25, allowed_updates: ['message', 'callback_query'] });
    for (const update of updates) {
      updateOffset = update.update_id + 1;
      if (update.message) {
        try { await handleBotMessage(update.message); }
        catch (error) {
          if (update.message.chat?.id) await telegramApi('sendMessage', { chat_id: update.message.chat.id, text: error.message || 'Сталася помилка.' });
        }
      }
      if (update.callback_query) {
        try { await handleCallbackQuery(update.callback_query); }
        catch (error) {
          if (update.callback_query.message?.chat?.id) await telegramApi('sendMessage', { chat_id: update.callback_query.message.chat.id, text: error.message || 'Сталася помилка.' });
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
 const publicFiles = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/config.js': 'config.js',
  '/about-service.jpg': 'about-service.jpg',
};
  const filename = publicFiles[pathname];
  if (!filename) return false;
  const filePath = join(STATIC_DIR, filename);
  if (!existsSync(filePath)) return false;
 const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
};
  response.writeHead(200, { 'Content-Type': mimeTypes[extname(filePath)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
  response.end(readFileSync(filePath));
  return true;
}

const server = createServer(async (request, response) => {
  setCors(request, response);
  if (request.method === 'OPTIONS') { response.writeHead(204); response.end(); return; }
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  if (request.method === 'GET' && url.pathname === '/api/health') {
    json(response, 200, { ok: true, botConfigured: Boolean(BOT_TOKEN), paymentConfigured: Boolean(PAYMENT_DETAILS), paymentWebhookConfigured: Boolean(PAYMENT_WEBHOOK_SECRET), demoOrdersAllowed: ALLOW_DEMO_ORDERS });
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/payments/confirm') {
    if (!PAYMENT_WEBHOOK_SECRET) {
      json(response, 503, { message: 'Автоматичне зарахування ще не налаштоване.' });
      return;
    }
    if (!isAuthorizedPaymentWebhook(request)) {
      json(response, 401, { message: 'Невірний ключ системи зарахування.' });
      return;
    }
    try {
      const body = await readJson(request);
      const orderId = String(body.orderId || '').trim().toUpperCase();
      if (!orderId) throw new Error('Передайте номер заявки.');
      const existingOrder = state.orders[orderId];
      if (!existingOrder) {
        json(response, 404, { message: 'Заявку не знайдено.' });
        return;
      }
      if (existingOrder.status === 'paid') {
        const access = state.access[String(existingOrder.userId)];
        json(response, 200, { ok: true, orderId, validUntil: access?.validUntil, alreadyProcessed: true });
        return;
      }
      if (existingOrder.status !== 'pending') throw new Error(`Заявка вже має статус: ${existingOrder.status}.`);

      const { order, validUntil } = confirmOrder(orderId, 'payment-system');
      if (!order.demo) {
        await telegramApi('sendMessage', {
          chat_id: order.userId,
          text: `✅ Оплату за заявкою № ${order.id} зараховано. Доступ до бота активний до ${formatDate(validUntil)}.`,
        });
      }
      json(response, 200, { ok: true, orderId: order.id, validUntil: validUntil.toISOString() });
    } catch (error) {
      json(response, 400, { message: error.message || 'Не вдалося зарахувати оплату.' });
    }
    return;
  }

  if (request.method === 'POST' && url.pathname === '/api/orders') {
    try {
      const body = await readJson(request);
      if (body.serviceId !== 'vidstrochka' || !TARIFFS[body.tariffId]) throw new Error('Оберіть коректний тариф.');
      const isDemo = ALLOW_DEMO_ORDERS && !body.initData;
      const user = isDemo ? { id: `demo-${randomBytes(4).toString('hex')}` } : telegramUserFromInitData(String(body.initData || ''));
      const order = {
        id: makeOrderId(),
        userId: user.id,
        serviceId: 'vidstrochka',
        tariffId: body.tariffId,
        status: 'pending',
        createdAt: new Date().toISOString(),
        demo: isDemo,
        customer: {
          firstName: user.first_name || '',
          lastName: user.last_name || '',
          username: user.username || '',
        },
      };
      state.orders[order.id] = order;
      persistState();
      if (!isDemo) await sendPaymentInstructions(order);
      json(response, 201, { orderId: order.id, demo: isDemo });
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
  if (!ADMIN_IDS.size) console.warn('ADMIN_IDS не задано: команди /o, /confirm, /reject і /orders нікому не доступні.');
  if (ALLOW_DEMO_ORDERS) console.warn('Увімкнено ALLOW_DEMO_ORDERS: тестові заявки створюються без Telegram і не мають реальної оплати.');
});

pollUpdates();
