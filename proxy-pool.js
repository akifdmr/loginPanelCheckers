// proxy-pool.js
const { SocksProxyAgent } = require('socks-proxy-agent');
const https = require('https');

class ProxyPool {
    constructor() {
        this.proxies = [];
        this.currentIndex = 0;
        this.userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        ];
        
        this.locations = {
            'us': { label: '🇺🇸 USA', code: 'US', timezone: 'America/New_York' },
            'de': { label: '🇩🇪 Germany', code: 'DE', timezone: 'Europe/Berlin' },
            'nl': { label: '🇳🇱 Netherlands', code: 'NL', timezone: 'Europe/Amsterdam' },
            'asia': { label: '🌏 Asia', code: 'SG', timezone: 'Asia/Singapore' },
            'tr': { label: '🇹🇷 Turkey', code: 'TR', timezone: 'Europe/Istanbul' }
        };
    }

    // Proxy ekle
    addProxy(config) {
        if (!config.host || !config.port) return false;
        
        // Aynı ID varsa güncelle
        const existingIndex = this.proxies.findIndex(p => p.id === config.id);
        if (existingIndex !== -1) {
            this.proxies[existingIndex] = {
                ...this.proxies[existingIndex],
                ...config,
                url: this.buildProxyUrl(config)
            };
            return true;
        }
        
        this.proxies.push({
            id: config.id || `proxy_${Date.now()}`,
            label: config.label || 'Custom Proxy',
            location: config.location || 'unknown',
            host: config.host,
            port: config.port,
            username: config.username || '',
            password: config.password || '',
            url: this.buildProxyUrl(config),
            enabled: config.enabled !== false,
            lastUsed: null,
            successCount: 0,
            failCount: 0,
            lastVerified: null,
            verifiedIp: null,
            verifiedCountry: null
        });
        
        return true;
    }

    // Proxy URL oluştur
    buildProxyUrl(config) {
        let url = `socks5://`;
        if (config.username) {
            url += `${encodeURIComponent(config.username)}`;
            if (config.password) {
                url += `:${encodeURIComponent(config.password)}`;
            }
            url += `@`;
        }
        url += `${config.host}:${config.port}`;
        return url;
    }

    // Rotasyon ile proxy al
    getNextProxy() {
        const enabled = this.proxies.filter(p => p.enabled);
        if (enabled.length === 0) return null;
        
        const proxy = enabled[this.currentIndex % enabled.length];
        this.currentIndex++;
        proxy.lastUsed = new Date();
        return proxy;
    }

    // Belirli lokasyondan proxy al
    getProxyByLocation(location) {
        const available = this.proxies.filter(p => 
            p.enabled && p.location === location
        );
        if (available.length === 0) return null;
        
        const proxy = available[this.currentIndex % available.length];
        this.currentIndex++;
        proxy.lastUsed = new Date();
        return proxy;
    }

    // Proxy'yi doğrula
    async validateProxy(proxy) {
        if (!proxy || !proxy.url) return false;
        
        try {
            const agent = new SocksProxyAgent(proxy.url);
            const result = await new Promise((resolve) => {
                const request = https.get('https://ipwho.is/', {
                    agent,
                    timeout: 10000,
                    headers: { 'User-Agent': this.userAgents[0] }
                }, (response) => {
                    let body = '';
                    response.on('data', chunk => body += chunk);
                    response.on('end', () => {
                        try {
                            const data = JSON.parse(body);
                            resolve({
                                success: data.success !== false,
                                ip: data.ip,
                                country: data.country_code,
                                countryName: data.country
                            });
                        } catch {
                            resolve({ success: false });
                        }
                    });
                });
                request.on('error', () => resolve({ success: false }));
                request.on('timeout', () => {
                    request.destroy();
                    resolve({ success: false });
                });
            });
            
            if (result.success) {
                proxy.lastVerified = new Date();
                proxy.verifiedIp = result.ip;
                proxy.verifiedCountry = result.country;
                proxy.verifiedCountryName = result.countryName;
                return true;
            }
            return false;
        } catch {
            return false;
        }
    }

    // User-Agent al
    getUserAgent() {
        return this.userAgents[Math.floor(Math.random() * this.userAgents.length)];
    }

    // Cookie'leri temizle (Puppeteer için)
    async clearCookies(page) {
        try {
            const client = await page.target().createCDPSession();
            await client.send('Network.clearBrowserCookies');
            await client.send('Network.clearBrowserCache');
            return true;
        } catch {
            try {
                // Alternatif yöntem
                await page.evaluate(() => {
                    document.cookie.split(';').forEach(c => {
                        document.cookie = c.replace(/^ +/, '').replace(/=.*/, `=; expires=${new Date(0).toUTCString()}; path=/`);
                    });
                });
                return true;
            } catch {
                return false;
            }
        }
    }

    // Gerçek kullanıcı gibi bekleme
    async randomDelay(min = 500, max = 3000) {
        const delay = Math.floor(Math.random() * (max - min + 1)) + min;
        return new Promise(resolve => setTimeout(resolve, delay));
    }

    // Mouse hareketleri simüle et
    async simulateHumanBehavior(page) {
        try {
            // Rastgele scroll
            await page.evaluate(() => {
                window.scrollTo({
                    top: Math.floor(Math.random() * 500),
                    behavior: 'smooth'
                });
            });
            
            // Rastgele bekle
            await this.randomDelay(200, 800);
            
            // Mouse hareketi
            const x = Math.floor(Math.random() * 800) + 100;
            const y = Math.floor(Math.random() * 400) + 100;
            await page.mouse.move(x, y, { steps: 10 });
            
            return true;
        } catch {
            return false;
        }
    }

    // Proxy istatistikleri
    getStats() {
        return this.proxies.map(p => ({
            id: p.id,
            label: p.label,
            location: p.location,
            enabled: p.enabled,
            successCount: p.successCount,
            failCount: p.failCount,
            lastUsed: p.lastUsed,
            verifiedIp: p.verifiedIp || null,
            verifiedCountry: p.verifiedCountry || null
        }));
    }

    // Proxy'leri DB'den yükle
    async loadFromDB(db) {
        try {
            if (!db) return;
            const settings = await db.collection('settings').findOne({ _id: 'system' });
            if (!settings || !settings.proxyPool) return;
            
            const proxies = settings.proxyPool || [];
            this.proxies = [];
            proxies.forEach(p => this.addProxy(p));
            
            console.log(`✅ ${this.proxies.length} proxy yüklendi`);
        } catch (error) {
            console.error('Proxy yükleme hatası:', error);
        }
    }

    // Proxy'leri DB'ye kaydet
    async saveToDB(db) {
        try {
            if (!db) return;
            const proxyData = this.proxies.map(p => ({
                id: p.id,
                label: p.label,
                location: p.location,
                host: p.host,
                port: p.port,
                username: p.username,
                password: p.password,
                enabled: p.enabled
            }));
            
            await db.collection('settings').updateOne(
                { _id: 'system' },
                { $set: { proxyPool: proxyData, updatedAt: new Date() } }
            );
            
            console.log(`✅ ${proxyData.length} proxy kaydedildi`);
        } catch (error) {
            console.error('Proxy kaydetme hatası:', error);
        }
    }
}

module.exports = ProxyPool;