// proxy-config.js
module.exports = {
    // Ülke bazlı proxy listesi (kendi proxy'lerinizi ekleyin)
    proxies: [
        // 🇺🇸 ABD
        {
            id: 'us-1',
            label: 'US Proxy #1',
            location: 'us',
            host: 'your-us-proxy.com',
            port: 1080,
            username: '',
            password: '',
            enabled: false
        },
        {
            id: 'us-2',
            label: 'US Proxy #2',
            location: 'us',
            host: 'your-us-proxy-2.com',
            port: 1080,
            username: '',
            password: '',
            enabled: false
        },
        // 🇩🇪 Almanya
        {
            id: 'de-1',
            label: 'Germany Proxy #1',
            location: 'de',
            host: 'your-de-proxy.com',
            port: 1080,
            username: '',
            password: '',
            enabled: false
        },
        // 🇳🇱 Hollanda
        {
            id: 'nl-1',
            label: 'Netherlands Proxy #1',
            location: 'nl',
            host: 'your-nl-proxy.com',
            port: 1080,
            username: '',
            password: '',
            enabled: false
        },
        // 🌏 Asya
        {
            id: 'asia-1',
            label: 'Asia Proxy #1',
            location: 'asia',
            host: 'your-asia-proxy.com',
            port: 1080,
            username: '',
            password: '',
            enabled: false
        },
        // 🇹🇷 Türkiye
        {
            id: 'tr-1',
            label: 'Turkey Proxy #1',
            location: 'tr',
            host: 'your-tr-proxy.com',
            port: 1080,
            username: '',
            password: '',
            enabled: false
        }
    ],
    
    // User-Agent listesi
    userAgents: [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
    ],
    
    // Lokasyonlar
    locations: {
        'us': { label: '🇺🇸 USA', code: 'US', timezone: 'America/New_York' },
        'de': { label: '🇩🇪 Germany', code: 'DE', timezone: 'Europe/Berlin' },
        'nl': { label: '🇳🇱 Netherlands', code: 'NL', timezone: 'Europe/Amsterdam' },
        'asia': { label: '🌏 Asia', code: 'SG', timezone: 'Asia/Singapore' },
        'tr': { label: '🇹🇷 Turkey', code: 'TR', timezone: 'Europe/Istanbul' }
    }
};