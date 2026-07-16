const { execFileSync } = require('child_process');
const path = require('path');

const shouldInstall = process.env.RENDER || process.env.INSTALL_CHROME === '1';

if (!shouldInstall) {
    console.log('Chrome install skipped. Set INSTALL_CHROME=1 to install locally.');
    process.exit(0);
}

const cacheDir = process.env.RENDER
    ? '/opt/render/project/src/.cache/puppeteer'
    : (process.env.PUPPETEER_CACHE_DIR || path.join(__dirname, '..', '.cache', 'puppeteer'));

console.log(`Installing Chrome for Puppeteer into ${cacheDir}`);

execFileSync(
    process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['@puppeteer/browsers', 'install', 'chrome@stable'],
    {
        stdio: 'inherit',
        env: {
            ...process.env,
            PUPPETEER_CACHE_DIR: cacheDir
        }
    }
);
