const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-gpu', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();

  // Use a wide viewport to avoid cramping
  await page.setViewport({ width: 2400, height: 1200, deviceScaleFactor: 2 });

  const htmlPath = path.resolve(__dirname, 'render_exact.html');
  await page.goto('file://' + htmlPath, { waitUntil: 'networkidle0', timeout: 30000 });

  // Wait for Mermaid to render
  await page.waitForSelector('.mermaid svg', { timeout: 15000 });
  await new Promise(r => setTimeout(r, 3000)); // extra wait for rendering

  // Full page screenshot
  await page.screenshot({
    path: path.resolve(__dirname, 'schema_architecture_francais.png'),
    fullPage: true,
    omitBackground: false
  });

  const dim = await page.evaluate(() => ({
    w: document.documentElement.scrollWidth,
    h: document.documentElement.scrollHeight
  }));
  console.log(`Screenshot saved! Page dimensions: ${dim.w}x${dim.h}`);
  await browser.close();
})();
