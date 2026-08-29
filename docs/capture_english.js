const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  const page = await browser.newPage();
  
  const filePath = path.resolve(__dirname, 'architecture_english.html');
  await page.goto('file://' + filePath, { waitUntil: 'networkidle0', timeout: 30000 });
  
  // Wait for Mermaid to render
  await page.waitForSelector('.mermaid svg', { timeout: 15000 });
  await new Promise(r => setTimeout(r, 2000));
  
  // Set viewport wide enough
  await page.setViewport({ width: 2400, height: 1600, deviceScaleFactor: 2 });
  await new Promise(r => setTimeout(r, 1000));
  
  // Full page screenshot
  await page.screenshot({
    path: path.resolve(__dirname, 'schema_architecture_english.png'),
    fullPage: true,
    type: 'png'
  });
  
  console.log('✅ Screenshot saved to docs/schema_architecture_english.png');
  await browser.close();
})();
