const puppeteer = require('puppeteer');

async function testAutomation() {
  console.log('🚀 Starting automation testing...');
  
  const browser = await puppeteer.launch({ 
    headless: true,
    defaultViewport: null,
    args: ['--start-maximized','--no-sandbox','--disable-setuid-sandbox','--ignore-certificate-errors','--allow-insecure-localhost'],
    ignoreHTTPSErrors: true
  });
  
  const page = await browser.newPage();
  page.setDefaultNavigationTimeout(60000);
  
  try {
    // Always start at login
    const base = 'https://reviewpilot-prod.us-east-1.elasticbeanstalk.com';
    console.log('📱 Navigating to login...');
    await page.goto(base + '/login', { waitUntil: 'networkidle0' });

    // Perform login
    console.log('🔐 Attempting login...');
    await page.type('input[name="email"]', 'mikeshobes718@yahoo.com', { delay: 10 });
    await page.type('input[name="password"]', 'ReviewPilot2025', { delay: 10 });
    await page.click('button[type="submit"]');
    await page.waitForNavigation({ waitUntil: 'networkidle0' });
    console.log('📍 After login, URL:', page.url());

    // Ensure we're on dashboard
    if (!page.url().includes('/dashboard')) {
      console.log('🔀 Forcing navigation to dashboard...');
      await page.goto(base + '/dashboard', { waitUntil: 'networkidle0' });
    }

    if (page.url().includes('/dashboard')) {
      console.log('✅ On dashboard');
      await page.waitForTimeout(2000);

      // Test Backfill
      console.log('🧪 Testing Backfill button...');
      const backfillButton = await page.$('#backfillButton');
      if (backfillButton) {
        const consoleLogs = [];
        page.on('console', msg => { consoleLogs.push(msg.text()); });
        await backfillButton.click();
        await page.waitForTimeout(4000);
        const statusText = await page.$eval('#saveStatus', el => el.textContent).catch(() => '');
        console.log('📊 Backfill status:', statusText.trim());
        console.log('📝 Backfill console logs:', consoleLogs);
      } else {
        console.log('❌ Backfill button not found');
      }

      // Test Daily Sync
      console.log('🧪 Testing Daily Sync button...');
      const dailySyncButton = await page.$('#dailySyncButton');
      if (dailySyncButton) {
        const syncLogs = [];
        page.on('console', msg => { syncLogs.push(msg.text()); });
        await dailySyncButton.click();
        await page.waitForTimeout(4000);
        const syncStatus = await page.$eval('#saveStatus', el => el.textContent).catch(() => '');
        console.log('📊 Daily sync status:', syncStatus.trim());
        console.log('📝 Daily sync console logs:', syncLogs);
      } else {
        console.log('❌ Daily sync button not found');
      }
    } else {
      console.log('❌ Not on dashboard, current URL:', page.url());
    }
  } catch (error) {
    console.error('💥 Test failed:', error);
  }
  
  await browser.close();
  console.log('🔍 Test complete.');
}

// Run the test
testAutomation().catch(console.error);
