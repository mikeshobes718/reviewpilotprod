const puppeteer = require('puppeteer');

async function testAutomation() {
  console.log('🚀 Starting automation testing...');
  
  const browser = await puppeteer.launch({ 
    headless: true, // Set to true for headless testing
    defaultViewport: null,
    args: ['--start-maximized']
  });
  
  const page = await browser.newPage();
  
  try {
    // Navigate to the site
    console.log('📱 Navigating to site...');
    await page.goto('http://reviewpilot-prod.us-east-1.elasticbeanstalk.com', { waitUntil: 'networkidle0' });
    
    // Check if we're on login page or dashboard
    const currentUrl = page.url();
    console.log('📍 Current URL:', currentUrl);
    
    if (currentUrl.includes('/login')) {
      console.log('🔐 On login page, attempting to login...');
      
      // Login with test credentials
      await page.type('input[name="email"]', 'mikeshobes718@gmail.com');
      await page.type('input[name="password"]', 'T@st1234');
      await page.click('button[type="submit"]');
      
      // Wait for redirect
      await page.waitForNavigation({ waitUntil: 'networkidle0' });
      console.log('📍 After login, URL:', page.url());
    }
    
    // Check if we're on dashboard
    if (page.url().includes('/dashboard')) {
      console.log('✅ Successfully on dashboard');
      
      // Wait for page to load completely
      await page.waitForTimeout(3000);
      
      // Look for the Automated Sending section
      console.log('🔍 Looking for Automated Sending section...');
      const automationSection = await page.$('h2:has-text("Automated Sending")');
      
      if (automationSection) {
        console.log('✅ Found Automated Sending section');
        
        // Check current settings display
        const currentSettings = await page.$('#currentSettingsDisplay');
        if (currentSettings) {
          console.log('✅ Found current settings display');
          
          // Get the text content
          const settingsText = await page.evaluate(el => el.textContent, currentSettings);
          console.log('📊 Current settings text:', settingsText);
        }
        
        // Check for the save button
        const saveButton = await page.$('#saveButton');
        if (saveButton) {
          console.log('✅ Found save button');
          
          // Check if checkbox is checked
          const checkbox = await page.$('#autoSendCheckbox');
          if (checkbox) {
            const isChecked = await page.evaluate(el => el.checked, checkbox);
            console.log('☑️ Checkbox checked:', isChecked);
          }
        }
        
        // TEST BACKFILL BUTTON
        console.log('🧪 Testing Backfill button...');
        const backfillButton = await page.$('#backfillButton');
        if (backfillButton) {
          console.log('✅ Found backfill button');
          
          // Click backfill button and capture console logs
          const consoleLogs = [];
          page.on('console', msg => {
            consoleLogs.push(msg.text());
            console.log('📝 Console:', msg.text());
          });
          
          await backfillButton.click();
          console.log('🖱️ Clicked backfill button');
          
          // Wait for any response
          await page.waitForTimeout(3000);
          
          // Check for status messages
          const statusElement = await page.$('#saveStatus');
          if (statusElement) {
            const statusText = await page.evaluate(el => el.textContent, statusElement);
            console.log('📊 Status after backfill:', statusText);
          }
          
          console.log('📝 All console logs during backfill:', consoleLogs);
        } else {
          console.log('❌ Backfill button not found');
        }
        
        // TEST DAILY SYNC BUTTON
        console.log('🧪 Testing Daily Sync button...');
        const dailySyncButton = await page.$('#dailySyncButton');
        if (dailySyncButton) {
          console.log('✅ Found daily sync button');
          
          // Click daily sync button and capture console logs
          const syncConsoleLogs = [];
          page.on('console', msg => {
            syncConsoleLogs.push(msg.text());
            console.log('📝 Console:', msg.text());
          });
          
          await dailySyncButton.click();
          console.log('🖱️ Clicked daily sync button');
          
          // Wait for any response
          await page.waitForTimeout(3000);
          
          // Check for status messages
          const syncStatusElement = await page.$('#saveStatus');
          if (syncStatusElement) {
            const syncStatusText = await page.evaluate(el => el.textContent, syncStatusElement);
            console.log('📊 Status after daily sync:', syncStatusText);
          }
          
          console.log('📝 All console logs during daily sync:', syncConsoleLogs);
        } else {
          console.log('❌ Daily sync button not found');
        }
        
      } else {
        console.log('❌ Automated Sending section not found');
      }
      
    } else {
      console.log('❌ Not on dashboard, current URL:', page.url());
    }
    
  } catch (error) {
    console.error('💥 Test failed:', error);
  }
  
  // Close browser
  await browser.close();
  console.log('🔍 Test complete.');
}

// Run the test
testAutomation().catch(console.error);
