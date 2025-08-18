const puppeteer = require('puppeteer');

async function testAutomation() {
  console.log('🚀 Starting automation testing...');
  
  const browser = await puppeteer.launch({ 
    headless: false, // Set to false to see what's happening
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
          
          // Check if it shows "Loading..."
          if (settingsText.includes('Loading...')) {
            console.log('⚠️ Settings still showing "Loading..." - checking console for errors');
          }
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
          
          // Try to click save button and see what happens
          console.log('🖱️ Clicking save button...');
          await saveButton.click();
          
          // Wait a moment for any response
          await page.waitForTimeout(2000);
          
          // Check for error messages
          const errorElement = await page.$('#saveStatus');
          if (errorElement) {
            const errorText = await page.evaluate(el => el.textContent, errorElement);
            console.log('❌ Save status:', errorText);
          }
          
          // Check browser console for any errors
          const consoleLogs = await page.evaluate(() => {
            return window.consoleLogs || [];
          });
          console.log('📝 Console logs:', consoleLogs);
          
        } else {
          console.log('❌ Save button not found');
        }
        
      } else {
        console.log('❌ Automated Sending section not found');
      }
      
      // Check for any JavaScript errors
      const errors = await page.evaluate(() => {
        return window.errors || [];
      });
      if (errors.length > 0) {
        console.log('🚨 JavaScript errors:', errors);
      }
      
    } else {
      console.log('❌ Not on dashboard, current URL:', page.url());
    }
    
  } catch (error) {
    console.error('💥 Test failed:', error);
  }
  
  // Keep browser open for manual inspection
  console.log('🔍 Test complete. Browser will stay open for manual inspection...');
  console.log('Press Ctrl+C to close...');
  
  // Don't close browser - let user inspect manually
  // await browser.close();
}

// Run the test
testAutomation().catch(console.error);
