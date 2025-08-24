const puppeteer = require('puppeteer');

async function testDebugJsLoading() {
  console.log('🔍 Testing JavaScript File Loading...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Debug JavaScript file loading...');
    
    // Step 1: Check if JavaScript file is accessible
    console.log('\n🔍 Step 1: Checking JavaScript file accessibility...');
    
    try {
      const response = await page.goto('https://reviewsandmarketing.com/js/subscription-popup.js', { waitUntil: 'networkidle2' });
      console.log(`  📊 JavaScript file response status: ${response.status()}`);
      
      if (response.status() === 200) {
        console.log('  ✅ SUCCESS: JavaScript file is accessible');
        
        // Check file content
        const jsContent = await response.text();
        console.log(`  📊 JavaScript file size: ${jsContent.length} characters`);
        
        if (jsContent.includes('initSubscriptionPopup')) {
          console.log('  ✅ SUCCESS: JavaScript file contains expected function');
        } else {
          console.log('  ❌ PROBLEM: JavaScript file missing expected function');
        }
        
      } else {
        console.log('  ❌ PROBLEM: JavaScript file not accessible');
      }
    } catch (error) {
      console.log('  ❌ ERROR: Could not access JavaScript file:', error.message);
    }
    
    // Step 2: Check if script tag is in HTML
    console.log('\n🔍 Step 2: Checking script tag in HTML...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Check page source for script tag
    const pageSource = await page.content();
    
    if (pageSource.includes('/js/subscription-popup.js')) {
      console.log('  ✅ SUCCESS: Script tag found in HTML');
    } else {
      console.log('  ❌ PROBLEM: Script tag not found in HTML');
    }
    
    if (pageSource.includes('subscription-popup.js')) {
      console.log('  ✅ SUCCESS: Script filename found in HTML');
    } else {
      console.log('  ❌ PROBLEM: Script filename not found in HTML');
    }
    
    // Step 3: Check browser console for errors
    console.log('\n🔍 Step 3: Checking browser console for errors...');
    
    // Set up console error listener
    page.on('console', msg => {
      if (msg.type() === 'error') {
        console.log(`  🚨 Console Error: ${msg.text()}`);
      }
    });
    
    // Set up page error listener
    page.on('pageerror', error => {
      console.log(`  🚨 Page Error: ${error.message}`);
    });
    
    // Reload page to trigger script loading
    await page.reload({ waitUntil: 'networkidle2' });
    
    // Wait for any errors
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Step 4: Check if script is actually executing
    console.log('\n🔍 Step 4: Checking script execution...');
    
    // Check if any popup-related elements exist
    const popupExists = await page.$('#subscription-required-popup');
    const mobilePopupExists = await page.$('#mobile-subscription-required-popup');
    
    console.log(`  📊 Desktop popup exists: ${!!popupExists}`);
    console.log(`  📊 Mobile popup exists: ${!!mobilePopupExists}`);
    
    // Check if script functions are available
    const scriptFunctions = await page.evaluate(() => {
      return {
        hasInitFunction: typeof window.initSubscriptionPopup === 'function',
        hasCreateFunction: typeof window.createPopupHTML === 'function',
        hasInterceptFunction: typeof window.interceptDashboardClicks === 'function'
      };
    });
    
    console.log(`  📊 Script functions available:`, scriptFunctions);
    
    // Step 5: Check network requests
    console.log('\n🔍 Step 5: Checking network requests...');
    
    // Enable request interception
    await page.setRequestInterception(true);
    
    const requests = [];
    page.on('request', request => {
      if (request.url().includes('subscription-popup.js')) {
        requests.push(request.url());
        console.log(`  📡 Script request: ${request.url()}`);
      }
      request.continue();
    });
    
    // Reload page again
    await page.reload({ waitUntil: 'networkidle2' });
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    console.log(`  📊 Total script requests: ${requests.length}`);
    
    // Step 6: Manual script injection test
    console.log('\n🔍 Step 6: Testing manual script injection...');
    
    const manualInjectionResult = await page.evaluate(() => {
      try {
        // Try to manually create the popup
        const popupHTML = `
          <div id="test-popup" style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            z-index: 10000;
            align-items: center;
            justify-content: center;
          ">
            <div style="background: white; padding: 20px; border-radius: 8px;">
              <h2>Test Popup</h2>
              <p>This is a test popup to verify JavaScript execution.</p>
            </div>
          </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', popupHTML);
        
        const testPopup = document.getElementById('test-popup');
        if (testPopup) {
          testPopup.remove();
          return 'Manual injection successful';
        } else {
          return 'Manual injection failed';
        }
      } catch (error) {
        return `Manual injection error: ${error.message}`;
      }
    });
    
    console.log(`  📊 Manual injection result: ${manualInjectionResult}`);
    
    // Step 7: Check file structure
    console.log('\n🔍 Step 7: Checking file structure...');
    
    // Try to access the file with different paths
    const testPaths = [
      'https://reviewsandmarketing.com/js/subscription-popup.js',
      'https://reviewsandmarketing.com/public/js/subscription-popup.js',
      'https://reviewsandmarketing.com/assets/js/subscription-popup.js'
    ];
    
    for (const testPath of testPaths) {
      try {
        const response = await page.goto(testPath, { waitUntil: 'networkidle2' });
        console.log(`  📊 ${testPath}: Status ${response.status()}`);
      } catch (error) {
        console.log(`  📊 ${testPath}: Error ${error.message}`);
      }
    }
    
    console.log('\n📋 JAVASCRIPT LOADING DEBUG RESULTS:');
    console.log('✅ File accessibility check:', 'Completed');
    console.log('✅ Script tag check:', 'Completed');
    console.log('✅ Console error check:', 'Completed');
    console.log('✅ Script execution check:', 'Completed');
    console.log('✅ Network request check:', 'Completed');
    console.log('✅ Manual injection test:', 'Completed');
    console.log('✅ File path check:', 'Completed');
    
    // Take screenshot
    await page.screenshot({ path: 'debug-js-loading-test.png' });
    console.log('📸 Screenshot saved as debug-js-loading-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testDebugJsLoading();
