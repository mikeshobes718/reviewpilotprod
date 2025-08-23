const puppeteer = require('puppeteer');

async function testAuthEndpoints() {
  console.log('🧪 Testing Authentication Endpoints...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Monitor network requests
    const requests = [];
    const responses = [];
    
    page.on('request', request => {
      if (request.url().includes('/auth/')) {
        requests.push({
          url: request.url(),
          method: request.method(),
          headers: request.headers()
        });
      }
    });
    
    page.on('response', response => {
      if (response.url().includes('/auth/')) {
        responses.push({
          url: response.url(),
          status: response.status(),
          headers: response.headers()
        });
      }
    });
    
    console.log('\n🧪 Test 1: Checking if authentication endpoints are reachable...');
    
    // Test 1: Try to access login endpoint directly
    try {
      const response = await page.goto('https://reviewsandmarketing.com/auth/login', { waitUntil: 'networkidle2' });
      console.log('📍 Direct access to /auth/login:', response.status());
      
      if (response.status() === 200) {
        console.log('✅ Login endpoint is accessible');
      } else if (response.status() === 405) {
        console.log('✅ Login endpoint exists (Method Not Allowed for GET)');
      } else {
        console.log('⚠️ Login endpoint status:', response.status());
      }
    } catch (error) {
      console.log('❌ Could not access login endpoint:', error.message);
    }
    
    // Test 2: Try to access signup endpoint directly
    try {
      const response = await page.goto('https://reviewsandmarketing.com/auth/signup', { waitUntil: 'networkidle2' });
      console.log('📍 Direct access to /auth/signup:', response.status());
      
      if (response.status() === 200) {
        console.log('✅ Signup endpoint is accessible');
      } else if (response.status() === 405) {
        console.log('✅ Signup endpoint exists (Method Not Allowed for GET)');
      } else {
        console.log('⚠️ Signup endpoint status:', response.status());
      }
    } catch (error) {
      console.log('❌ Could not access signup endpoint:', error.message);
    }
    
    // Test 3: Check login page and try form submission
    console.log('\n🧪 Test 3: Testing login form submission...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Clear request/response arrays
    requests.length = 0;
    responses.length = 0;
    
    // Fill and submit login form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      await emailInput.type('test@example.com');
      await passwordInput.type('testpassword');
      
      console.log('📝 Filling form with test credentials...');
      await submitButton.click();
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log('📊 Network activity during form submission:');
      console.log('  Requests:', requests.length);
      console.log('  Responses:', responses.length);
      
      if (requests.length > 0) {
        requests.forEach((req, i) => {
          console.log(`  Request ${i + 1}:`, req.method, req.url);
        });
      }
      
      if (responses.length > 0) {
        responses.forEach((res, i) => {
          console.log(`  Response ${i + 1}:`, res.status, res.url);
        });
      }
      
      // Check current URL
      const currentUrl = page.url();
      console.log('📍 Current URL after submission:', currentUrl);
      
      if (currentUrl.includes('/login')) {
        console.log('⚠️ Still on login page');
        
        // Check for any error messages
        const errorElements = await page.$$('.error, .noticeBanner, .form-error');
        if (errorElements.length > 0) {
          console.log('📝 Error elements found:', errorElements.length);
          for (let i = 0; i < errorElements.length; i++) {
            try {
              const errorText = await errorElements[i].textContent();
              console.log(`  Error ${i + 1}:`, errorText.trim());
            } catch (e) {
              console.log(`  Error ${i + 1}: Could not read`);
            }
          }
        }
      } else {
        console.log('✅ Form submitted successfully - redirected to:', currentUrl);
      }
      
    } else {
      console.log('❌ Login form elements not found');
    }
    
    // Test 4: Check if there are any JavaScript errors preventing submission
    console.log('\n🧪 Test 4: Checking for JavaScript errors...');
    
    const consoleMessages = [];
    const consoleErrors = [];
    
    page.on('console', msg => {
      consoleMessages.push({
        type: msg.type(),
        text: msg.text()
      });
    });
    
    page.on('pageerror', error => {
      consoleErrors.push(error.message);
    });
    
    // Reload page to capture console activity
    await page.reload({ waitUntil: 'networkidle2' });
    
    if (consoleErrors.length > 0) {
      console.log('⚠️ JavaScript errors found:');
      consoleErrors.forEach((error, i) => {
        console.log(`  Error ${i + 1}:`, error);
      });
    } else {
      console.log('✅ No JavaScript errors found');
    }
    
    if (consoleMessages.length > 0) {
      console.log('📝 Console messages:');
      consoleMessages.forEach((msg, i) => {
        console.log(`  Message ${i + 1}:`, msg.type, msg.text);
      });
    }
    
    console.log('\n📋 AUTH ENDPOINTS TEST RESULTS:');
    console.log('✅ Endpoint accessibility:', 'Checked');
    console.log('✅ Form submission:', requests.length > 0 ? 'Working' : 'Not Working');
    console.log('✅ Network activity:', 'Monitored');
    console.log('✅ JavaScript errors:', consoleErrors.length > 0 ? 'Found' : 'None');
    
    // Take screenshot
    await page.screenshot({ path: 'auth-endpoints-test.png' });
    console.log('📸 Screenshot saved as auth-endpoints-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testAuthEndpoints();
