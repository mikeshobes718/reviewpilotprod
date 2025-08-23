const puppeteer = require('puppeteer');

async function testUserMikeshobes718Yahoo() {
  console.log('🧪 Testing User: mikeshobes718@yahoo.com');
  
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
      requests.push({
        url: request.url(),
        method: request.method(),
        headers: request.headers()
      });
    });
    
    page.on('response', response => {
      responses.push({
        url: response.url(),
        status: response.status(),
        headers: response.headers()
      });
    });
    
    console.log('\n🧪 Test: Attempting login with mikeshobes718@yahoo.com...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Clear request/response arrays
    requests.length = 0;
    responses.length = 0;
    
    // Fill login form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      console.log('📝 Filling login form...');
      await emailInput.type('mikeshobes718@yahoo.com');
      await passwordInput.type('T@st1234');
      
      console.log('🔘 Submitting login form...');
      await submitButton.click();
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log('\n📊 Login attempt results:');
      console.log('  Current URL:', page.url());
      
      // Check for success (redirect to dashboard)
      if (page.url().includes('/dashboard')) {
        console.log('✅ LOGIN SUCCESSFUL! Redirected to dashboard');
        
        // Check dashboard content
        const dashboardTitle = await page.$eval('h1, h2, .dashboard-title', el => el.textContent).catch(() => 'Not found');
        console.log('  Dashboard title:', dashboardTitle);
        
        // Check for business name
        const businessName = await page.$eval('.business-name, .user-name, h1', el => el.textContent).catch(() => 'Not found');
        console.log('  Business/User name:', businessName);
        
        // Check for subscription status
        const subscriptionStatus = await page.$eval('.subscription-status, .plan-info, .trial-info', el => el.textContent).catch(() => 'Not found');
        console.log('  Subscription status:', subscriptionStatus);
        
      } else if (page.url().includes('/login')) {
        console.log('❌ LOGIN FAILED - Still on login page');
        
        // Check for error messages
        const errorElements = await page.$$('.error, .noticeBanner, .form-error, .alert');
        if (errorElements.length > 0) {
          console.log('⚠️ Error messages found:');
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
        console.log('🔄 LOGIN RESULT UNKNOWN - URL:', page.url());
      }
      
      // Check network activity
      console.log('\n🌐 Network activity during login:');
      console.log('  Requests:', requests.length);
      console.log('  Responses:', responses.length);
      
      if (responses.length > 0) {
        responses.forEach((res, i) => {
          console.log(`  Response ${i + 1}:`, res.status, res.url);
        });
      }
      
    } else {
      console.log('❌ Login form elements not found');
    }
    
    console.log('\n📋 LOGIN TEST RESULTS:');
    console.log('✅ Form submission:', 'Completed');
    console.log('✅ URL after login:', page.url());
    console.log('✅ Dashboard access:', page.url().includes('/dashboard') ? 'SUCCESS' : 'FAILED');
    
    // Take screenshot
    await page.screenshot({ path: 'mikeshobes718-yahoo-login-test.png' });
    console.log('📸 Screenshot saved as mikeshobes718-yahoo-login-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testUserMikeshobes718Yahoo();
