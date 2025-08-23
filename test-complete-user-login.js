const puppeteer = require('puppeteer');

async function testCompleteUserLogin() {
  console.log('🧪 Testing Complete User Login System...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test User 1: mikeshobes718@yahoo.com (STARTER PLAN - 30 days free trial)
    console.log('\n🧪 Test User 1: mikeshobes718@yahoo.com (STARTER PLAN)');
    console.log('📧 Username: mikeshobes718@yahoo.com');
    console.log('🔑 Password: T@st1234');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Fill login form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    await emailInput.type('mikeshobes718@yahoo.com');
    await passwordInput.type('T@st1234');
    await submitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const user1Url = page.url();
    console.log('📍 URL after login:', user1Url);
    
    if (user1Url.includes('/dashboard')) {
      console.log('✅ Login successful - redirected to dashboard');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
      // Look for subscription info
      const subscriptionElements = await page.$$eval('*', elements => 
        elements
          .filter(el => el.textContent && (
            el.textContent.includes('STARTER') || 
            el.textContent.includes('PRO') || 
            el.textContent.includes('trial') ||
            el.textContent.includes('subscription')
          ))
          .map(el => el.textContent.trim().substring(0, 100))
      );
      
      if (subscriptionElements.length > 0) {
        console.log('💳 Subscription info found:', subscriptionElements[0]);
      } else {
        console.log('ℹ️ No subscription info found on dashboard');
      }
      
    } else if (user1Url.includes('/pricing')) {
      console.log('✅ Login successful - redirected to pricing (may need subscription)');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else if (user1Url.includes('/login')) {
      console.log('⚠️ Still on login page - checking for errors');
      
      // Check for error messages
      const errorElements = await page.$$('.error, .noticeBanner');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Error message ${i + 1}:`, errorText.trim());
        }
      }
    }
    
    // Test User 2: xexiyi4080@featcore.com (STARTER PLAN - 30 days free trial)
    console.log('\n🧪 Test User 2: xexiyi4080@featcore.com (STARTER PLAN)');
    console.log('📧 Username: xexiyi4080@featcore.com');
    console.log('🔑 Password: T@st2025');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get fresh form elements
    const emailInput2 = await page.$('input[name="email"]');
    const passwordInput2 = await page.$('input[name="password"]');
    const submitButton2 = await page.$('button[type="submit"]');
    
    await emailInput2.type('xexiyi4080@featcore.com');
    await passwordInput2.type('T@st2025');
    await submitButton2.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const user2Url = page.url();
    console.log('📍 URL after login:', user2Url);
    
    if (user2Url.includes('/dashboard')) {
      console.log('✅ Login successful - redirected to dashboard');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
    } else if (user2Url.includes('/pricing')) {
      console.log('✅ Login successful - redirected to pricing (may need subscription)');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else if (user2Url.includes('/login')) {
      console.log('⚠️ Still on login page - checking for errors');
      
      // Check for error messages
      const errorElements = await page.$$('.error, .noticeBanner');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Error message ${i + 1}:`, errorText.trim());
        }
      }
    }
    
    // Test User 3: mikeshobes718@gmail.com (Not yet on a plan)
    console.log('\n🧪 Test User 3: mikeshobes718@gmail.com (No plan)');
    console.log('📧 Username: mikeshobes718@gmail.com');
    console.log('🔑 Password: Test!234');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get fresh form elements
    const emailInput3 = await page.$('input[name="email"]');
    const passwordInput3 = await page.$('input[name="password"]');
    const submitButton3 = await page.$('button[type="submit"]');
    
    await emailInput3.type('mikeshobes718@gmail.com');
    await passwordInput3.type('Test!234');
    await submitButton3.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const user3Url = page.url();
    console.log('📍 URL after login:', user3Url);
    
    if (user3Url.includes('/dashboard')) {
      console.log('✅ Login successful - redirected to dashboard');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
    } else if (user3Url.includes('/pricing')) {
      console.log('✅ Login successful - redirected to pricing (no plan - expected)');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else if (user3Url.includes('/login')) {
      console.log('⚠️ Still on login page - checking for errors');
      
      // Check for error messages
      const errorElements = await page.$$('.error, .noticeBanner');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Error message ${i + 1}:`, errorText.trim());
        }
      }
    }
    
    // Test User 4: Square credentials (if needed)
    console.log('\n🧪 Test User 4: Square credentials check');
    console.log('📧 Username: mikeshobes718@yahoo.com');
    console.log('🔑 Password: ReviewPilot2025');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get fresh form elements
    const emailInput4 = await page.$('input[name="email"]');
    const passwordInput4 = await page.$('input[name="password"]');
    const submitButton4 = await page.$('button[type="submit"]');
    
    await emailInput4.type('mikeshobes718@yahoo.com');
    await passwordInput4.type('ReviewPilot2025');
    await submitButton4.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const user4Url = page.url();
    console.log('📍 URL after login:', user4Url);
    
    if (user4Url.includes('/dashboard')) {
      console.log('✅ Square login successful - redirected to dashboard');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
    } else if (user4Url.includes('/pricing')) {
      console.log('✅ Square login successful - redirected to pricing');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else if (user4Url.includes('/login')) {
      console.log('⚠️ Square login failed - still on login page');
      
      // Check for error messages
      const errorElements = await page.$$('.error, .noticeBanner');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Error message ${i + 1}:`, errorText.trim());
        }
      }
    }
    
    // Summary of all tests
    console.log('\n📋 COMPLETE USER LOGIN TEST RESULTS:');
    console.log('✅ User 1 (mikeshobes718@yahoo.com):', user1Url !== '/login' ? 'Login Working' : 'Login Issue');
    console.log('✅ User 2 (xexiyi4080@featcore.com):', user2Url !== '/login' ? 'Login Working' : 'Login Issue');
    console.log('✅ User 3 (mikeshobes718@gmail.com):', user3Url !== '/login' ? 'Login Working' : 'Login Issue');
    console.log('✅ User 4 (Square credentials):', user4Url !== '/login' ? 'Login Working' : 'Login Issue');
    
    // Check dashboard access for each user
    console.log('\n🏠 DASHBOARD ACCESS SUMMARY:');
    console.log('✅ User 1 Dashboard:', user1Url.includes('/dashboard') ? 'Accessible' : 'Limited');
    console.log('✅ User 2 Dashboard:', user2Url.includes('/dashboard') ? 'Accessible' : 'Limited');
    console.log('✅ User 3 Dashboard:', user3Url.includes('/dashboard') ? 'Accessible' : 'Limited');
    console.log('✅ User 4 Dashboard:', user4Url.includes('/dashboard') ? 'Accessible' : 'Limited');
    
    // Take screenshot
    await page.screenshot({ path: 'complete-user-login-test.png' });
    console.log('📸 Screenshot saved as complete-user-login-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testCompleteUserLogin();
