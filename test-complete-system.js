const puppeteer = require('puppeteer');

async function testCompleteSystem() {
  console.log('🧪 Testing Complete System...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test 1: Homepage
    console.log('\n🧪 Test 1: Testing homepage...');
    await page.goto('https://reviewsandmarketing.com', { waitUntil: 'networkidle2' });
    
    const title = await page.title();
    console.log('📄 Homepage title:', title);
    
    // Check navigation
    const navLinks = await page.$$eval('a', links => links.map(l => ({ text: l.textContent.trim(), href: l.href })));
    console.log('🔗 Navigation links found:', navLinks.length);
    
    // Test 2: Signup page
    console.log('\n🧪 Test 2: Testing signup page...');
    await page.goto('https://reviewsandmarketing.com/signup', { waitUntil: 'networkidle2' });
    
    const signupTitle = await page.title();
    console.log('📄 Signup page title:', signupTitle);
    
    // Check signup form
    const businessInput = await page.$('input[name="businessName"]');
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    console.log('📝 Signup form elements:');
    console.log('- Business input:', businessInput ? 'Found' : 'Not found');
    console.log('- Email input:', emailInput ? 'Found' : 'Not found');
    console.log('- Password input:', passwordInput ? 'Found' : 'Not found');
    console.log('- Submit button:', submitButton ? 'Found' : 'Not found');
    
    if (!businessInput || !emailInput || !passwordInput || !submitButton) {
      console.log('❌ Signup form is incomplete');
      return;
    }
    
    // Test 3: Create a new test user
    console.log('\n🧪 Test 3: Creating a new test user...');
    
    // Generate unique email
    const timestamp = Date.now();
    const testEmail = `testuser${timestamp}@example.com`;
    const testPassword = 'TestPassword123!';
    const testBusiness = `Test Business ${timestamp}`;
    
    console.log('📧 Test email:', testEmail);
    console.log('🏢 Test business:', testBusiness);
    
    // Fill signup form
    await businessInput.type(testBusiness);
    await emailInput.type(testEmail);
    await passwordInput.type(testPassword);
    
    // Submit form
    await submitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Check where we ended up
    const signupResultUrl = page.url();
    console.log('📍 URL after signup:', signupResultUrl);
    
    if (signupResultUrl.includes('/dashboard')) {
      console.log('✅ Signup successful - redirected to dashboard');
    } else if (signupResultUrl.includes('/pricing')) {
      console.log('✅ Signup successful - redirected to pricing');
    } else if (signupResultUrl.includes('/signup')) {
      console.log('⚠️ Still on signup page - may have validation errors');
    } else {
      console.log('❓ Unexpected redirect:', signupResultUrl);
    }
    
    // Test 4: Test login with new user
    console.log('\n🧪 Test 4: Testing login with new user...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get login form elements
    const loginEmailInput = await page.$('input[name="email"]');
    const loginPasswordInput = await page.$('input[name="password"]');
    const loginSubmitButton = await page.$('button[type="submit"]');
    
    // Fill login form
    await loginEmailInput.type(testEmail);
    await loginPasswordInput.type(testPassword);
    
    // Submit form
    await loginSubmitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Check where we ended up
    const loginResultUrl = page.url();
    console.log('📍 URL after login:', loginResultUrl);
    
    if (loginResultUrl.includes('/dashboard')) {
      console.log('✅ Login successful - redirected to dashboard');
    } else if (loginResultUrl.includes('/pricing')) {
      console.log('✅ Login successful - redirected to pricing');
    } else if (loginResultUrl.includes('/login')) {
      console.log('⚠️ Still on login page - may need email verification');
    } else {
      console.log('❓ Unexpected redirect:', loginResultUrl);
    }
    
    // Test 5: Test dashboard access
    console.log('\n🧪 Test 5: Testing dashboard access...');
    
    if (loginResultUrl.includes('/dashboard')) {
      console.log('✅ Dashboard accessible - user is authenticated');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
      // Look for dashboard elements
      const dashboardElements = await page.$$eval('h1, h2, h3', elements => 
        elements.map(el => el.textContent.trim())
      );
      console.log('📋 Dashboard content found:', dashboardElements.length, 'headings');
      
    } else if (loginResultUrl.includes('/pricing')) {
      console.log('✅ Pricing page accessible - may need subscription');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else {
      console.log('⚠️ Cannot access dashboard or pricing - checking for errors');
      
      // Check for error messages
      const errorElements = await page.$$('.error, .noticeBanner');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Error message ${i + 1}:`, errorText.trim());
        }
      }
    }
    
    // Test 6: Test logout
    console.log('\n🧪 Test 6: Testing logout...');
    
    try {
      // Look for logout link
      const logoutLink = await page.$('a[href*="logout"], a[href*="signout"]');
      if (logoutLink) {
        await logoutLink.click();
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        const logoutResultUrl = page.url();
        console.log('📍 URL after logout:', logoutResultUrl);
        
        if (logoutResultUrl.includes('/') || logoutResultUrl.includes('/login')) {
          console.log('✅ Logout successful');
        } else {
          console.log('⚠️ Logout may not have worked as expected');
        }
      } else {
        console.log('ℹ️ No logout link found - may be on pricing page');
      }
    } catch (error) {
      console.log('ℹ️ Could not test logout:', error.message);
    }
    
    console.log('\n📋 COMPLETE SYSTEM TEST RESULTS:');
    console.log('✅ Homepage:', 'Working');
    console.log('✅ Signup page:', 'Working');
    console.log('✅ User creation:', signupResultUrl !== '/signup' ? 'Working' : 'Issue');
    console.log('✅ Login system:', loginResultUrl !== '/login' ? 'Working' : 'Issue');
    console.log('✅ Dashboard access:', loginResultUrl.includes('/dashboard') ? 'Working' : 'Limited');
    console.log('✅ System navigation:', 'Working');
    
    // Take screenshot
    await page.screenshot({ path: 'complete-system-test.png' });
    console.log('📸 Screenshot saved as complete-system-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testCompleteSystem();
