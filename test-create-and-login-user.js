const puppeteer = require('puppeteer');

async function testCreateAndLoginUser() {
  console.log('🧪 Testing Create and Login User...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Step 1: Create a new test user
    console.log('\n🧪 Step 1: Creating a new test user...');
    
    await page.goto('https://reviewsandmarketing.com/signup', { waitUntil: 'networkidle2' });
    
    // Generate unique test data
    const timestamp = Date.now();
    const testEmail = `testuser${timestamp}@example.com`;
    const testPassword = 'TestPassword123!';
    const testBusiness = `Test Business ${timestamp}`;
    
    console.log('📧 Test email:', testEmail);
    console.log('🏢 Test business:', testBusiness);
    
    // Fill signup form
    const businessInput = await page.$('input[name="businessName"]');
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (!businessInput || !emailInput || !passwordInput || !submitButton) {
      console.log('❌ Signup form incomplete');
      return;
    }
    
    await businessInput.type(testBusiness);
    await emailInput.type(testEmail);
    await passwordInput.type(testPassword);
    
    // Submit signup form
    await submitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const signupResultUrl = page.url();
    console.log('📍 URL after signup:', signupResultUrl);
    
    if (signupResultUrl.includes('/dashboard')) {
      console.log('✅ Signup successful - redirected to dashboard');
    } else if (signupResultUrl.includes('/pricing')) {
      console.log('✅ Signup successful - redirected to pricing');
    } else if (signupResultUrl.includes('/signup')) {
      console.log('⚠️ Still on signup page - may have validation errors');
      
      // Check for signup errors
      const errorElements = await page.$$('.error, .noticeBanner, .form-error');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Signup error ${i + 1}:`, errorText.trim());
        }
      }
      return;
    } else {
      console.log('❓ Unexpected redirect after signup:', signupResultUrl);
      return;
    }
    
    // Step 2: Logout (if we're logged in)
    console.log('\n🧪 Step 2: Logging out...');
    
    try {
      const logoutLink = await page.$('a[href*="logout"], a[href*="signout"]');
      if (logoutLink) {
        await logoutLink.click();
        await new Promise(resolve => setTimeout(resolve, 2000));
        console.log('✅ Logged out successfully');
      } else {
        console.log('ℹ️ No logout link found - may need to go to login page');
        await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
      }
    } catch (error) {
      console.log('ℹ️ Could not logout, going to login page');
      await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    }
    
    // Step 3: Login with the newly created user
    console.log('\n🧪 Step 3: Logging in with newly created user...');
    
    // Get login form elements
    const loginEmailInput = await page.$('input[name="email"]');
    const loginPasswordInput = await page.$('input[name="password"]');
    const loginSubmitButton = await page.$('button[type="submit"]');
    
    if (!loginEmailInput || !loginPasswordInput || !loginSubmitButton) {
      console.log('❌ Login form incomplete');
      return;
    }
    
    // Fill login form with the test user credentials
    await loginEmailInput.type(testEmail);
    await loginPasswordInput.type(testPassword);
    
    // Submit login form
    await loginSubmitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const loginResultUrl = page.url();
    console.log('📍 URL after login:', loginResultUrl);
    
    if (loginResultUrl.includes('/dashboard')) {
      console.log('✅ Login successful - redirected to dashboard');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
      // Look for user-specific content
      const userContent = await page.$$eval('*', elements => 
        elements
          .filter(el => el.textContent && el.textContent.includes(testBusiness))
          .map(el => el.textContent.trim().substring(0, 100))
      );
      
      if (userContent.length > 0) {
        console.log('👤 User-specific content found:', userContent[0]);
      } else {
        console.log('ℹ️ No user-specific content found on dashboard');
      }
      
    } else if (loginResultUrl.includes('/pricing')) {
      console.log('✅ Login successful - redirected to pricing (may need subscription)');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else if (loginResultUrl.includes('/login')) {
      console.log('⚠️ Still on login page - login failed');
      
      // Check for login errors
      const errorElements = await page.$$('.error, .noticeBanner, .form-error');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Login error ${i + 1}:`, errorText.trim());
        }
      } else {
        console.log('ℹ️ No error messages displayed');
      }
      
    } else {
      console.log('❓ Unexpected redirect after login:', loginResultUrl);
    }
    
    console.log('\n📋 CREATE AND LOGIN USER TEST RESULTS:');
    console.log('✅ User creation:', signupResultUrl !== '/signup' ? 'Successful' : 'Failed');
    console.log('✅ User login:', loginResultUrl !== '/login' ? 'Successful' : 'Failed');
    console.log('✅ Dashboard access:', loginResultUrl.includes('/dashboard') ? 'Working' : 'Limited');
    
    // Take screenshot
    await page.screenshot({ path: 'create-and-login-user-test.png' });
    console.log('📸 Screenshot saved as create-and-login-user-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testCreateAndLoginUser();
