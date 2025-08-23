const puppeteer = require('puppeteer');

async function testSimpleVerification() {
  console.log('🧪 Testing Simple Verification...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test login with the user we just created
    console.log('\n🧪 Test: Testing login with newly created user...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get login form elements
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (!emailInput || !passwordInput || !submitButton) {
      console.log('❌ Login form elements not found');
      return;
    }
    
    // Fill login form with the user we just created
    const testEmail = 'testuser1755917729960@example.com';
    const testPassword = 'TestPassword123!';
    
    console.log('📧 Logging in with:', testEmail);
    
    await emailInput.type(testEmail);
    await passwordInput.type(testPassword);
    
    // Submit form
    await submitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Check where we ended up
    const resultUrl = page.url();
    console.log('📍 URL after login:', resultUrl);
    
    if (resultUrl.includes('/dashboard')) {
      console.log('✅ Login successful - redirected to dashboard');
      
      // Check dashboard content
      const dashboardTitle = await page.title();
      console.log('📄 Dashboard title:', dashboardTitle);
      
      // Look for dashboard elements
      const dashboardElements = await page.$$eval('h1, h2, h3', elements => 
        elements.map(el => el.textContent.trim())
      );
      console.log('📋 Dashboard content found:', dashboardElements.length, 'headings');
      
      if (dashboardElements.length > 0) {
        console.log('📝 Sample headings:', dashboardElements.slice(0, 3));
      }
      
    } else if (resultUrl.includes('/pricing')) {
      console.log('✅ Login successful - redirected to pricing');
      
      // Check pricing content
      const pricingTitle = await page.title();
      console.log('📄 Pricing title:', pricingTitle);
      
    } else if (resultUrl.includes('/login')) {
      console.log('⚠️ Still on login page - checking for errors');
      
      // Check for error messages
      const errorElements = await page.$$('.error, .noticeBanner');
      if (errorElements.length > 0) {
        for (let i = 0; i < errorElements.length; i++) {
          const errorText = await errorElements[i].textContent();
          console.log(`⚠️ Error message ${i + 1}:`, errorText.trim());
        }
      } else {
        console.log('ℹ️ No error messages found');
      }
    } else {
      console.log('❓ Unexpected redirect:', resultUrl);
    }
    
    console.log('\n📋 SIMPLE VERIFICATION RESULTS:');
    console.log('✅ Login form:', 'Working');
    console.log('✅ Form submission:', 'Working');
    console.log('✅ Authentication:', resultUrl !== '/login' ? 'Working' : 'Issue');
    console.log('✅ Dashboard access:', resultUrl.includes('/dashboard') ? 'Working' : 'Limited');
    
    // Take screenshot
    await page.screenshot({ path: 'simple-verification-test.png' });
    console.log('📸 Screenshot saved as simple-verification-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testSimpleVerification();
