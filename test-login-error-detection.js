const puppeteer = require('puppeteer');

async function testLoginErrorDetection() {
  console.log('🧪 Testing Login Error Detection...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test User 1: mikeshobes718@yahoo.com
    console.log('\n🧪 Test User 1: mikeshobes718@yahoo.com');
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
    
    // Check current URL
    const currentUrl = page.url();
    console.log('📍 Current URL:', currentUrl);
    
    // Check for error messages
    console.log('\n🔍 Checking for error messages...');
    
    const errorElements = await page.$$('.error, .noticeBanner, .form-error');
    console.log('📝 Error elements found:', errorElements.length);
    
    if (errorElements.length > 0) {
      for (let i = 0; i < errorElements.length; i++) {
        try {
          const errorText = await errorElements[i].textContent();
          const errorClass = await errorElements[i].getAttribute('class');
          const errorId = await errorElements[i].getAttribute('id');
          console.log(`⚠️ Error ${i + 1}:`, {
            text: errorText.trim(),
            class: errorClass,
            id: errorId
          });
        } catch (e) {
          console.log(`⚠️ Error ${i + 1}: Could not read error details`);
        }
      }
    } else {
      console.log('✅ No error elements found');
    }
    
    // Check for any text that might indicate an error
    console.log('\n🔍 Checking page content for error indicators...');
    
    const pageContent = await page.content();
    const errorIndicators = [
      'invalid',
      'incorrect',
      'failed',
      'error',
      'wrong',
      'not found',
      'unauthorized',
      'forbidden'
    ];
    
    errorIndicators.forEach(indicator => {
      if (pageContent.toLowerCase().includes(indicator)) {
        console.log(`⚠️ Found error indicator: "${indicator}"`);
      }
    });
    
    // Check if form was submitted
    console.log('\n🔍 Checking form submission...');
    
    // Look for any hidden fields or form state
    const hiddenFields = await page.$$eval('input[type="hidden"]', inputs => 
      inputs.map(input => ({
        name: input.name,
        value: input.value
      }))
    );
    
    console.log('🔒 Hidden fields:', hiddenFields);
    
    // Check if we're still on login page
    if (currentUrl.includes('/login')) {
      console.log('⚠️ Still on login page - form submission may have failed');
      
      // Check if form fields are still filled
      const emailValue = await emailInput.evaluate(el => el.value);
      const passwordValue = await passwordInput.evaluate(el => el.value);
      
      console.log('📧 Email field value:', emailValue);
      console.log('🔑 Password field value:', passwordValue);
      
      // Check if there are any validation errors
      const emailError = await page.$('#emailError');
      const passwordError = await page.$('#passwordError');
      
      if (emailError) {
        const emailErrorText = await emailError.textContent();
        console.log('📧 Email error:', emailErrorText.trim());
      }
      
      if (passwordError) {
        const passwordErrorText = await passwordError.textContent();
        console.log('🔑 Password error:', passwordErrorText.trim());
      }
      
    } else {
      console.log('✅ Form submitted successfully - redirected to:', currentUrl);
    }
    
    // Check network requests
    console.log('\n🔍 Checking network activity...');
    
    // Monitor network requests during login
    const requests = [];
    page.on('request', request => {
      if (request.url().includes('/auth/login')) {
        requests.push({
          url: request.url(),
          method: request.method(),
          headers: request.headers()
        });
      }
    });
    
    // Reload page to capture network activity
    await page.reload({ waitUntil: 'networkidle2' });
    
    console.log('🌐 Login requests captured:', requests.length);
    requests.forEach((req, i) => {
      console.log(`  Request ${i + 1}:`, req.method, req.url);
    });
    
    // Take screenshot
    await page.screenshot({ path: 'login-error-detection-test.png' });
    console.log('📸 Screenshot saved as login-error-detection-test.png');
    
    console.log('\n📋 LOGIN ERROR DETECTION RESULTS:');
    console.log('✅ Error elements:', errorElements.length > 0 ? 'Found' : 'None');
    console.log('✅ Form submission:', currentUrl !== '/login' ? 'Successful' : 'Failed');
    console.log('✅ Network requests:', 'Monitored');
    console.log('✅ Page content:', 'Analyzed');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testLoginErrorDetection();
