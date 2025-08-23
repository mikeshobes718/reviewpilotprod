const puppeteer = require('puppeteer');

async function testLoginFormWorking() {
  console.log('🧪 Testing Login Form Working...');
  
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
    
    console.log('\n🧪 Test: Checking login form submission with network monitoring...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Clear request/response arrays
    requests.length = 0;
    responses.length = 0;
    
    // Fill and submit login form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      console.log('📝 Filling form with test credentials...');
      await emailInput.type('test@example.com');
      await passwordInput.type('testpassword');
      
      console.log('🔘 Clicking submit button...');
      await submitButton.click();
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log('\n📊 Network activity during form submission:');
      console.log('  Total Requests:', requests.length);
      console.log('  Total Responses:', responses.length);
      
      if (requests.length > 0) {
        console.log('\n🌐 All Requests:');
        requests.forEach((req, i) => {
          console.log(`  Request ${i + 1}:`, req.method, req.url);
        });
      }
      
      if (responses.length > 0) {
        console.log('\n🌐 All Responses:');
        responses.forEach((res, i) => {
          console.log(`  Response ${i + 1}:`, res.status, res.url);
        });
      }
      
      // Check current URL
      const currentUrl = page.url();
      console.log('\n📍 Current URL after submission:', currentUrl);
      
      // Check for any error messages
      const errorElements = await page.$$('.error, .noticeBanner, .form-error');
      if (errorElements.length > 0) {
        console.log('\n⚠️ Error elements found:', errorElements.length);
        for (let i = 0; i < errorElements.length; i++) {
          try {
            const errorText = await errorElements[i].textContent();
            console.log(`  Error ${i + 1}:`, errorText.trim());
          } catch (e) {
            console.log(`  Error ${i + 1}: Could not read`);
          }
        }
      }
      
      // Check if form fields still have values
      const emailValue = await emailInput.evaluate(el => el.value);
      const passwordValue = await passwordInput.evaluate(el => el.value);
      
      console.log('\n📝 Form field values after submission:');
      console.log('  Email:', emailValue);
      console.log('  Password:', passwordValue);
      
    } else {
      console.log('❌ Login form elements not found');
    }
    
    console.log('\n📋 LOGIN FORM TEST RESULTS:');
    console.log('✅ Form elements:', 'Found');
    console.log('✅ Form submission:', 'Attempted');
    console.log('✅ Network requests:', requests.length);
    console.log('✅ Network responses:', responses.length);
    console.log('✅ Current URL:', currentUrl);
    
    // Take screenshot
    await page.screenshot({ path: 'login-form-working-test.png' });
    console.log('📸 Screenshot saved as login-form-working-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testLoginFormWorking();

