const puppeteer = require('puppeteer');

async function testSignupErrorDetection() {
  console.log('🧪 Testing Signup Error Detection...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Monitor console messages and errors
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
    
    console.log('\n🧪 Test: Checking signup form submission...');
    
    await page.goto('https://reviewsandmarketing.com/signup', { waitUntil: 'networkidle2' });
    
    // Check console messages on page load
    if (consoleMessages.length > 0) {
      console.log('📝 Console messages on page load:');
      consoleMessages.forEach((msg, i) => {
        console.log(`  Message ${i + 1}:`, msg.type, msg.text);
      });
    }
    
    // Check for JavaScript errors on page load
    if (consoleErrors.length > 0) {
      console.log('⚠️ JavaScript errors on page load:');
      consoleErrors.forEach((error, i) => {
        console.log(`  Error ${i + 1}:`, error);
      });
    }
    
    // Check form structure
    console.log('\n🔍 Checking form structure...');
    
    const form = await page.$('form');
    if (form) {
      const formAction = await form.evaluate(el => el.action);
      const formMethod = await form.evaluate(el => el.method);
      console.log('📝 Form action:', formAction);
      console.log('📝 Form method:', formMethod);
    }
    
    // Check form fields
    console.log('\n🔍 Checking form fields...');
    
    const businessInput = await page.$('input[name="businessName"]');
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (businessInput && emailInput && passwordInput && submitButton) {
      console.log('✅ All form fields found');
      
      // Check if submit button is disabled
      const isDisabled = await submitButton.evaluate(el => el.disabled);
      console.log('🔘 Submit button disabled:', isDisabled);
      
      // Check if form fields have any validation attributes
      const businessRequired = await businessInput.evaluate(el => el.required);
      const emailRequired = await emailInput.evaluate(el => el.required);
      const passwordRequired = await passwordInput.evaluate(el => el.required);
      
      console.log('🏢 Business required:', businessRequired);
      console.log('📧 Email required:', emailRequired);
      console.log('🔑 Password required:', passwordRequired);
      
    } else {
      console.log('❌ Some form fields missing');
      return;
    }
    
    // Try to submit form
    console.log('\n🧪 Attempting form submission...');
    
    // Clear console messages and errors for submission test
    consoleMessages.length = 0;
    consoleErrors.length = 0;
    
    // Fill form with test data
    const timestamp = Date.now();
    const testEmail = `testuser${timestamp}@example.com`;
    const testPassword = 'TestPassword123!';
    const testBusiness = `Test Business ${timestamp}`;
    
    console.log('📧 Test email:', testEmail);
    console.log('🏢 Test business:', testBusiness);
    
    await businessInput.type(testBusiness);
    await emailInput.type(testEmail);
    await passwordInput.type(testPassword);
    
    // Submit form
    await submitButton.click();
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Check results
    console.log('\n🔍 Form submission results...');
    
    const currentUrl = page.url();
    console.log('📍 Current URL:', currentUrl);
    
    // Check for JavaScript errors during submission
    if (consoleErrors.length > 0) {
      console.log('⚠️ JavaScript errors during submission:');
      consoleErrors.forEach((error, i) => {
        console.log(`  Error ${i + 1}:`, error);
      });
    } else {
      console.log('✅ No JavaScript errors during submission');
    }
    
    // Check console messages during submission
    if (consoleMessages.length > 0) {
      console.log('📝 Console messages during submission:');
      consoleMessages.forEach((msg, i) => {
        console.log(`  Message ${i + 1}:`, msg.type, msg.text);
      });
    }
    
    // Check if form fields still have values
    const businessValue = await businessInput.evaluate(el => el.value);
    const emailValue = await emailInput.evaluate(el => el.value);
    const passwordValue = await passwordInput.evaluate(el => el.value);
    
    console.log('🏢 Business field value after submission:', businessValue);
    console.log('📧 Email field value after submission:', emailValue);
    console.log('🔑 Password field value after submission:', passwordValue);
    
    // Check for any error messages
    const errorElements = await page.$$('.error, .noticeBanner, .form-error');
    if (errorElements.length > 0) {
      console.log('⚠️ Error elements found after submission:', errorElements.length);
      for (let i = 0; i < errorElements.length; i++) {
        try {
          const errorText = await errorElements[i].textContent();
          const errorClass = await errorElements[i].getAttribute('class');
          const errorId = await errorElements[i].getAttribute('id');
          console.log(`  Error ${i + 1}:`, {
            text: errorText.trim(),
            class: errorClass,
            id: errorId
          });
        } catch (e) {
          console.log(`  Error ${i + 1}: Could not read error details`);
        }
      }
    } else {
      console.log('✅ No error elements found after submission');
    }
    
    // Check if we're still on signup page
    if (currentUrl.includes('/signup')) {
      console.log('⚠️ Still on signup page - form submission may have failed');
      
      // Check if there are any validation errors
      const businessError = await page.$('#businessError, .business-error');
      const emailError = await page.$('#emailError, .email-error');
      const passwordError = await page.$('#passwordError, .password-error');
      
      if (businessError) {
        const businessErrorText = await businessError.textContent();
        console.log('🏢 Business error:', businessErrorText.trim());
      }
      
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
    
    // Check page content for any error indicators
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
      'forbidden',
      'already exists',
      'duplicate'
    ];
    
    errorIndicators.forEach(indicator => {
      if (pageContent.toLowerCase().includes(indicator)) {
        console.log(`⚠️ Found error indicator: "${indicator}"`);
      }
    });
    
    console.log('\n📋 SIGNUP ERROR DETECTION RESULTS:');
    console.log('✅ Form structure:', 'Checked');
    console.log('✅ Form fields:', 'Verified');
    console.log('✅ JavaScript errors:', consoleErrors.length > 0 ? 'Found' : 'None');
    console.log('✅ Form submission:', currentUrl !== '/signup' ? 'Successful' : 'Failed');
    
    // Take screenshot
    await page.screenshot({ path: 'signup-error-detection-test.png' });
    console.log('📸 Screenshot saved as signup-error-detection-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testSignupErrorDetection();
