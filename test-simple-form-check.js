const puppeteer = require('puppeteer');

async function testSimpleFormCheck() {
  console.log('🧪 Testing Simple Form Check...');
  
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
    
    console.log('\n🧪 Test: Checking login form submission...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
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
    
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      console.log('✅ All form fields found');
      
      // Check if submit button is disabled
      const isDisabled = await submitButton.evaluate(el => el.disabled);
      console.log('🔘 Submit button disabled:', isDisabled);
      
    } else {
      console.log('❌ Some form fields missing');
      return;
    }
    
    // Try to submit form
    console.log('\n🧪 Attempting form submission...');
    
    // Clear console messages and errors for submission test
    consoleMessages.length = 0;
    consoleErrors.length = 0;
    
    // Fill form
    await emailInput.type('mikeshobes718@yahoo.com');
    await passwordInput.type('T@st1234');
    
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
    const emailValue = await emailInput.evaluate(el => el.value);
    const passwordValue = await passwordInput.evaluate(el => el.value);
    
    console.log('📧 Email field value after submission:', emailValue);
    console.log('🔑 Password field value after submission:', passwordValue);
    
    // Check for any error messages
    const errorElements = await page.$$('.error, .noticeBanner, .form-error');
    if (errorElements.length > 0) {
      console.log('⚠️ Error elements found after submission:', errorElements.length);
      for (let i = 0; i < errorElements.length; i++) {
        try {
          const errorText = await errorElements[i].textContent();
          console.log(`  Error ${i + 1}:`, errorText.trim());
        } catch (e) {
          console.log(`  Error ${i + 1}: Could not read`);
        }
      }
    } else {
      console.log('✅ No error elements found after submission');
    }
    
    // Check if we're still on login page
    if (currentUrl.includes('/login')) {
      console.log('⚠️ Still on login page - form submission may have failed');
      
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
    
    console.log('\n📋 SIMPLE FORM CHECK RESULTS:');
    console.log('✅ Form structure:', 'Checked');
    console.log('✅ Form fields:', 'Verified');
    console.log('✅ JavaScript errors:', consoleErrors.length > 0 ? 'Found' : 'None');
    console.log('✅ Form submission:', currentUrl !== '/login' ? 'Successful' : 'Failed');
    
    // Take screenshot
    await page.screenshot({ path: 'simple-form-check-test.png' });
    console.log('📸 Screenshot saved as simple-form-check-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testSimpleFormCheck();
