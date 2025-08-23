const puppeteer = require('puppeteer');

async function testJavaScriptErrors() {
  console.log('🧪 Testing JavaScript Errors...');
  
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
    
    console.log('\n🧪 Test: Checking for JavaScript errors...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Wait a moment for any JavaScript to load
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check for JavaScript errors on page load
    if (consoleErrors.length > 0) {
      console.log('⚠️ JavaScript errors found on page load:');
      consoleErrors.forEach((error, i) => {
        console.log(`  Error ${i + 1}:`, error);
      });
    } else {
      console.log('✅ No JavaScript errors on page load');
    }
    
    // Check console messages
    if (consoleMessages.length > 0) {
      console.log('📝 Console messages on page load:');
      consoleMessages.forEach((msg, i) => {
        console.log(`  Message ${i + 1}:`, msg.type, msg.text);
      });
    }
    
    // Clear arrays for form submission test
    consoleMessages.length = 0;
    consoleErrors.length = 0;
    
    // Try to submit the form
    console.log('\n🧪 Test: Attempting form submission...');
    
    const form = await page.$('form');
    if (form) {
      // Try to submit the form programmatically
      console.log('📝 Submitting form programmatically...');
      
      try {
        await form.evaluate(form => form.submit());
        console.log('✅ Form submitted programmatically');
      } catch (error) {
        console.log('❌ Form submission failed:', error.message);
      }
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 3000));
      
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
      
      // Check current URL
      const currentUrl = page.url();
      console.log('📍 Current URL after submission:', currentUrl);
      
    } else {
      console.log('❌ No form found');
    }
    
    // Check if there are any JavaScript functions that might be interfering
    console.log('\n🔍 Checking for interfering JavaScript...');
    
    const interferingJS = await page.evaluate(() => {
      const results = {};
      
      // Check for common form submission blockers
      results.preventDefaultExists = typeof Event !== 'undefined' && Event.prototype.preventDefault;
      results.stopPropagationExists = typeof Event !== 'undefined' && Event.prototype.stopPropagation;
      
      // Check for any global form handlers
      results.globalSubmitHandler = typeof window.onSubmit !== 'undefined';
      results.globalFormHandler = typeof window.onForm !== 'undefined';
      
      // Check for any form validation
      results.formValidation = document.querySelector('form') ? document.querySelector('form').checkValidity() : false;
      
      // Check if form has any submit event listeners
      const form = document.querySelector('form');
      if (form) {
        results.formSubmitListeners = form.onSubmit !== null;
        results.formAction = form.action;
        results.formMethod = form.method;
        results.formTarget = form.target;
      }
      
      return results;
    });
    
    console.log('🔍 JavaScript Interference Check:', interferingJS);
    
    console.log('\n📋 JAVASCRIPT ERROR TEST RESULTS:');
    console.log('✅ Page load errors:', consoleErrors.length > 0 ? 'Found' : 'None');
    console.log('✅ Form submission errors:', consoleErrors.length > 0 ? 'Found' : 'None');
    console.log('✅ Console messages:', consoleMessages.length);
    console.log('✅ JavaScript interference:', 'Checked');
    
    // Take screenshot
    await page.screenshot({ path: 'javascript-errors-test.png' });
    console.log('📸 Screenshot saved as javascript-errors-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testJavaScriptErrors();

