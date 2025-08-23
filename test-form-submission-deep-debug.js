const puppeteer = require('puppeteer');

async function testFormSubmissionDeepDebug() {
  console.log('🔍 Deep Debug: Form Submission Investigation...');
  
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
    
    console.log('\n🧪 Test: Deep investigation of form submission...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Wait for JavaScript to load
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    console.log('\n🔍 Step 1: Analyzing page structure and JavaScript...');
    
    // Get detailed information about the page
    const pageAnalysis = await page.evaluate(() => {
      const results = {};
      
      // Check form details
      const form = document.querySelector('form');
      if (form) {
        results.formAction = form.action;
        results.formMethod = form.method;
        results.formId = form.id;
        results.formClass = form.className;
        results.formHasSubmitHandler = form.onsubmit !== null;
        results.formHasEventListener = typeof form.addEventListener === 'function';
        
        // Check submit button
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
          results.submitButtonType = submitButton.type;
          results.submitButtonDisabled = submitButton.disabled;
          results.submitButtonOnclick = submitButton.onclick;
          results.submitButtonOnmousedown = submitButton.onmousedown;
          results.submitButtonOnmouseup = submitButton.onmouseup;
        }
      }
      
      // Check for any global form handlers
      results.globalOnSubmit = typeof window.onSubmit !== 'undefined';
      results.globalOnForm = typeof window.onForm !== 'undefined';
      
      // Check for any form validation libraries
      results.jQuery = typeof window.jQuery !== 'undefined';
      results.validator = typeof window.validator !== 'undefined';
      results.validate = typeof window.validate !== 'undefined';
      
      // Check for any custom form handling
      results.customFormHandlers = [];
      if (window.addEventListener) {
        // This is a simplified check
        results.customFormHandlers.push('addEventListener available');
      }
      
      return results;
    });
    
    console.log('📊 Page Analysis:', pageAnalysis);
    
    console.log('\n🔍 Step 2: Testing form submission with detailed monitoring...');
    
    // Clear console arrays
    consoleMessages.length = 0;
    consoleErrors.length = 0;
    
    // Fill the form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      console.log('📝 Filling form...');
      await emailInput.type('mikeshobes718@yahoo.com');
      await passwordInput.type('T@st1234');
      
      console.log('🔘 About to click submit button...');
      
      // Monitor what happens when we click
      await page.evaluate(() => {
        // Add a temporary submit handler to see what happens
        const form = document.querySelector('form');
        if (form) {
          form.addEventListener('submit', function(e) {
            console.log('🔍 Form submit event triggered!');
            console.log('🔍 Event details:', {
              type: e.type,
              defaultPrevented: e.defaultPrevented,
              cancelable: e.cancelable,
              target: e.target.tagName
            });
          });
        }
      });
      
      console.log('🔘 Clicking submit button now...');
      await submitButton.click();
      
      // Wait for any response
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      console.log('\n📊 Results after button click:');
      console.log('  Current URL:', page.url());
      
      // Check console messages
      if (consoleMessages.length > 0) {
        console.log('\n📝 Console messages during submission:');
        consoleMessages.forEach((msg, i) => {
          console.log(`  Message ${i + 1}:`, msg.type, msg.text);
        });
      }
      
      // Check for JavaScript errors
      if (consoleErrors.length > 0) {
        console.log('\n⚠️ JavaScript errors during submission:');
        consoleErrors.forEach((error, i) => {
          console.log(`  Error ${i + 1}:`, error);
        });
      }
      
      // Check if form fields still have values
      const emailValue = await emailInput.evaluate(el => el.value);
      const passwordValue = await passwordInput.evaluate(el => el.value);
      
      console.log('\n📝 Form field values after submission:');
      console.log('  Email:', emailValue);
      console.log('  Password:', passwordValue);
      
      // Check for any error messages
      const errorElements = await page.$$('.error, .noticeBanner, .form-error, .alert');
      if (errorElements.length > 0) {
        console.log('\n⚠️ Error elements found:');
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
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 DEEP DEBUG RESULTS:');
    console.log('✅ Page analysis:', 'Completed');
    console.log('✅ Form submission test:', 'Completed');
    console.log('✅ Console monitoring:', 'Active');
    console.log('✅ Error detection:', 'Active');
    console.log('✅ Final URL:', page.url());
    
    // Take screenshot
    await page.screenshot({ path: 'form-submission-deep-debug-test.png' });
    console.log('📸 Screenshot saved as form-submission-deep-debug-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testFormSubmissionDeepDebug();
