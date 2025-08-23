const puppeteer = require('puppeteer');

async function testFormSubmissionDebug() {
  console.log('🧪 Testing Form Submission Debug...');
  
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
    
    // Monitor network requests more carefully
    const requests = [];
    const responses = [];
    
    page.on('request', request => {
      requests.push({
        url: request.url(),
        method: request.method(),
        headers: request.headers(),
        postData: request.postData()
      });
    });
    
    page.on('response', response => {
      responses.push({
        url: response.url(),
        status: response.status(),
        headers: response.headers()
      });
    });
    
    console.log('\n🧪 Test: Debugging form submission...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Wait for JavaScript to load
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log('📝 Checking form before submission...');
    
    // Get form details
    const form = await page.$('form');
    if (form) {
      const formAction = await form.evaluate(el => el.action);
      const formMethod = await form.evaluate(el => el.method);
      const formId = await form.evaluate(el => el.id);
      
      console.log('  Form Action:', formAction);
      console.log('  Form Method:', formMethod);
      console.log('  Form ID:', formId);
      
      // Check if form has any submit event listeners
      const formSubmitListeners = await form.evaluate(el => {
        const listeners = [];
        if (el.onsubmit) listeners.push('onsubmit');
        if (el.addEventListener) {
          // This is a simplified check - in real browsers we'd need to use getEventListeners
          listeners.push('addEventListener available');
        }
        return listeners;
      });
      
      console.log('  Form Submit Listeners:', formSubmitListeners);
    }
    
    // Clear arrays
    requests.length = 0;
    responses.length = 0;
    consoleMessages.length = 0;
    consoleErrors.length = 0;
    
    console.log('\n🔘 Attempting form submission...');
    
    // Try different submission methods
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      // Fill form
      await emailInput.type('mikeshobes718@yahoo.com');
      await passwordInput.type('T@st1234');
      
      console.log('  Method 1: Clicking submit button...');
      await submitButton.click();
      
      // Wait for any response
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      console.log('\n📊 Results after button click:');
      console.log('  Current URL:', page.url());
      console.log('  Requests made:', requests.length);
      console.log('  Responses received:', responses.length);
      
      if (requests.length > 0) {
        console.log('\n🌐 All Requests:');
        requests.forEach((req, i) => {
          console.log(`  Request ${i + 1}:`, req.method, req.url);
          if (req.postData) {
            console.log(`    Post Data:`, req.postData.substring(0, 100) + '...');
          }
        });
      }
      
      if (responses.length > 0) {
        console.log('\n🌐 All Responses:');
        responses.forEach((res, i) => {
          console.log(`  Response ${i + 1}:`, res.status, res.url);
        });
      }
      
      // Check for JavaScript errors
      if (consoleErrors.length > 0) {
        console.log('\n⚠️ JavaScript errors during submission:');
        consoleErrors.forEach((error, i) => {
          console.log(`  Error ${i + 1}:`, error);
        });
      }
      
      // Check console messages
      if (consoleMessages.length > 0) {
        console.log('\n📝 Console messages during submission:');
        consoleMessages.forEach((msg, i) => {
          console.log(`  Message ${i + 1}:`, msg.type, msg.text);
        });
      }
      
      // Try method 2: form.submit()
      console.log('\n  Method 2: Using form.submit()...');
      
      // Clear arrays again
      requests.length = 0;
      responses.length = 0;
      
      try {
        await form.evaluate(form => form.submit());
        console.log('    Form.submit() executed');
        
        // Wait for response
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        console.log('    Current URL after form.submit():', page.url());
        console.log('    Requests after form.submit():', requests.length);
        console.log('    Responses after form.submit():', responses.length);
        
      } catch (error) {
        console.log('    Form.submit() failed:', error.message);
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 FORM SUBMISSION DEBUG RESULTS:');
    console.log('✅ Form inspection:', 'Completed');
    console.log('✅ Button click test:', 'Completed');
    console.log('✅ Form.submit() test:', 'Completed');
    console.log('✅ Network monitoring:', 'Active');
    console.log('✅ JavaScript error monitoring:', 'Active');
    
    // Take screenshot
    await page.screenshot({ path: 'form-submission-debug-test.png' });
    console.log('📸 Screenshot saved as form-submission-debug-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testFormSubmissionDebug();
