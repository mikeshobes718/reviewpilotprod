const puppeteer = require('puppeteer');

async function testJavaScriptInterception() {
  console.log('🔍 Testing JavaScript Interception...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Monitor console messages
    const consoleMessages = [];
    
    page.on('console', msg => {
      consoleMessages.push({
        type: msg.type(),
        text: msg.text()
      });
    });
    
    console.log('\n🧪 Test: Finding JavaScript that intercepts form submission...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Wait for JavaScript to load
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    console.log('\n🔍 Step 1: Checking for hidden event handlers...');
    
    // Check for any hidden event handlers or form interception
    const hiddenHandlers = await page.evaluate(() => {
      const results = {};
      
      // Check if there are any global form submission interceptors
      results.documentSubmit = typeof document.submit !== 'undefined';
      results.documentForms = document.forms.length;
      
      // Check for any MutationObserver that might be watching forms
      results.mutationObserver = typeof MutationObserver !== 'undefined';
      
      // Check for any form-related global functions
      results.globalFunctions = [];
      for (const key in window) {
        if (typeof window[key] === 'function' && 
            (key.toLowerCase().includes('form') || 
             key.toLowerCase().includes('submit') ||
             key.toLowerCase().includes('login'))) {
          results.globalFunctions.push(key);
        }
      }
      
      // Check if there are any event listeners on the document
      results.documentEventListeners = [];
      if (typeof document.addEventListener === 'function') {
        results.documentEventListeners.push('addEventListener available');
      }
      
      // Check for any form validation or submission libraries
      results.formLibraries = [];
      if (window.HTMLFormElement && window.HTMLFormElement.prototype.submit) {
        results.formLibraries.push('HTMLFormElement.prototype.submit available');
      }
      
      return results;
    });
    
    console.log('📊 Hidden Handlers Analysis:', hiddenHandlers);
    
    console.log('\n🔍 Step 2: Testing form submission with event monitoring...');
    
    // Clear console messages
    consoleMessages.length = 0;
    
    // Add our own event listener to see what happens
    await page.evaluate(() => {
      const form = document.querySelector('form');
      if (form) {
        // Monitor all form events
        const events = ['submit', 'click', 'mousedown', 'mouseup', 'keydown', 'keyup'];
        events.forEach(eventType => {
          form.addEventListener(eventType, function(e) {
            console.log(`🔍 Form ${eventType} event triggered!`);
            console.log(`🔍 Event details:`, {
              type: e.type,
              target: e.target.tagName,
              currentTarget: e.currentTarget.tagName,
              defaultPrevented: e.defaultPrevented,
              cancelable: e.cancelable,
              timestamp: e.timeStamp
            });
          });
        });
        
        // Monitor submit button events
        const submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
          events.forEach(eventType => {
            submitButton.addEventListener(eventType, function(e) {
              console.log(`🔍 Submit button ${eventType} event triggered!`);
              console.log(`🔍 Event details:`, {
                type: e.type,
                target: e.target.tagName,
                defaultPrevented: e.defaultPrevented,
                cancelable: e.cancelable,
                timestamp: e.timeStamp
              });
            });
          });
        }
      }
    });
    
    console.log('🔍 Step 3: Attempting form submission with monitoring...');
    
    // Fill and submit the form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      await emailInput.type('mikeshobes718@yahoo.com');
      await passwordInput.type('T@st1234');
      
      console.log('🔘 Clicking submit button with event monitoring...');
      await submitButton.click();
      
      // Wait for any events to fire
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      console.log('\n📊 Event monitoring results:');
      console.log('  Current URL:', page.url());
      
      // Check console messages for events
      if (consoleMessages.length > 0) {
        console.log('\n📝 Console messages (events detected):');
        consoleMessages.forEach((msg, i) => {
          console.log(`  Message ${i + 1}:`, msg.type, msg.text);
        });
      } else {
        console.log('❌ No events detected - form submission completely blocked');
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 JAVASCRIPT INTERCEPTION TEST RESULTS:');
    console.log('✅ Hidden handler analysis:', 'Completed');
    console.log('✅ Event monitoring:', 'Active');
    console.log('✅ Form submission test:', 'Completed');
    console.log('✅ Events detected:', consoleMessages.length);
    console.log('✅ Final URL:', page.url());
    
    // Take screenshot
    await page.screenshot({ path: 'javascript-interception-test.png' });
    console.log('📸 Screenshot saved as javascript-interception-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testJavaScriptInterception();
