const puppeteer = require('puppeteer');

async function fixLoginFormJavaScript() {
  console.log('🔧 Fixing Login Form JavaScript...');
  
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
    
    console.log('\n🧪 Test: Fixing JavaScript and testing submit button...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get the CSRF token
    const csrfInput = await page.$('input[name="_csrf"]');
    let csrfToken = '';
    
    if (csrfInput) {
      csrfToken = await csrfInput.evaluate(el => el.value);
      console.log('🔐 CSRF Token found:', csrfToken.substring(0, 20) + '...');
    } else {
      console.log('⚠️ No CSRF token found');
    }
    
    // Clear arrays
    requests.length = 0;
    responses.length = 0;
    
    console.log('\n🔧 Step 1: Removing any problematic event handlers...');
    
    // Remove any submit event handlers that might be preventing submission
    const formFixed = await page.evaluate(() => {
      const form = document.querySelector('form');
      if (!form) return 'No form found';
      
      // Remove any existing submit event listeners
      const newForm = form.cloneNode(true);
      form.parentNode.replaceChild(newForm, form);
      
      // Remove any onclick handlers from submit button
      const submitButton = newForm.querySelector('button[type="submit"]');
      if (submitButton) {
        submitButton.removeAttribute('onclick');
        submitButton.removeAttribute('onmousedown');
        submitButton.removeAttribute('onmouseup');
      }
      
      return 'Form cleaned and event handlers removed';
    });
    
    console.log('  Form fix result:', formFixed);
    
    console.log('\n🔧 Step 2: Testing submit button after JavaScript fix...');
    
    // Fill the form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput && passwordInput && submitButton) {
      console.log('📝 Filling form with test credentials...');
      await emailInput.type('mikeshobes718@yahoo.com');
      await passwordInput.type('T@st1234');
      
      console.log('🔘 Clicking submit button (should work now)...');
      await submitButton.click();
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log('\n📊 Results after JavaScript fix:');
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
      
      // Check if we're on dashboard
      if (page.url().includes('/dashboard')) {
        console.log('✅ SUCCESS! Submit button now works - redirected to dashboard');
      } else if (page.url().includes('/login')) {
        console.log('❌ Submit button still not working - still on login page');
        
        // Check for error messages
        const errorElements = await page.$$('.error, .noticeBanner, .form-error, .alert');
        if (errorElements.length > 0) {
          console.log('⚠️ Error messages found:');
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
        console.log('🔄 Redirected to unknown page:', page.url());
      }
      
    } else {
      console.log('❌ Form elements not found after fix');
    }
    
    console.log('\n📋 JAVASCRIPT FIX TEST RESULTS:');
    console.log('✅ Form cleaning:', 'Completed');
    console.log('✅ Event handler removal:', 'Attempted');
    console.log('✅ Submit button test:', 'Completed');
    console.log('✅ Network monitoring:', 'Active');
    console.log('✅ Final result:', page.url().includes('/dashboard') ? 'SUCCESS' : 'FAILED');
    
    // Take screenshot
    await page.screenshot({ path: 'login-form-javascript-fix-test.png' });
    console.log('📸 Screenshot saved as login-form-javascript-fix-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

fixLoginFormJavaScript();
