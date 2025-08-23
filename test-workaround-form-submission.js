const puppeteer = require('puppeteer');

async function testWorkaroundFormSubmission() {
  console.log('🔧 Testing Form Submission Workarounds...');
  
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
    
    console.log('\n🧪 Test: Trying different form submission workarounds...');
    
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
    
    console.log('\n🔧 Workaround 1: Using Enter key to submit form...');
    
    // Fill the form
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    
    if (emailInput && passwordInput) {
      await emailInput.type('mikeshobes718@yahoo.com');
      await passwordInput.type('T@st1234');
      
      // Try pressing Enter in the password field
      console.log('  Pressing Enter in password field...');
      await passwordInput.press('Enter');
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      console.log('  Current URL after Enter key:', page.url());
      console.log('  Requests made:', requests.length);
      console.log('  Responses received:', responses.length);
      
      if (requests.length > 0) {
        console.log('  ✅ Enter key submission worked!');
      } else {
        console.log('  ❌ Enter key submission failed');
      }
    }
    
    // Clear arrays for next test
    requests.length = 0;
    responses.length = 0;
    
    console.log('\n🔧 Workaround 2: Using JavaScript dispatchEvent...');
    
    // Go back to login page
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get fresh CSRF token
    const newCsrfInput = await page.$('input[name="_csrf"]');
    if (newCsrfInput) {
      csrfToken = await newCsrfInput.evaluate(el => el.value);
    }
    
    // Fill form again
    const emailInput2 = await page.$('input[name="email"]');
    const passwordInput2 = await page.$('input[name="password"]');
    
    if (emailInput2 && passwordInput2) {
      await emailInput2.type('mikeshobes718@yahoo.com');
      await passwordInput2.type('T@st1234');
      
      // Try dispatching a submit event manually
      console.log('  Dispatching submit event manually...');
      const submitEvent = await page.evaluate(() => {
        const form = document.querySelector('form');
        if (form) {
          const event = new Event('submit', { bubbles: true, cancelable: true });
          form.dispatchEvent(event);
          return 'Submit event dispatched';
        }
        return 'No form found';
      });
      
      console.log('  Submit event result:', submitEvent);
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      console.log('  Current URL after submit event:', page.url());
      console.log('  Requests made:', requests.length);
      console.log('  Responses received:', responses.length);
      
      if (requests.length > 0) {
        console.log('  ✅ Manual submit event worked!');
      } else {
        console.log('  ❌ Manual submit event failed');
      }
    }
    
    // Clear arrays for next test
    requests.length = 0;
    responses.length = 0;
    
    console.log('\n🔧 Workaround 3: Using fetch API directly...');
    
    // Go back to login page
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get fresh CSRF token
    const finalCsrfInput = await page.$('input[name="_csrf"]');
    if (finalCsrfInput) {
      csrfToken = await finalCsrfInput.evaluate(el => el.value);
    }
    
    // Try using fetch API directly
    console.log('  Using fetch API to submit form...');
    const fetchResult = await page.evaluate((token) => {
      const formData = new FormData();
      formData.append('_csrf', token);
      formData.append('email', 'mikeshobes718@yahoo.com');
      formData.append('password', 'T@st1234');
      
      return fetch('/auth/login', {
        method: 'POST',
        body: formData,
        redirect: 'follow'
      }).then(response => {
        if (response.redirected) {
          window.location.href = response.url;
          return 'Redirect successful';
        } else {
          return 'No redirect';
        }
      }).catch(error => {
        return 'Fetch error: ' + error.message;
      });
    }, csrfToken);
    
    console.log('  Fetch API result:', fetchResult);
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    console.log('  Current URL after fetch API:', page.url());
    console.log('  Requests made:', requests.length);
    console.log('  Responses received:', responses.length);
    
    if (requests.length > 0) {
      console.log('  ✅ Fetch API submission worked!');
    } else {
      console.log('  ❌ Fetch API submission failed');
    }
    
    console.log('\n📋 WORKAROUND TEST RESULTS:');
    console.log('✅ Enter key test:', 'Completed');
    console.log('✅ Manual submit event:', 'Completed');
    console.log('✅ Fetch API test:', 'Completed');
    console.log('✅ Final URL:', page.url());
    console.log('✅ Dashboard access:', page.url().includes('/dashboard') ? 'SUCCESS' : 'FAILED');
    
    // Take screenshot
    await page.screenshot({ path: 'workaround-form-submission-test.png' });
    console.log('📸 Screenshot saved as workaround-form-submission-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testWorkaroundFormSubmission();
