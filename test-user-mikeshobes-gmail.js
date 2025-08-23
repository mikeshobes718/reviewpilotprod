const puppeteer = require('puppeteer');

async function testUserMikeshobesGmail() {
  console.log('🧪 Testing User: mikeshobes718@gmail.com');
  
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
    
    console.log('\n🧪 Test: Attempting login with mikeshobes718@gmail.com...');
    
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
    
    // Submit form using page.evaluate to bypass any event handlers
    const submissionResult = await page.evaluate((token) => {
      const form = document.querySelector('form');
      if (!form) return 'No form found';
      
      // Fill the form fields
      const emailInput = form.querySelector('input[name="email"]');
      const passwordInput = form.querySelector('input[name="password"]');
      
      if (emailInput && passwordInput) {
        emailInput.value = 'mikeshobes718@gmail.com';
        passwordInput.value = 'Test!234';
        
        // Submit the form directly
        form.submit();
        return 'Form submitted via form.submit()';
      } else {
        return 'Form fields not found';
      }
    }, csrfToken);
    
    console.log('  Submission result:', submissionResult);
    
    // Wait for response
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    console.log('\n📊 Results after submission:');
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
      console.log('✅ SUCCESS! Redirected to dashboard');
      
      // Get dashboard content
      const pageContent = await page.content();
      
      // Check for business name
      const businessNameMatch = pageContent.match(/<h[1-6][^>]*>([^<]+)<\/h[1-6]>/);
      if (businessNameMatch) {
        console.log('  Business/User name found:', businessNameMatch[1].trim());
      }
      
      // Check for subscription info
      if (pageContent.includes('STARTER PLAN') || pageContent.includes('FREE TRIAL')) {
        console.log('  Subscription: STARTER PLAN (FREE TRIAL)');
      } else if (pageContent.includes('PRO PLAN')) {
        console.log('  Subscription: PRO PLAN');
      } else {
        console.log('  Subscription: Unknown');
      }
      
      // Check for any verification notices
      if (pageContent.includes('verification') || pageContent.includes('verify')) {
        console.log('  Verification notice: Found');
      } else {
        console.log('  Verification notice: None');
      }
      
    } else if (page.url().includes('/login')) {
      console.log('❌ Still on login page - authentication failed');
      
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
    
    console.log('\n📋 LOGIN TEST RESULTS:');
    console.log('✅ Form submission method:', 'Direct (bypassing JavaScript)');
    console.log('✅ CSRF token:', csrfToken ? 'Found' : 'Missing');
    console.log('✅ Network requests:', requests.length);
    console.log('✅ Final URL:', page.url());
    console.log('✅ Dashboard access:', page.url().includes('/dashboard') ? 'SUCCESS' : 'FAILED');
    
    // Take screenshot
    await page.screenshot({ path: 'mikeshobes-gmail-login-test.png' });
    console.log('📸 Screenshot saved as mikeshobes-gmail-login-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testUserMikeshobesGmail();
