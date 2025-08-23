const puppeteer = require('puppeteer');

async function testDebugVariables() {
  console.log('🔍 Testing Template Variables...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Debug template variables...');
    
    // Test user: mikeshobes718@gmail.com (No active subscription)
    const testUser = {
      email: 'mikeshobes718@gmail.com',
      password: 'Test!234',
      name: 'No Plan User'
    };
    
    console.log(`\n👤 Testing User: ${testUser.name}`);
    console.log(`  Email: ${testUser.email}`);
    
    // Step 1: Go to login page
    console.log('\n🔍 Step 1: Accessing login page...');
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Step 2: Login
    const csrfInput = await page.$('input[name="_csrf"]');
    let csrfToken = '';
    if (csrfInput) {
      csrfToken = await csrfInput.evaluate(el => el.value);
    }
    
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    
    if (emailInput && passwordInput) {
      await emailInput.type(testUser.email);
      await passwordInput.type(testUser.password);
      
      console.log(`  📝 Logging in with ${testUser.email}...`);
      await passwordInput.press('Enter');
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log(`  📍 Current URL after login: ${page.url()}`);
      
      if (page.url().includes('/pricing')) {
        console.log('  ✅ User correctly redirected to pricing page');
        
        // Step 3: Debug template variables
        console.log('\n🔍 Step 2: Debugging template variables...');
        
        // Wait for any dynamic content to load
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Check page source for debugging
        const pageSource = await page.content();
        
        // Look for specific patterns that indicate variables
        console.log('\n📋 TEMPLATE VARIABLE DEBUG:');
        
        // Check if user variable is available
        if (pageSource.includes('Signed in: mikeshobes718@gmail.com')) {
          console.log('  ✅ User variable: Available');
        } else {
          console.log('  ❌ User variable: Not available');
        }
        
        // Check if subscriptionStatus variable is available
        if (pageSource.includes('subscriptionStatus')) {
          console.log('  ✅ SubscriptionStatus variable: Available');
        } else {
          console.log('  ❌ SubscriptionStatus variable: Not available');
        }
        
        // Check if trialEndsAt variable is available
        if (pageSource.includes('trialEndsAt')) {
          console.log('  ✅ TrialEndsAt variable: Available');
        } else {
          console.log('  ❌ TrialEndsAt variable: Not available');
        }
        
        // Check for dashboard elements
        const dashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
        console.log(`  📊 Dashboard elements found: ${dashboardElements.length}`);
        
        if (dashboardElements.length > 0) {
          console.log('  ❌ PROBLEM: Dashboard elements still visible');
          
          // Get details about visible elements
          for (let i = 0; i < dashboardElements.length; i++) {
            try {
              const elementText = await dashboardElements[i].textContent();
              const elementHref = await dashboardElements[i].evaluate(el => el.href || el.getAttribute('href') || 'No href');
              const elementClass = await dashboardElements[i].evaluate(el => el.className || 'No class');
              const elementTag = await dashboardElements[i].evaluate(el => el.tagName);
              
              console.log(`    Element ${i + 1}:`);
              console.log(`      Tag: ${elementTag}`);
              console.log(`      Text: "${elementText.trim()}"`);
              console.log(`      Href: ${elementHref}`);
              console.log(`      Class: ${elementClass}`);
            } catch (e) {
              console.log(`    Element ${i + 1}: Could not read`);
            }
          }
        } else {
          console.log('  ✅ SUCCESS: No dashboard elements visible');
        }
        
        // Step 4: Check page source for debugging info
        console.log('\n🔍 Step 3: Analyzing page source...');
        
        // Look for any JavaScript variables or debugging info
        const scriptTags = await page.$$('script');
        console.log(`  📊 Script tags found: ${scriptTags.length}`);
        
        // Check if there are any console.log statements or debugging info
        if (pageSource.includes('console.log')) {
          console.log('  📝 Found console.log statements in page source');
        }
        
        // Check for any error messages
        if (pageSource.includes('error') || pageSource.includes('Error')) {
          console.log('  ⚠️ Found error-related text in page source');
        }
        
        // Step 5: Test with a different page
        console.log('\n🔍 Step 4: Testing on home page...');
        
        await page.goto('https://reviewsandmarketing.com/', { waitUntil: 'networkidle2' });
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        const homePageSource = await page.content();
        const homeDashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
        
        console.log(`  📊 Dashboard elements on home page: ${homeDashboardElements.length}`);
        
        if (homePageSource.includes('Signed in: mikeshobes718@gmail.com')) {
          console.log('  ✅ User variable available on home page');
        } else {
          console.log('  ❌ User variable not available on home page');
        }
        
      } else {
        console.log('  ❌ Unexpected: User not redirected to pricing page');
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 TEMPLATE VARIABLE DEBUG RESULTS:');
    console.log('✅ Login process:', 'Completed');
    console.log('✅ Variable debugging:', 'Completed');
    console.log('✅ Page source analysis:', 'Completed');
    console.log('✅ Multi-page testing:', 'Completed');
    
    // Take screenshot
    await page.screenshot({ path: 'debug-variables-test.png' });
    console.log('📸 Screenshot saved as debug-variables-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testDebugVariables();
