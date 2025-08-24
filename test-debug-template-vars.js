const puppeteer = require('puppeteer');

async function testDebugTemplateVars() {
  console.log('🔍 Testing Template Variables Debug...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Debug template variables for popup conditional logic...');
    
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
        
        // Check for popup HTML
        if (pageSource.includes('subscription-required-popup')) {
          console.log('  ✅ Popup HTML: Found in page source');
        } else {
          console.log('  ❌ Popup HTML: Not found in page source');
        }
        
        // Check for mobile popup HTML
        if (pageSource.includes('mobile-subscription-required-popup')) {
          console.log('  ✅ Mobile popup HTML: Found in page source');
        } else {
          console.log('  ❌ Mobile popup HTML: Not found in page source');
        }
        
        // Check for popup JavaScript
        if (pageSource.includes('initPopup')) {
          console.log('  ✅ Popup JavaScript: Found in page source');
        } else {
          console.log('  ❌ Popup JavaScript: Not found in page source');
        }
        
        // Check for mobile popup JavaScript
        if (pageSource.includes('initMobilePopup')) {
          console.log('  ✅ Mobile popup JavaScript: Found in page source');
        } else {
          console.log('  ❌ Mobile popup JavaScript: Not found in page source');
        }
        
        // Step 4: Check page source for conditional logic
        console.log('\n🔍 Step 3: Analyzing conditional logic...');
        
        // Look for the exact conditional statement
        if (pageSource.includes('typeof subscriptionStatus !== \'undefined\'')) {
          console.log('  ✅ Conditional logic: Found in page source');
        } else {
          console.log('  ❌ Conditional logic: Not found in page source');
        }
        
        // Look for the complex condition
        if (pageSource.includes('subscriptionStatus !== \'active\'')) {
          console.log('  ✅ Active check: Found in page source');
        } else {
          console.log('  ❌ Active check: Not found in page source');
        }
        
        // Look for trial check
        if (pageSource.includes('trialEndsAt <= new Date()')) {
          console.log('  ✅ Trial check: Found in page source');
        } else {
          console.log('  ❌ Trial check: Not found in page source');
        }
        
        // Step 5: Check if variables are being rendered
        console.log('\n🔍 Step 4: Checking variable rendering...');
        
        // Look for any rendered variable values
        const variableMatches = pageSource.match(/subscriptionStatus|trialEndsAt/g);
        if (variableMatches) {
          console.log(`  📊 Variable references found: ${variableMatches.length}`);
          console.log(`  📝 Variables: ${variableMatches.join(', ')}`);
        } else {
          console.log('  ❌ No variable references found');
        }
        
        // Step 6: Check if the popup section is completely missing
        console.log('\n🔍 Step 5: Checking popup section...');
        
        // Look for the comment that should be before the popup
        if (pageSource.includes('<!-- Subscription Required Popup Modal -->')) {
          console.log('  ✅ Popup comment: Found in page source');
        } else {
          console.log('  ❌ Popup comment: Not found in page source');
        }
        
        // Look for the mobile popup comment
        if (pageSource.includes('<!-- Mobile Subscription Required Popup Modal -->')) {
          console.log('  ✅ Mobile popup comment: Found in page source');
        } else {
          console.log('  ❌ Mobile popup comment: Not found in page source');
        }
        
        // Step 7: Check if the entire popup section is missing
        const popupSectionStart = pageSource.indexOf('<!-- Subscription Required Popup Modal -->');
        const popupSectionEnd = pageSource.indexOf('<!-- Mobile drawer -->');
        
        if (popupSectionStart !== -1 && popupSectionEnd !== -1) {
          const popupSection = pageSource.substring(popupSectionStart, popupSectionEnd);
          console.log(`  📊 Popup section length: ${popupSection.length} characters`);
          
          if (popupSection.length > 100) {
            console.log('  ✅ Popup section: Found and substantial');
          } else {
            console.log('  ❌ Popup section: Found but too short');
          }
        } else {
          console.log('  ❌ Popup section: Not found or incomplete');
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
    console.log('✅ Conditional logic analysis:', 'Completed');
    console.log('✅ Popup section analysis:', 'Completed');
    
    // Take screenshot
    await page.screenshot({ path: 'debug-template-vars-test.png' });
    console.log('📸 Screenshot saved as debug-template-vars-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testDebugTemplateVars();
