const puppeteer = require('puppeteer');

async function testAccessControlDashboardButton() {
  console.log('🔒 Testing Access Control - Dashboard Button Visibility...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Checking dashboard button visibility for users without plans...');
    
    // Test the user without a plan: mikeshobes718@gmail.com
    console.log('\n👤 Testing User: mikeshobes718@gmail.com (No active subscription)');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get CSRF token
    const csrfInput = await page.$('input[name="_csrf"]');
    let csrfToken = '';
    if (csrfInput) {
      csrfToken = await csrfInput.evaluate(el => el.value);
    }
    
    // Login using Enter key (the working workaround)
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    
    if (emailInput && passwordInput) {
      await emailInput.type('mikeshobes718@gmail.com');
      await passwordInput.type('Test!234');
      
      console.log('  📝 Logging in with mikeshobes718@gmail.com...');
      await passwordInput.press('Enter');
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log(`  📍 Current URL after login: ${page.url()}`);
      
      if (page.url().includes('/pricing')) {
        console.log('  ✅ User correctly redirected to pricing page (no access)');
        
        // Check if dashboard button/link is visible on pricing page
        console.log('\n🔍 Checking for dashboard button/link on pricing page...');
        
        const dashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
        console.log(`  📊 Dashboard elements found: ${dashboardElements.length}`);
        
        if (dashboardElements.length > 0) {
          console.log('  ❌ PROBLEM: Dashboard elements are visible to user without subscription!');
          
          // Check what dashboard elements are visible
          for (let i = 0; i < dashboardElements.length; i++) {
            try {
              const elementText = await dashboardElements[i].textContent();
              const elementHref = await dashboardElements[i].evaluate(el => el.href || el.getAttribute('href') || 'No href');
              console.log(`    Element ${i + 1}: "${elementText.trim()}" - ${elementHref}`);
            } catch (e) {
              console.log(`    Element ${i + 1}: Could not read`);
            }
          }
        } else {
          console.log('  ✅ CORRECT: No dashboard elements visible to user without subscription');
        }
        
        // Check for any navigation that might lead to dashboard
        console.log('\n🔍 Checking for navigation elements...');
        
        const navElements = await page.$$('nav, .navigation, .navbar, .menu, .header');
        console.log(`  📊 Navigation elements found: ${navElements.length}`);
        
        if (navElements.length > 0) {
          for (let i = 0; i < navElements.length; i++) {
            try {
              const navText = await navElements[i].textContent();
              console.log(`    Navigation ${i + 1}: ${navText.substring(0, 100).trim()}...`);
            } catch (e) {
              console.log(`    Navigation ${i + 1}: Could not read`);
            }
          }
        }
        
        // Check if user can manually navigate to dashboard
        console.log('\n🔍 Testing manual navigation to dashboard...');
        
        try {
          await page.goto('https://reviewsandmarketing.com/dashboard', { waitUntil: 'networkidle2' });
          console.log(`  📍 Manual dashboard URL result: ${page.url()}`);
          
          if (page.url().includes('/dashboard')) {
            console.log('  ❌ PROBLEM: User without subscription can access dashboard directly!');
            
            // Check dashboard content
            const pageContent = await page.content();
            if (pageContent.includes('verification') || pageContent.includes('verify')) {
              console.log('  📝 Dashboard shows verification notice');
            } else {
              console.log('  📝 Dashboard content accessible');
            }
            
          } else if (page.url().includes('/pricing')) {
            console.log('  ✅ CORRECT: User redirected to pricing when trying to access dashboard');
          } else {
            console.log('  🔄 Redirected to unknown page:', page.url());
          }
          
        } catch (error) {
          console.log('  ❌ Error accessing dashboard:', error.message);
        }
        
      } else {
        console.log('  ❌ Unexpected: User not redirected to pricing page');
        console.log('  📍 Current URL:', page.url());
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n🔍 Testing access control for users WITH plans...');
    
    // Test a user with a plan to compare
    console.log('\n👤 Testing User: mikeshobes718@yahoo.com (PRO PLAN - should see dashboard)');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get fresh CSRF token
    const newCsrfInput = await page.$('input[name="_csrf"]');
    if (newCsrfInput) {
      csrfToken = await newCsrfInput.evaluate(el => el.value);
    }
    
    // Login with user who has a plan
    const emailInput2 = await page.$('input[name="email"]');
    const passwordInput2 = await page.$('input[name="password"]');
    
    if (emailInput2 && passwordInput2) {
      await emailInput2.type('mikeshobes718@yahoo.com');
      await passwordInput2.type('T@st1234');
      
      console.log('  📝 Logging in with mikeshobes718@yahoo.com...');
      await passwordInput2.press('Enter');
      
      // Wait for response
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      console.log(`  📍 Current URL after login: ${page.url()}`);
      
      if (page.url().includes('/dashboard')) {
        console.log('  ✅ User with plan successfully accessed dashboard');
        
        // Check what dashboard elements are visible to user with plan
        console.log('\n🔍 Checking dashboard elements for user WITH plan...');
        
        const dashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
        console.log(`  📊 Dashboard elements found: ${dashboardElements.length}`);
        
        if (dashboardElements.length > 0) {
          console.log('  ✅ CORRECT: Dashboard elements visible to user with subscription');
        } else {
          console.log('  ❌ PROBLEM: No dashboard elements visible to user with subscription');
        }
        
      } else {
        console.log('  ❌ Unexpected: User with plan not redirected to dashboard');
      }
      
    } else {
      console.log('❌ Form elements not found for second user');
    }
    
    console.log('\n📋 ACCESS CONTROL TEST RESULTS:');
    console.log('✅ No-plan user test:', 'Completed');
    console.log('✅ Dashboard button visibility:', 'Checked');
    console.log('✅ Manual dashboard access:', 'Tested');
    console.log('✅ Plan user comparison:', 'Completed');
    console.log('✅ Access control verification:', 'Completed');
    
    // Take screenshot
    await page.screenshot({ path: 'access-control-dashboard-button-test.png' });
    console.log('📸 Screenshot saved as access-control-dashboard-button-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testAccessControlDashboardButton();
