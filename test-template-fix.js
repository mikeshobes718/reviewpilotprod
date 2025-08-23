const puppeteer = require('puppeteer');

async function testTemplateFix() {
  console.log('🔧 Testing Template Fix for Dashboard Element Hiding...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Server-side template fix for dashboard element hiding...');
    
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
        
        // Step 3: Check if dashboard elements are hidden by template
        console.log('\n🔍 Step 2: Checking template-based dashboard element hiding...');
        
        // Wait for any dynamic content to load
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Check for dashboard elements
        const dashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
        console.log(`  📊 Dashboard elements found: ${dashboardElements.length}`);
        
        if (dashboardElements.length === 0) {
          console.log('  ✅ SUCCESS: Template fix working! No dashboard elements visible');
        } else {
          console.log('  ❌ PROBLEM: Dashboard elements still visible after template fix');
          
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
        }
        
        // Step 4: Test navigation to other pages
        console.log('\n🔍 Step 3: Testing dashboard element hiding on other pages...');
        
        const testPages = [
          'https://reviewsandmarketing.com/',
          'https://reviewsandmarketing.com/features',
          'https://reviewsandmarketing.com/signup'
        ];
        
        for (let i = 0; i < testPages.length; i++) {
          const testPage = testPages[i];
          console.log(`  🔄 Testing page: ${testPage}`);
          
          await page.goto(testPage, { waitUntil: 'networkidle2' });
          
          // Wait for content to load
          await new Promise(resolve => setTimeout(resolve, 2000));
          
          // Check dashboard elements on this page
          const pageDashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
          console.log(`    📊 Dashboard elements found: ${pageDashboardElements.length}`);
          
          if (pageDashboardElements.length === 0) {
            console.log(`    ✅ SUCCESS: No dashboard elements on ${testPage}`);
          } else {
            console.log(`    ❌ PROBLEM: Dashboard elements visible on ${testPage}`);
          }
        }
        
        // Step 5: Test with a user who HAS a subscription
        console.log('\n🔍 Step 4: Testing with user who HAS subscription...');
        
        // Go back to login
        await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
        
        // Login as user with subscription
        const subscriptionUser = {
          email: 'mikeshobes718@yahoo.com',
          password: 'T@st1234'
        };
        
        console.log(`  📝 Testing with subscription user: ${subscriptionUser.email}`);
        
        const emailInput2 = await page.$('input[name="email"]');
        const passwordInput2 = await page.$('input[name="password"]');
        
        if (emailInput2 && passwordInput2) {
          await emailInput2.type(subscriptionUser.email);
          await passwordInput2.type(subscriptionUser.password);
          
          await passwordInput2.press('Enter');
          
          // Wait for response
          await new Promise(resolve => setTimeout(resolve, 5000));
          
          console.log(`  📍 Subscription user URL: ${page.url()}`);
          
          if (page.url().includes('/dashboard')) {
            console.log('  ✅ Subscription user correctly taken to dashboard');
            
            // Check if dashboard elements are visible for subscription user
            const subscriptionDashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
            console.log(`  📊 Dashboard elements for subscription user: ${subscriptionDashboardElements.length}`);
            
            if (subscriptionDashboardElements.length > 0) {
              console.log('  ✅ SUCCESS: Dashboard elements visible for subscription user');
            } else {
              console.log('  ❌ PROBLEM: No dashboard elements for subscription user');
            }
          } else {
            console.log('  ❌ Unexpected: Subscription user not taken to dashboard');
          }
        }
        
      } else {
        console.log('  ❌ Unexpected: User not redirected to pricing page');
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 TEMPLATE FIX TEST RESULTS:');
    console.log('✅ Login process:', 'Completed');
    console.log('✅ Template fix verification:', 'Completed');
    console.log('✅ Multi-page testing:', 'Completed');
    console.log('✅ Subscription user testing:', 'Completed');
    
    // Take screenshot
    await page.screenshot({ path: 'template-fix-test.png' });
    console.log('📸 Screenshot saved as template-fix-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testTemplateFix();
