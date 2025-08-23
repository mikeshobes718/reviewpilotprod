const puppeteer = require('puppeteer');

async function testPricingPageInvestigation() {
  console.log('🔍 Investigating Pricing Page Template...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Investigating pricing page template and dashboard elements...');
    
    // First, check pricing page without being logged in
    console.log('\n🔍 Step 1: Checking pricing page as anonymous user...');
    
    await page.goto('https://reviewsandmarketing.com/pricing', { waitUntil: 'networkidle2' });
    
    console.log(`  📍 Pricing page URL: ${page.url()}`);
    
    // Check for dashboard elements on public pricing page
    const publicDashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
    console.log(`  📊 Dashboard elements found (public): ${publicDashboardElements.length}`);
    
    if (publicDashboardElements.length > 0) {
      console.log('  ❌ PROBLEM: Dashboard elements visible on public pricing page!');
      
      for (let i = 0; i < publicDashboardElements.length; i++) {
        try {
          const elementText = await publicDashboardElements[i].textContent();
          const elementHref = await publicDashboardElements[i].evaluate(el => el.href || el.getAttribute('href') || 'No href');
          const elementClass = await publicDashboardElements[i].evaluate(el => el.className || 'No class');
          console.log(`    Element ${i + 1}: "${elementText.trim()}" - ${elementHref} - Class: ${elementClass}`);
        } catch (e) {
          console.log(`    Element ${i + 1}: Could not read`);
        }
      }
    } else {
      console.log('  ✅ CORRECT: No dashboard elements visible on public pricing page');
    }
    
    // Check page source to see what's being rendered
    console.log('\n🔍 Step 2: Analyzing pricing page source code...');
    
    const pageSource = await page.content();
    
    // Look for dashboard-related content in the HTML
    const dashboardKeywords = ['dashboard', 'Dashboard', 'DASHBOARD'];
    const foundKeywords = [];
    
    dashboardKeywords.forEach(keyword => {
      if (pageSource.includes(keyword)) {
        foundKeywords.push(keyword);
      }
    });
    
    console.log(`  📝 Dashboard keywords found in source: ${foundKeywords.join(', ')}`);
    
    // Look for specific dashboard elements in HTML
    if (pageSource.includes('href="/dashboard"') || pageSource.includes('href=\'/dashboard\'')) {
      console.log('  ❌ Found dashboard link in HTML source');
    }
    
    if (pageSource.includes('onclick') && pageSource.includes('dashboard')) {
      console.log('  ❌ Found dashboard onclick in HTML source');
    }
    
    // Check for any conditional rendering logic
    if (pageSource.includes('if') && pageSource.includes('subscription')) {
      console.log('  📝 Found subscription conditional logic in template');
    }
    
    if (pageSource.includes('user') && pageSource.includes('plan')) {
      console.log('  📝 Found user plan logic in template');
    }
    
    // Now check pricing page as logged-in user without subscription
    console.log('\n🔍 Step 3: Checking pricing page as logged-in user without subscription...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get CSRF token
    const csrfInput = await page.$('input[name="_csrf"]');
    let csrfToken = '';
    if (csrfInput) {
      csrfToken = await csrfInput.evaluate(el => el.value);
    }
    
    // Login with user without subscription
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
        console.log('  ✅ User correctly on pricing page');
        
        // Check dashboard elements again
        const loggedInDashboardElements = await page.$$('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
        console.log(`  📊 Dashboard elements found (logged-in, no plan): ${loggedInDashboardElements.length}`);
        
        if (loggedInDashboardElements.length > 0) {
          console.log('  ❌ PROBLEM: Dashboard elements still visible to logged-in user without plan!');
          
          // Get more details about these elements
          for (let i = 0; i < loggedInDashboardElements.length; i++) {
            try {
              const elementText = await loggedInDashboardElements[i].textContent();
              const elementHref = await loggedInDashboardElements[i].evaluate(el => el.href || el.getAttribute('href') || 'No href');
              const elementClass = await loggedInDashboardElements[i].evaluate(el => el.className || 'No class');
              const elementId = await loggedInDashboardElements[i].evaluate(el => el.id || 'No id');
              const elementTag = await loggedInDashboardElements[i].evaluate(el => el.tagName);
              
              console.log(`    Element ${i + 1}:`);
              console.log(`      Tag: ${elementTag}`);
              console.log(`      Text: "${elementText.trim()}"`);
              console.log(`      Href: ${elementHref}`);
              console.log(`      Class: ${elementClass}`);
              console.log(`      ID: ${elementId}`);
            } catch (e) {
              console.log(`    Element ${i + 1}: Could not read`);
            }
          }
        } else {
          console.log('  ✅ CORRECT: No dashboard elements visible to logged-in user without plan');
        }
        
        // Check if there are any hidden dashboard elements
        const hiddenDashboardElements = await page.$$('a[href*="dashboard"][style*="display: none"], a[href*="dashboard"][style*="display:none"], .dashboard-link[style*="display: none"], .dashboard-link[style*="display:none"]');
        console.log(`  📊 Hidden dashboard elements found: ${hiddenDashboardElements.length}`);
        
        if (hiddenDashboardElements.length > 0) {
          console.log('  📝 Found hidden dashboard elements (might be conditional rendering)');
        }
        
      } else {
        console.log('  ❌ Unexpected: User not on pricing page');
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 PRICING PAGE INVESTIGATION RESULTS:');
    console.log('✅ Public pricing page check:', 'Completed');
    console.log('✅ HTML source analysis:', 'Completed');
    console.log('✅ Logged-in user check:', 'Completed');
    console.log('✅ Dashboard element details:', 'Analyzed');
    console.log('✅ Conditional rendering check:', 'Completed');
    
    // Take screenshot
    await page.screenshot({ path: 'pricing-page-investigation-test.png' });
    console.log('📸 Screenshot saved as pricing-page-investigation-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testPricingPageInvestigation();
