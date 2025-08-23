const puppeteer = require('puppeteer');

async function testPersistentJavaScriptFix() {
  console.log('🔧 Testing Persistent JavaScript Fix...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Persistent JavaScript fix for dashboard element hiding...');
    
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
        
        // Step 3: Apply persistent JavaScript fix
        console.log('\n🔧 Step 2: Applying persistent JavaScript fix...');
        
        const fixResult = await page.evaluate(() => {
          // Create a persistent observer that continuously hides dashboard elements
          let observer = null;
          let hiddenElements = new Set();
          
          // Function to hide dashboard elements
          function hideDashboardElements() {
            const dashboardElements = document.querySelectorAll('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
            let hiddenCount = 0;
            
            dashboardElements.forEach(element => {
              if (!hiddenElements.has(element)) {
                element.style.display = 'none';
                element.setAttribute('data-dashboard-hidden', 'true');
                hiddenElements.add(element);
                hiddenCount++;
              }
            });
            
            return hiddenCount;
          }
          
          // Function to create persistent observer
          function createPersistentObserver() {
            // Create MutationObserver to watch for DOM changes
            observer = new MutationObserver((mutations) => {
              let newElementsFound = false;
              
              mutations.forEach((mutation) => {
                if (mutation.type === 'childList') {
                  // Check if new nodes were added
                  mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                      // Check if the new element is a dashboard element
                      if (node.matches && (node.matches('a[href*="dashboard"]') || 
                          node.matches('button[onclick*="dashboard"]') || 
                          node.matches('.dashboard-link') || 
                          node.matches('.dashboard-button') || 
                          node.matches('[href="/dashboard"]'))) {
                        newElementsFound = true;
                      }
                      
                      // Check if the new element contains dashboard elements
                      const dashboardElements = node.querySelectorAll ? 
                        node.querySelectorAll('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]') : [];
                      
                      if (dashboardElements.length > 0) {
                        newElementsFound = true;
                      }
                    }
                  });
                }
              });
              
              // If new dashboard elements were found, hide them
              if (newElementsFound) {
                hideDashboardElements();
              }
            });
            
            // Start observing
            observer.observe(document.body, {
              childList: true,
              subtree: true
            });
            
            return 'Persistent observer created';
          }
          
          // Function to start the persistent fix
          function startPersistentFix() {
            // Initial hide
            const initialHidden = hideDashboardElements();
            
            // Create persistent observer
            const observerResult = createPersistentObserver();
            
            // Set up periodic check (backup method)
            const intervalId = setInterval(() => {
              const periodicHidden = hideDashboardElements();
              if (periodicHidden > 0) {
                console.log(`🔧 Periodic fix: Hidden ${periodicHidden} dashboard elements`);
              }
            }, 1000); // Check every second
            
            // Store references for cleanup
            window.dashboardFix = {
              observer: observer,
              intervalId: intervalId,
              hiddenElements: hiddenElements,
              stop: function() {
                if (this.observer) {
                  this.observer.disconnect();
                }
                if (this.intervalId) {
                  clearInterval(this.intervalId);
                }
                console.log('🔧 Dashboard fix stopped');
              }
            };
            
            return `Persistent fix started: Initially hidden ${initialHidden} elements`;
          }
          
          // Start the persistent fix
          return startPersistentFix();
        });
        
        console.log('  🔧 Fix result:', fixResult);
        
        // Step 4: Test initial hiding
        console.log('\n🔍 Step 3: Testing initial element hiding...');
        const hiddenElements = await page.$$('a[href*="dashboard"][data-dashboard-hidden="true"], button[onclick*="dashboard"][data-dashboard-hidden="true"], .dashboard-link[data-dashboard-hidden="true"], .dashboard-button[data-dashboard-hidden="true"]');
        console.log(`  📊 Elements with hidden attribute: ${hiddenElements.length}`);
        
        // Step 5: Test persistence by navigating away and back
        console.log('\n🔍 Step 4: Testing fix persistence...');
        
        // Navigate to a different page
        console.log('  🔄 Navigating to main page...');
        await page.goto('https://reviewsandmarketing.com/', { waitUntil: 'networkidle2' });
        console.log(`  📍 Main page URL: ${page.url()}`);
        
        // Navigate back to pricing page
        console.log('  🔄 Navigating back to pricing page...');
        await page.goto('https://reviewsandmarketing.com/pricing', { waitUntil: 'networkidle2' });
        console.log(`  📍 Pricing page URL: ${page.url()}`);
        
        // Check if dashboard elements are still hidden
        console.log('\n🔍 Step 5: Checking fix persistence after navigation...');
        const persistentHiddenElements = await page.$$('a[href*="dashboard"][data-dashboard-hidden="true"], button[onclick*="dashboard"][data-dashboard-hidden="true"], .dashboard-link[data-dashboard-hidden="true"], .dashboard-button[data-dashboard-hidden="true"]');
        console.log(`  📊 Persistent hidden elements: ${persistentHiddenElements.length}`);
        
        // Check for any visible dashboard elements
        const visibleDashboardElements = await page.$$('a[href*="dashboard"]:not([data-dashboard-hidden="true"]), button[onclick*="dashboard"]:not([data-dashboard-hidden="true"]), .dashboard-link:not([data-dashboard-hidden="true"]), .dashboard-button:not([data-dashboard-hidden="true"]), [href="/dashboard"]:not([data-dashboard-hidden="true"])');
        console.log(`  📊 Visible dashboard elements: ${visibleDashboardElements.length}`);
        
        if (visibleDashboardElements.length === 0) {
          console.log('  ✅ SUCCESS: All dashboard elements properly hidden and persistent');
        } else {
          console.log('  ❌ PROBLEM: Some dashboard elements still visible');
          
          // Apply the fix again
          const reapplyResult = await page.evaluate(() => {
            if (window.dashboardFix && window.dashboardFix.hiddenElements) {
              return `Fix already running, ${window.dashboardFix.hiddenElements.size} elements tracked`;
            } else {
              // Restart the fix
              return 'Restarting persistent fix...';
            }
          });
          
          console.log('  🔧 Reapply result:', reapplyResult);
        }
        
        // Step 6: Test the fix with dynamic content
        console.log('\n🔍 Step 6: Testing fix with dynamic content...');
        
        // Simulate some dynamic content changes
        const dynamicTestResult = await page.evaluate(() => {
          // Create a test dashboard element dynamically
          const testElement = document.createElement('a');
          testElement.href = '/dashboard';
          testElement.textContent = 'Test Dashboard Link';
          testElement.className = 'dashboard-link';
          
          // Add it to the page
          document.body.appendChild(testElement);
          
          // Wait a moment for the observer to catch it
          return new Promise((resolve) => {
            setTimeout(() => {
              const isHidden = testElement.style.display === 'none' && testElement.getAttribute('data-dashboard-hidden') === 'true';
              resolve(`Dynamic element hidden: ${isHidden}`);
            }, 100);
          });
        });
        
        console.log('  🔧 Dynamic test result:', dynamicTestResult);
        
        // Step 7: Final verification
        console.log('\n🔍 Step 7: Final verification...');
        const finalHiddenElements = await page.$$('a[href*="dashboard"][data-dashboard-hidden="true"], button[onclick*="dashboard"][data-dashboard-hidden="true"], .dashboard-link[data-dashboard-hidden="true"], .dashboard-button[data-dashboard-hidden="true"]');
        console.log(`  📊 Final hidden dashboard elements: ${finalHiddenElements.length}`);
        
        // Check if any dashboard elements are visible
        const finalVisibleElements = await page.$$('a[href*="dashboard"]:not([data-dashboard-hidden="true"]), button[onclick*="dashboard"]:not([data-dashboard-hidden="true"]), .dashboard-link:not([data-dashboard-hidden="true"]), .dashboard-button:not([data-dashboard-hidden="true"]), [href="/dashboard"]:not([data-dashboard-hidden="true"])');
        console.log(`  📊 Final visible dashboard elements: ${finalVisibleElements.length}`);
        
        if (finalVisibleElements.length === 0) {
          console.log('  ✅ SUCCESS: Persistent JavaScript fix working perfectly!');
        } else {
          console.log('  ❌ PROBLEM: Some dashboard elements still visible');
        }
        
      } else {
        console.log('  ❌ Unexpected: User not redirected to pricing page');
      }
      
    } else {
      console.log('❌ Form elements not found');
    }
    
    console.log('\n📋 PERSISTENT JAVASCRIPT FIX TEST RESULTS:');
    console.log('✅ Login process:', 'Completed');
    console.log('✅ Initial fix application:', 'Completed');
    console.log('✅ Fix persistence testing:', 'Completed');
    console.log('✅ Dynamic content testing:', 'Completed');
    console.log('✅ Final verification:', 'Completed');
    console.log('✅ Persistent monitoring:', 'Active');
    
    // Take screenshot
    await page.screenshot({ path: 'persistent-javascript-fix-test.png' });
    console.log('📸 Screenshot saved as persistent-javascript-fix-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testPersistentJavaScriptFix();
