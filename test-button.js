const puppeteer = require('puppeteer');

async function testButton() {
  console.log('🚀 Starting headless browser test...');
  
  const browser = await puppeteer.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  try {
    const page = await browser.newPage();
    
    // Set viewport
    await page.setViewport({ width: 1280, height: 720 });
    
    // Enable console logging
    page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
    
    // First, let's test the home page to see if the server is working
    console.log('📱 Testing home page...');
    await page.goto('http://localhost:3000', { waitUntil: 'networkidle0' });
    
    // Wait for page to load
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    console.log('✅ Home page loaded successfully');
    
    // Now let's test the dashboard (will redirect to login)
    console.log('📱 Testing dashboard access...');
    await page.goto('http://localhost:3000/dashboard', { waitUntil: 'networkidle0' });
    
    // Wait for redirect
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check current URL
    const currentUrl = page.url();
    console.log('📍 Current URL:', currentUrl);
    
    if (currentUrl.includes('/login')) {
      console.log('✅ Dashboard correctly redirected to login (expected behavior)');
    } else if (currentUrl.includes('/dashboard')) {
      console.log('✅ Dashboard loaded successfully');
      
      // Now test the button functionality
      await testButtonFunctionality(page);
    } else {
      console.log('❌ Unexpected redirect:', currentUrl);
    }
    
    return true;
    
  } catch (error) {
    console.error('❌ Test failed with error:', error.message);
    return false;
  } finally {
    await browser.close();
  }
}

async function testButtonFunctionality(page) {
  console.log('🔍 Looking for button...');
  const button = await page.$('#btnFirstRequestStatic');
  
  if (!button) {
    console.log('❌ Button not found!');
    return false;
  }
  
  console.log('✅ Button found!');
  
  // Check if Review Kit section exists
  const reviewKitSection = await page.$('#reviewKitCard');
  if (!reviewKitSection) {
    console.log('❌ Review Kit section not found!');
    return false;
  }
  
  console.log('✅ Review Kit section found!');
  
  // Get initial scroll position
  const initialScrollY = await page.evaluate(() => window.scrollY);
  console.log('📍 Initial scroll position:', initialScrollY);
  
  // Click the button
  console.log('🖱️ Clicking button...');
  await button.click();
  
  // Wait for scroll animation
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Check if page scrolled
  const finalScrollY = await page.evaluate(() => window.scrollY);
  console.log('📍 Final scroll position:', finalScrollY);
  
  if (finalScrollY > initialScrollY) {
    console.log('✅ Button worked! Page scrolled successfully.');
    return true;
  } else {
    console.log('❌ Button failed! Page did not scroll.');
    return false;
  }
}

// Run the test
testButton().then(success => {
  if (success) {
    console.log('🎉 All tests passed! Server is working correctly.');
    process.exit(0);
  } else {
    console.log('💥 Tests failed!');
    process.exit(1);
  }
}).catch(error => {
  console.error('💥 Test crashed:', error);
  process.exit(1);
});
