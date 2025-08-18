const puppeteer = require('puppeteer');

async function testHtmlStructure() {
  console.log('🚀 Testing dashboard HTML structure...');
  
  const browser = await puppeteer.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  try {
    const page = await browser.newPage();
    
    // Enable console logging
    page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
    
    // Go to dashboard (will redirect to login, but we can check the HTML)
    console.log('📱 Going to dashboard...');
    await page.goto('http://localhost:3000/dashboard', { waitUntil: 'networkidle0' });
    
    // Wait for redirect
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check current URL
    const currentUrl = page.url();
    console.log('📍 Current URL:', currentUrl);
    
    if (currentUrl.includes('/login')) {
      console.log('✅ Dashboard correctly redirected to login (expected)');
      
      // Let's check if we can get the dashboard HTML by looking at the source
      console.log('📱 Checking dashboard HTML source...');
      
      // Try to access dashboard directly and see what HTML we get
      const response = await page.goto('http://localhost:3000/dashboard', { 
        waitUntil: 'networkidle0',
        timeout: 10000
      });
      
      if (response) {
        console.log('📊 Response status:', response.status());
        console.log('📊 Response headers:', response.headers());
        
        // Get the HTML content
        const html = await page.content();
        
        // Check for key elements
        const hasButton = html.includes('btnFirstRequestStatic');
        const hasFunction = html.includes('scrollToReviewKit');
        const hasReviewKit = html.includes('reviewKitCard');
        
        console.log('🔍 HTML Analysis:');
        console.log('  - Button ID found:', hasButton);
        console.log('  - Function found:', hasFunction);
        console.log('  - Review Kit section found:', hasReviewKit);
        
        if (hasButton && hasFunction && hasReviewKit) {
          console.log('✅ All required HTML elements found!');
          return true;
        } else {
          console.log('❌ Missing required HTML elements');
          return false;
        }
      } else {
        console.log('❌ No response from dashboard');
        return false;
      }
    } else {
      console.log('❌ Unexpected redirect:', currentUrl);
      return false;
    }
    
  } catch (error) {
    console.error('❌ Test failed with error:', error.message);
    return false;
  } finally {
    await browser.close();
  }
}

// Run the test
testHtmlStructure().then(success => {
  if (success) {
    console.log('🎉 HTML structure test passed! Dashboard has all required elements.');
    process.exit(0);
  } else {
    console.log('💥 HTML structure test failed! Dashboard is missing required elements.');
    process.exit(1);
  }
}).catch(error => {
  console.error('💥 Test crashed:', error);
  process.exit(1);
});
