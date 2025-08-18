const puppeteer = require('puppeteer');

async function testDashboardAccess() {
  console.log('🚀 Testing dashboard access without authentication...');
  
  const browser = await puppeteer.launch({ 
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });
  
  try {
    const page = await browser.newPage();
    
    // Enable console logging
    page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
    
    // Go to dashboard
    console.log('📱 Going to dashboard...');
    const response = await page.goto('http://localhost:3000/dashboard', { 
      waitUntil: 'networkidle0',
      timeout: 10000
    });
    
    if (response) {
      console.log('📊 Response status:', response.status());
      console.log('📊 Response URL:', response.url());
      
      // Get the HTML content
      const html = await page.content();
      
      // Check for key elements
      const hasButton = html.includes('btnFirstRequestStatic');
      const hasFunction = html.includes('scrollToReviewKit');
      const hasReviewKit = html.includes('reviewKitCard');
      const hasFeedback = html.includes('feedback');
      const hasTable = html.includes('table');
      
      console.log('🔍 HTML Analysis:');
      console.log('  - Button ID found:', hasButton);
      console.log('  - Function found:', hasFunction);
      console.log('  - Review Kit section found:', hasReviewKit);
      console.log('  - Feedback variable found:', hasFeedback);
      console.log('  - Table found:', hasTable);
      
      // Look for specific patterns
      const hasConditionalBlock = html.includes('if (feedback.length > 0)');
      const hasEmptyState = html.includes('Your customer feedback will appear here');
      
      console.log('🔍 Template Logic:');
      console.log('  - Conditional block found:', hasConditionalBlock);
      console.log('  - Empty state text found:', hasEmptyState);
      
      // Check if this is the login page or dashboard
      if (response.url().includes('/login')) {
        console.log('📍 This is the login page (redirected)');
      } else if (response.url().includes('/dashboard')) {
        console.log('📍 This is the dashboard page');
      } else {
        console.log('📍 Unexpected page:', response.url());
      }
      
      // Save HTML to file for inspection
      const fs = require('fs');
      fs.writeFileSync('dashboard-response.html', html);
      console.log('💾 HTML saved to dashboard-response.html');
      
      return hasButton && hasFunction && hasReviewKit;
    } else {
      console.log('❌ No response from dashboard');
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
testDashboardAccess().then(success => {
  if (success) {
    console.log('🎉 Dashboard access test passed! All required elements found.');
    process.exit(0);
  } else {
    console.log('💥 Dashboard access test failed! Missing required elements.');
    process.exit(1);
  }
}).catch(error => {
  console.error('💥 Test crashed:', error);
  process.exit(1);
});
