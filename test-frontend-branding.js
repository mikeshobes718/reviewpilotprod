const puppeteer = require('puppeteer');

async function testFrontendBranding() {
  console.log('🧪 Testing Frontend Branding...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test 1: Check homepage branding
    console.log('\n🧪 Test 1: Checking homepage branding...');
    await page.goto('https://reviewsandmarketing.com', { waitUntil: 'networkidle2' });
    
    const title = await page.title();
    console.log('📄 Homepage title:', title);
    
    // Check if RM logo is displayed
    const logoElement = await page.$('img[src="/logo.svg"]');
    if (logoElement) {
      console.log('✅ RM logo found on homepage');
    } else {
      console.log('❌ RM logo not found on homepage');
    }
    
    // Test 2: Check login page branding
    console.log('\n🧪 Test 2: Checking login page branding...');
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    const loginTitle = await page.title();
    console.log('📄 Login page title:', loginTitle);
    
    // Check if RM logo is displayed
    const loginLogo = await page.$('img[src="/logo.svg"]');
    if (loginLogo) {
      console.log('✅ RM logo found on login page');
    } else {
      console.log('❌ RM logo not found on login page');
    }
    
    // Test 3: Check signup page branding
    console.log('\n🧪 Test 3: Checking signup page branding...');
    await page.goto('https://reviewsandmarketing.com/signup', { waitUntil: 'networkidle2' });
    
    const signupTitle = await page.title();
    console.log('📄 Signup page title:', signupTitle);
    
    // Check if RM logo is displayed
    const signupLogo = await page.$('img[src="/logo.svg"]');
    if (signupLogo) {
      console.log('✅ RM logo found on signup page');
    } else {
      console.log('❌ RM logo not found on signup page');
    }
    
    // Test 4: Check if old marketing images are gone
    console.log('\n🧪 Test 4: Checking if old marketing images are removed...');
    
    const oldLogo = await page.$('img[src*="Landscape-Photoroom"]');
    if (!oldLogo) {
      console.log('✅ Old marketing images removed');
    } else {
      console.log('❌ Old marketing images still present');
    }
    
    // Test 5: Check page titles for RM branding
    console.log('\n🧪 Test 5: Checking page titles for RM branding...');
    
    const allTitles = [title, loginTitle, signupTitle];
    const rmBrandingCount = allTitles.filter(t => t.includes('RM')).length;
    
    console.log('📊 Pages with RM branding:', rmBrandingCount, 'out of', allTitles.length);
    
    if (rmBrandingCount === allTitles.length) {
      console.log('✅ All pages have RM branding');
    } else {
      console.log('⚠️ Some pages missing RM branding');
    }
    
    console.log('\n📋 FRONTEND BRANDING TEST RESULTS:');
    console.log('✅ RM logo on homepage:', logoElement ? 'Working' : 'Issue');
    console.log('✅ RM logo on login:', loginLogo ? 'Working' : 'Issue');
    console.log('✅ RM logo on signup:', signupLogo ? 'Working' : 'Issue');
    console.log('✅ Old marketing images removed:', !oldLogo ? 'Working' : 'Issue');
    console.log('✅ RM branding in titles:', rmBrandingCount === allTitles.length ? 'Working' : 'Issue');
    
    // Take screenshot
    await page.screenshot({ path: 'frontend-branding-test.png' });
    console.log('📸 Screenshot saved as frontend-branding-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testFrontendBranding();
