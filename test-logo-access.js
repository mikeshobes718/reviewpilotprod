const puppeteer = require('puppeteer');

async function testLogoAccess() {
  console.log('🧪 Testing Logo Access...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test 1: Try to access logo directly
    console.log('\n🧪 Test 1: Testing direct logo access...');
    try {
      await page.goto('https://reviewsandmarketing.com/logo.svg', { waitUntil: 'networkidle2' });
      const logoContent = await page.content();
      
      if (logoContent.includes('<svg') && logoContent.includes('RM')) {
        console.log('✅ Logo file accessible directly');
      } else {
        console.log('❌ Logo file not accessible or wrong content');
      }
    } catch (error) {
      console.log('❌ Could not access logo directly:', error.message);
    }
    
    // Test 2: Check network requests for logo
    console.log('\n🧪 Test 2: Checking network requests...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get all network requests
    const requests = await page.evaluate(() => {
      return performance.getEntriesByType('resource')
        .filter(r => r.name.includes('logo') || r.name.includes('svg'))
        .map(r => r.name);
    });
    
    console.log('🔍 Logo-related network requests:', requests);
    
    // Test 3: Check if logo element exists in DOM
    console.log('\n🧪 Test 3: Checking DOM for logo elements...');
    
    const allImages = await page.$$eval('img', imgs => 
      imgs.map(img => ({ src: img.src, alt: img.alt }))
    );
    
    console.log('📸 All images on page:', allImages);
    
    // Test 4: Check for any logo-related elements
    console.log('\n🧪 Test 4: Checking for logo-related elements...');
    
    const logoElements = await page.$$eval('*', elements => {
      return elements
        .filter(el => el.textContent && el.textContent.includes('RM'))
        .map(el => ({ tag: el.tagName, text: el.textContent.trim().substring(0, 50) }));
    });
    
    console.log('🔍 RM text elements found:', logoElements);
    
    // Test 5: Check page source for logo references
    console.log('\n🧪 Test 5: Checking page source...');
    
    const pageSource = await page.content();
    const logoReferences = pageSource.match(/logo\.svg|main-logo\.png|Landscape-Photoroom/g);
    
    console.log('🔍 Logo references in source:', logoReferences);
    
    console.log('\n📋 LOGO ACCESS TEST RESULTS:');
    console.log('✅ Direct logo access:', 'Tested');
    console.log('✅ Network requests:', 'Checked');
    console.log('✅ DOM elements:', 'Analyzed');
    console.log('✅ Page source:', 'Scanned');
    
    // Take screenshot
    await page.screenshot({ path: 'logo-access-test.png' });
    console.log('📸 Screenshot saved as logo-access-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testLogoAccess();
