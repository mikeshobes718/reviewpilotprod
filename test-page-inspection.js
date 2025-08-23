const puppeteer = require('puppeteer');

async function testPageInspection() {
  console.log('🧪 Testing Page Inspection...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test 1: Check login page content
    console.log('\n🧪 Test 1: Checking login page content...');
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get the brand div content
    const brandContent = await page.$eval('.brand', el => el.innerHTML);
    console.log('🔍 Brand div content:', brandContent);
    
    // Check if there are any img tags
    const imgTags = await page.$$eval('img', imgs => 
      imgs.map(img => ({ src: img.src, alt: img.alt, outerHTML: img.outerHTML }))
    );
    console.log('📸 Image tags found:', imgTags.length);
    
    if (imgTags.length > 0) {
      imgTags.forEach((img, i) => {
        console.log(`  Image ${i + 1}:`, img);
      });
    }
    
    // Test 2: Check page source for img tags
    console.log('\n🧪 Test 2: Checking page source for img tags...');
    
    const pageSource = await page.content();
    const imgMatches = pageSource.match(/<img[^>]*>/g);
    
    if (imgMatches) {
      console.log('🔍 IMG tags in source:', imgMatches.length);
      imgMatches.forEach((img, i) => {
        console.log(`  IMG ${i + 1}:`, img);
      });
    } else {
      console.log('❌ No IMG tags found in source');
    }
    
    // Test 3: Check if logo is being rendered as text
    console.log('\n🧪 Test 3: Checking for text-based logo...');
    
    const brandText = await page.$eval('.brand', el => el.textContent);
    console.log('🔍 Brand text content:', brandText);
    
    // Test 4: Check CSS for logo display
    console.log('\n🧪 Test 4: Checking CSS for logo...');
    
    const brandStyles = await page.$eval('.brand', el => {
      const styles = window.getComputedStyle(el);
      return {
        display: styles.display,
        visibility: styles.visibility,
        opacity: styles.opacity,
        fontSize: styles.fontSize,
        fontWeight: styles.fontWeight
      };
    });
    
    console.log('🎨 Brand styles:', brandStyles);
    
    // Test 5: Check if there are any errors in console
    console.log('\n🧪 Test 5: Checking console for errors...');
    
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });
    
    // Reload page to capture console errors
    await page.reload({ waitUntil: 'networkidle2' });
    
    if (consoleErrors.length > 0) {
      console.log('⚠️ Console errors found:', consoleErrors);
    } else {
      console.log('✅ No console errors found');
    }
    
    console.log('\n📋 PAGE INSPECTION RESULTS:');
    console.log('✅ Brand content:', 'Analyzed');
    console.log('✅ Image tags:', imgTags.length > 0 ? 'Found' : 'None');
    console.log('✅ Page source:', 'Scanned');
    console.log('✅ Brand styles:', 'Checked');
    console.log('✅ Console errors:', consoleErrors.length > 0 ? 'Found' : 'None');
    
    // Take screenshot
    await page.screenshot({ path: 'page-inspection-test.png' });
    console.log('📸 Screenshot saved as page-inspection-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testPageInspection();
