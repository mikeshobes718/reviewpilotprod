const puppeteer = require('puppeteer');

async function testHtmlStructure() {
  console.log('🧪 Testing HTML Structure...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    // Test 1: Check login page structure
    console.log('\n🧪 Test 1: Checking login page structure...');
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get all div elements to see the structure
    const divElements = await page.$$eval('div', divs => 
      divs.map(div => ({
        className: div.className,
        id: div.id,
        textContent: div.textContent.trim().substring(0, 100)
      }))
    );
    
    console.log('🔍 Div elements found:', divElements.length);
    divElements.forEach((div, i) => {
      if (div.className || div.id) {
        console.log(`  Div ${i + 1}:`, { className: div.className, id: div.id, text: div.textContent });
      }
    });
    
    // Test 2: Check for any elements with "brand" in class or id
    console.log('\n🧪 Test 2: Checking for brand-related elements...');
    
    const brandElements = await page.$$eval('*', elements => {
      return elements
        .filter(el => (el.className && el.className.includes('brand')) || 
                     (el.id && el.id.includes('brand')) ||
                     (el.textContent && el.textContent.includes('RM')))
        .map(el => ({
          tag: el.tagName,
          className: el.className,
          id: el.id,
          text: el.textContent.trim().substring(0, 50)
        }));
    });
    
    console.log('🔍 Brand-related elements:', brandElements);
    
    // Test 3: Check the entire page structure
    console.log('\n🧪 Test 3: Checking page structure...');
    
    const pageStructure = await page.$$eval('body', body => {
      function getElementInfo(el, depth = 0) {
        const indent = '  '.repeat(depth);
        let info = `${indent}${el.tagName}`;
        
        if (el.className) info += `.${el.className.split(' ').join('.')}`;
        if (el.id) info += `#${el.id}`;
        if (el.textContent && el.textContent.trim()) {
          const text = el.textContent.trim().substring(0, 30);
          if (text) info += ` (${text})`;
        }
        
        return info;
      }
      
      function traverse(el, depth = 0) {
        const result = [getElementInfo(el, depth)];
        for (const child of el.children) {
          result.push(...traverse(child, depth + 1));
        }
        return result;
      }
      
      return traverse(body);
    });
    
    console.log('🌳 Page structure:');
    pageStructure.forEach(line => console.log(line));
    
    // Test 4: Check for any images or logos
    console.log('\n🧪 Test 4: Checking for images and logos...');
    
    const allImages = await page.$$eval('img', imgs => 
      imgs.map(img => ({
        src: img.src,
        alt: img.alt,
        className: img.className,
        id: img.id
      }))
    );
    
    console.log('📸 All images:', allImages);
    
    // Test 5: Check page title and meta
    console.log('\n🧪 Test 5: Checking page metadata...');
    
    const title = await page.title();
    const metaDescription = await page.$eval('meta[name="description"]', el => el?.content).catch(() => 'Not found');
    
    console.log('📄 Page title:', title);
    console.log('📝 Meta description:', metaDescription);
    
    console.log('\n📋 HTML STRUCTURE TEST RESULTS:');
    console.log('✅ Page structure:', 'Analyzed');
    console.log('✅ Brand elements:', brandElements.length > 0 ? 'Found' : 'None');
    console.log('✅ Images:', allImages.length > 0 ? 'Found' : 'None');
    console.log('✅ Page metadata:', 'Checked');
    
    // Take screenshot
    await page.screenshot({ path: 'html-structure-test.png' });
    console.log('📸 Screenshot saved as html-structure-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testHtmlStructure();
