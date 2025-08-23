const puppeteer = require('puppeteer');

async function testFormHtmlInspection() {
  console.log('🧪 Testing Form HTML Inspection...');
  
  const browser = await puppeteer.launch({ 
    headless: true, 
    args: ['--no-sandbox', '--disable-setuid-sandbox'] 
  });
  
  try {
    const page = await browser.newPage();
    
    console.log('\n🧪 Test: Inspecting login form HTML...');
    
    await page.goto('https://reviewsandmarketing.com/login', { waitUntil: 'networkidle2' });
    
    // Get form details
    const form = await page.$('form');
    if (form) {
      const formAction = await form.evaluate(el => el.action);
      const formMethod = await form.evaluate(el => el.method);
      const formId = await form.evaluate(el => el.id);
      const formClass = await form.evaluate(el => el.className);
      
      console.log('\n📝 Form Details:');
      console.log('  Action:', formAction);
      console.log('  Method:', formMethod);
      console.log('  ID:', formId);
      console.log('  Class:', formClass);
      
      // Check for JavaScript event handlers
      const formEvents = await form.evaluate(el => {
        const events = [];
        for (const key in el) {
          if (key.startsWith('on')) {
            events.push(key);
          }
        }
        return events;
      });
      
      if (formEvents.length > 0) {
        console.log('  Event Handlers:', formEvents);
      } else {
        console.log('  Event Handlers: None');
      }
      
      // Check for any JavaScript that might prevent submission
      const formScripts = await page.$$eval('script', scripts => 
        scripts.map(script => script.textContent || script.src).filter(content => content)
      );
      
      console.log('\n📜 Scripts found:', formScripts.length);
      formScripts.forEach((script, i) => {
        if (typeof script === 'string' && script.length > 0) {
          console.log(`  Script ${i + 1}:`, script.substring(0, 200) + '...');
        } else {
          console.log(`  Script ${i + 1}:`, script);
        }
      });
      
    } else {
      console.log('❌ No form found');
    }
    
    // Check form fields
    console.log('\n🔍 Form Fields:');
    
    const emailInput = await page.$('input[name="email"]');
    const passwordInput = await page.$('input[name="password"]');
    const submitButton = await page.$('button[type="submit"]');
    
    if (emailInput) {
      const emailType = await emailInput.evaluate(el => el.type);
      const emailRequired = await emailInput.evaluate(el => el.required);
      const emailDisabled = await emailInput.evaluate(el => el.disabled);
      
      console.log('  Email Input:');
      console.log('    Type:', emailType);
      console.log('    Required:', emailRequired);
      console.log('    Disabled:', emailDisabled);
    }
    
    if (passwordInput) {
      const passwordType = await passwordInput.evaluate(el => el.type);
      const passwordRequired = await passwordInput.evaluate(el => el.required);
      const passwordDisabled = await passwordInput.evaluate(el => el.disabled);
      
      console.log('  Password Input:');
      console.log('    Type:', passwordType);
      console.log('    Required:', passwordRequired);
      console.log('    Disabled:', passwordDisabled);
    }
    
    if (submitButton) {
      const buttonType = await submitButton.evaluate(el => el.type);
      const buttonDisabled = await submitButton.evaluate(el => el.disabled);
      const buttonText = await submitButton.evaluate(el => el.textContent);
      
      console.log('  Submit Button:');
      console.log('    Type:', buttonType);
      console.log('    Disabled:', buttonDisabled);
      console.log('    Text:', buttonText.trim());
    }
    
    // Check for any validation or submission blocking
    console.log('\n🔍 Form Validation:');
    
    const formValidation = await page.evaluate(() => {
      const form = document.querySelector('form');
      if (!form) return 'No form found';
      
      // Check if form has novalidate
      const novalidate = form.hasAttribute('novalidate');
      
      // Check for any form validation libraries
      const validationLibraries = [];
      if (window.jQuery) validationLibraries.push('jQuery');
      if (window.validator) validationLibraries.push('validator');
      if (window.validate) validationLibraries.push('validate');
      
      return {
        novalidate,
        validationLibraries,
        formHTML: form.outerHTML.substring(0, 500) + '...'
      };
    });
    
    console.log('  Form Validation Details:', formValidation);
    
    console.log('\n📋 FORM HTML INSPECTION RESULTS:');
    console.log('✅ Form structure:', 'Analyzed');
    console.log('✅ Form fields:', 'Inspected');
    console.log('✅ Scripts:', 'Found');
    console.log('✅ Validation:', 'Checked');
    
    // Take screenshot
    await page.screenshot({ path: 'form-html-inspection-test.png' });
    console.log('📸 Screenshot saved as form-html-inspection-test.png');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await browser.close();
  }
}

testFormHtmlInspection();

