// Auto-Popup System for RM
// This script automatically injects a subscription popup system for users without active subscriptions

(function() {
  'use strict';
  
  console.log('🔒 Auto-popup system loading...');
  
  // Wait for DOM to be ready
  function initAutoPopup() {
    console.log('🔒 Initializing auto-popup system...');
    
    // Check if popup already exists
    if (document.getElementById('subscription-required-popup')) {
      console.log('🔒 Popup already exists, skipping initialization');
      return;
    }
    
    // Create popup HTML
    const popupHTML = `
      <div id="subscription-required-popup" class="popup-overlay" style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        display: none;
        z-index: 10000;
        align-items: center;
        justify-content: center;
      ">
        <div class="popup-content" style="
          background: white;
          border-radius: 12px;
          padding: 32px;
          max-width: 500px;
          width: 90%;
          text-align: center;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        ">
          <div class="popup-icon" style="
            font-size: 48px;
            margin-bottom: 16px;
          ">🔒</div>
          
          <h2 class="popup-title" style="
            font-size: 24px;
            font-weight: 700;
            margin: 0 0 16px 0;
            color: #1f2937;
          ">Subscription Required</h2>
          
          <p class="popup-message" style="
            font-size: 16px;
            line-height: 1.6;
            color: #6b7280;
            margin: 0 0 24px 0;
          ">You need an active subscription to access the dashboard. Choose a plan to get started with managing your reviews and analytics.</p>
          
          <div class="popup-actions" style="
            display: flex;
            gap: 12px;
            justify-content: center;
            flex-wrap: wrap;
          ">
            <button id="popup-view-plans" class="popup-btn primary" style="
              background: #10b981;
              color: white;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              font-weight: 600;
              cursor: pointer;
              font-size: 16px;
            ">View Plans</button>
            
            <button id="popup-close" class="popup-btn secondary" style="
              background: #f3f4f6;
              color: #374151;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              font-weight: 600;
              cursor: pointer;
              font-size: 16px;
            ">Close</button>
          </div>
        </div>
      </div>
    `;
    
    // Add popup to page
    document.body.insertAdjacentHTML('beforeend', popupHTML);
    console.log('🔒 Popup HTML added to page');
    
    // Set up event listeners
    const popup = document.getElementById('subscription-required-popup');
    const viewPlansBtn = document.getElementById('popup-view-plans');
    const closeBtn = document.getElementById('popup-close');
    
    if (!popup || !viewPlansBtn || !closeBtn) {
      console.error('❌ Popup elements not found after injection');
      return;
    }
    
    // View plans button
    viewPlansBtn.addEventListener('click', () => {
      console.log('🔒 View plans button clicked');
      window.location.href = '/pricing';
    });
    
    // Close button
    closeBtn.addEventListener('click', () => {
      console.log('🔒 Close button clicked');
      popup.style.display = 'none';
    });
    
    // Close on overlay click
    popup.addEventListener('click', (e) => {
      if (e.target === popup) {
        console.log('🔒 Overlay clicked, closing popup');
        popup.style.display = 'none';
      }
    });
    
    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && popup.style.display === 'flex') {
        console.log('🔒 Escape key pressed, closing popup');
        popup.style.display = 'none';
      }
    });
    
    console.log('🔒 Popup event listeners set up');
    
    // Intercept dashboard button clicks
    function interceptDashboardClicks() {
      const dashboardElements = document.querySelectorAll('a[href="/dashboard"], .dashboard-btn, .dashboard-btn-mobile');
      
      console.log(`🔒 Found ${dashboardElements.length} dashboard elements to intercept`);
      
      dashboardElements.forEach((element, index) => {
        console.log(`🔒 Intercepting dashboard element ${index + 1}:`, element.tagName, element.textContent?.trim());
        
        // Remove existing event listeners by cloning the element
        const newElement = element.cloneNode(true);
        element.parentNode.replaceChild(newElement, element);
        
        // Add new click handler
        newElement.addEventListener('click', (e) => {
          e.preventDefault();
          e.stopPropagation();
          
          console.log('🔒 Dashboard access blocked - showing subscription popup');
          popup.style.display = 'flex';
          
          return false;
        });
        
        console.log(`🔒 Dashboard element ${index + 1} intercepted successfully`);
      });
      
      return dashboardElements.length;
    }
    
    // Initial interception
    const interceptedCount = interceptDashboardClicks();
    console.log(`🔒 Successfully intercepted ${interceptedCount} dashboard elements`);
    
    // Set up observer for new dashboard elements
    const observer = new MutationObserver((mutations) => {
      let newElementsFound = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check if the new element is a dashboard element
              if (node.matches && (node.matches('a[href="/dashboard"]') || 
                  node.matches('.dashboard-btn') || 
                  node.matches('.dashboard-btn-mobile'))) {
                newElementsFound = true;
              }
              
              // Check if the new element contains dashboard elements
              const dashboardElements = node.querySelectorAll ? 
                node.querySelectorAll('a[href="/dashboard"], .dashboard-btn, .dashboard-btn-mobile') : [];
              
              if (dashboardElements.length > 0) {
                newElementsFound = true;
              }
            }
          });
        }
      });
      
      // If new dashboard elements were found, intercept them
      if (newElementsFound) {
        console.log('🔒 New dashboard elements detected, intercepting...');
        setTimeout(() => {
          const newInterceptedCount = interceptDashboardClicks();
          if (newInterceptedCount > 0) {
            console.log(`🔒 Intercepted ${newInterceptedCount} new dashboard elements`);
          }
        }, 100);
      }
    });
    
    // Start observing
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
    
    console.log('🔒 MutationObserver set up for dynamic dashboard elements');
    console.log('🔒 Auto-popup system fully initialized!');
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAutoPopup);
  } else {
    initAutoPopup();
  }
  
  // Also try to initialize after a short delay to catch any late-loading elements
  setTimeout(initAutoPopup, 1000);
  
})();
