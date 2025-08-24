/**
 * Subscription Required Popup System
 * Automatically detects users without active subscriptions and shows popup when they click dashboard elements
 */

(function() {
  'use strict';
  
  // Wait for DOM to be ready
  function initSubscriptionPopup() {
    console.log('🔒 Initializing subscription popup system...');
    
    // Create popup HTML
    createPopupHTML();
    
    // Set up event listeners
    setupEventListeners();
    
    // Intercept dashboard clicks
    interceptDashboardClicks();
    
    // Set up observer for new dashboard elements
    setupMutationObserver();
    
    console.log('🔒 Subscription popup system initialized');
  }
  
  // Function to create popup HTML
  function createPopupHTML() {
    // Check if popup already exists
    if (document.getElementById('subscription-required-popup')) {
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
      
      <!-- Mobile Subscription Required Popup Modal -->
      <div id="mobile-subscription-required-popup" class="mobile-popup-overlay" style="
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
        <div class="mobile-popup-content" style="
          background: white;
          border-radius: 12px;
          padding: 24px;
          max-width: 90%;
          width: 90%;
          text-align: center;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
          margin: 20px;
        ">
          <div class="mobile-popup-icon" style="
            font-size: 36px;
            margin-bottom: 12px;
          ">🔒</div>
          
          <h2 class="mobile-popup-title" style="
            font-size: 20px;
            font-weight: 700;
            margin: 0 0 12px 0;
            color: #1f2937;
          ">Subscription Required</h2>
          
          <p class="mobile-popup-message" style="
            font-size: 14px;
            line-height: 1.5;
            color: #6b7280;
            margin: 0 0 20px 0;
          ">You need an active subscription to access the dashboard. Choose a plan to get started.</p>
          
          <div class="mobile-popup-actions" style="
            display: flex;
            flex-direction: column;
            gap: 8px;
            align-items: center;
          ">
            <button id="mobile-popup-view-plans" class="mobile-popup-btn primary" style="
              background: #10b981;
              color: white;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              font-weight: 600;
              cursor: pointer;
              font-size: 16px;
              width: 100%;
              max-width: 200px;
            ">View Plans</button>
            
            <button id="mobile-popup-close" class="mobile-popup-btn secondary" style="
              background: #f3f4f6;
              color: #374151;
              border: none;
              padding: 12px 24px;
              border-radius: 8px;
              font-weight: 600;
              cursor: pointer;
              font-size: 16px;
              width: 100%;
              max-width: 200px;
            ">Close</button>
          </div>
        </div>
      </div>
    `;
    
    // Add popup to page
    document.body.insertAdjacentHTML('beforeend', popupHTML);
  }
  
  // Function to set up event listeners
  function setupEventListeners() {
    const popup = document.getElementById('subscription-required-popup');
    const mobilePopup = document.getElementById('mobile-subscription-required-popup');
    
    if (!popup || !mobilePopup) return;
    
    // Desktop popup event listeners
    const viewPlansBtn = document.getElementById('popup-view-plans');
    const closeBtn = document.getElementById('popup-close');
    
    if (viewPlansBtn) {
      viewPlansBtn.addEventListener('click', () => {
        window.location.href = '/pricing';
      });
    }
    
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        popup.style.display = 'none';
      });
    }
    
    // Close on overlay click
    popup.addEventListener('click', (e) => {
      if (e.target === popup) {
        popup.style.display = 'none';
      }
    });
    
    // Mobile popup event listeners
    const mobileViewPlansBtn = document.getElementById('mobile-popup-view-plans');
    const mobileCloseBtn = document.getElementById('mobile-popup-close');
    
    if (mobileViewPlansBtn) {
      mobileViewPlansBtn.addEventListener('click', () => {
        window.location.href = '/pricing';
      });
    }
    
    if (mobileCloseBtn) {
      mobileCloseBtn.addEventListener('click', () => {
        mobilePopup.style.display = 'none';
      });
    }
    
    // Close on overlay click
    mobilePopup.addEventListener('click', (e) => {
      if (e.target === mobilePopup) {
        mobilePopup.style.display = 'none';
      }
    });
    
    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        if (popup.style.display === 'flex') {
          popup.style.display = 'none';
        }
        if (mobilePopup.style.display === 'flex') {
          mobilePopup.style.display = 'none';
        }
      }
    });
  }
  
  // Function to intercept dashboard button clicks
  function interceptDashboardClicks() {
    const dashboardElements = document.querySelectorAll('a[href*="dashboard"], button[onclick*="dashboard"], .dashboard-link, .dashboard-button, [href="/dashboard"]');
    
    dashboardElements.forEach(element => {
      // Remove existing event listeners by cloning the element
      const newElement = element.cloneNode(true);
      element.parentNode.replaceChild(newElement, element);
      
      // Add new click handler
      newElement.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        console.log('🔒 Dashboard access blocked - showing subscription popup');
        
        // Show appropriate popup based on screen size
        if (window.innerWidth <= 768) {
          const mobilePopup = document.getElementById('mobile-subscription-required-popup');
          if (mobilePopup) {
            mobilePopup.style.display = 'flex';
          }
        } else {
          const popup = document.getElementById('subscription-required-popup');
          if (popup) {
            popup.style.display = 'flex';
          }
        }
        
        return false;
      });
    });
    
    return dashboardElements.length;
  }
  
  // Function to set up mutation observer
  function setupMutationObserver() {
    const observer = new MutationObserver((mutations) => {
      let newElementsFound = false;
      
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
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
      
      // If new dashboard elements were found, intercept them
      if (newElementsFound) {
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
  }
  
  // Initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSubscriptionPopup);
  } else {
    initSubscriptionPopup();
  }
  
  // Also initialize on page load (for SPA navigation)
  window.addEventListener('load', initSubscriptionPopup);
  
})();
