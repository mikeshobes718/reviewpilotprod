// Clean Room Implementation: Public Review Gating (Submission Logic)
// This manages the 1-4 star internal feedback vs. 5-star Google redirect flow

document.addEventListener('DOMContentLoaded', () => {
    console.log('[CLEANROOM-GATING] DOM loaded, initializing...');
    
    const appContainer = document.getElementById('rate-root');
    if (!appContainer) {
        console.error('[CLEANROOM-GATING] Could not find #rate-root element');
        return;
    }

    // Retrieve IDs injected by the backend (Step 1)
    const targetBusinessId = appContainer.getAttribute('data-business-id');
    const googlePlaceId = appContainer.getAttribute('data-place-id');
    const googleReviewUrl = `https://search.google.com/local/writereview?placeid=${googlePlaceId}`;

    console.log(`[CLEANROOM-GATING] Initialized for UID: ${targetBusinessId}, Place ID: ${googlePlaceId}`);
    console.log('[CLEANROOM-GATING] App container:', appContainer);
    console.log('[CLEANROOM-GATING] Data attributes:', appContainer.dataset);

    const ratingSection = document.getElementById('rating-section');
    const contactSection = document.getElementById('contact-section');
    const feedbackSection = document.getElementById('feedback-section');
    const submitSection = document.getElementById('submit-section');
    const thankYouSection = document.getElementById('thank-you-section');
    const stars = Array.from(document.querySelectorAll('.star'));
    console.log('[DOM] Stars found:', stars.length);
    stars.forEach((star, index) => {
        console.log(`[DOM] Star ${index + 1}:`, star, 'data-value:', star.dataset.value);
    });
    
    const actionButton5Star = document.getElementById('action-button-5star');
    const feedbackTextarea = document.getElementById('feedback-text');
    const customerName = document.getElementById('customer-name');
    const customerEmail = document.getElementById('customer-email');
    const customerPhone = document.getElementById('customer-phone');
    const consentCheckbox = document.getElementById('consent-checkbox');


    


    let currentRating = 0;
    let isSubmitting = false;

    // Phone number formatting for US format
    function formatPhoneNumber(value) {
        let digits = value.replace(/\D/g, ''); // Remove non-digits
        if (digits.length === 0) return '';
        if (digits.length <= 3) return `(${digits}`;
        if (digits.length <= 6) return `(${digits.slice(0, 3)}) ${digits.slice(3)}`;
        if (digits.length <= 10) return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6, 10)}`;
        return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6, 10)}`;
    }

    // Add phone formatting event listener
    if (customerPhone) {
        customerPhone.addEventListener('input', function(e) {
            const formatted = formatPhoneNumber(e.target.value);
            e.target.value = formatted;
        });
        
        // Also format on paste
        customerPhone.addEventListener('paste', function(e) {
            setTimeout(() => {
                const formatted = formatPhoneNumber(e.target.value);
                e.target.value = formatted;
            }, 10);
        });
    }

    function paint(value) {
        console.log('[PAINT] Painting stars with value:', value);
        console.log('[PAINT] Stars array length:', stars.length);
        
        if (stars.length === 0) {
            console.error('[PAINT] No stars found!');
            return;
        }
        
        const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981';
        console.log('[PAINT] Accent color:', accentColor);
        
        stars.forEach((s, index) => {
            const starValue = parseInt(s.dataset.value);
            const on = starValue <= value;
            const color = on ? accentColor : '#CBD5E0';
            
            console.log(`[PAINT] Star ${index + 1} (value: ${starValue}): on=${on}, color=${color}`);
            console.log(`[PAINT] Star element:`, s);
            console.log(`[PAINT] Star computed style before:`, getComputedStyle(s).color);
            
            s.style.color = color;
            
            console.log(`[PAINT] Star computed style after:`, getComputedStyle(s).color);
        });
        
        console.log('[PAINT] Paint function completed');
    }

    // Function to update UI based on rating (Attach this logic to star click events)
    function selectRating(rating) {
        currentRating = rating;

        // Show contact section for all ratings
        contactSection.style.display = 'block';
        submitSection.style.display = 'block';

        if (rating >= 1 && rating <= 4) {
            // 1-4 Stars: Show feedback form
            feedbackSection.style.display = 'block';
        } else if (rating === 5) {
            // 5 Stars: Hide feedback form
            feedbackSection.style.display = 'none';
            feedbackTextarea.value = ''; // Clear textarea
        }
    }

    // Function to handle submission (Attach to action-button click event)
    async function handleSubmit() {
        if (isSubmitting) return;
        isSubmitting = true;

        // Validate required fields
        const name = customerName.value.trim();
        const email = customerEmail.value.trim();
        const phone = customerPhone.value.trim();
        let comment = null;

        if (!email) {
            alert("Please enter your email address.");
            isSubmitting = false;
            return;
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            alert("Please enter a valid email address.");
            isSubmitting = false;
            return;
        }

        if (!consentCheckbox || !consentCheckbox.checked) {
            alert("Please check the consent checkbox to continue.");
            isSubmitting = false;
            return;
        }

        if (currentRating <= 4) {
            comment = feedbackTextarea.value.trim();
            if (!comment) {
                alert("Please let us know what would make your experience 5 stars.");
                isSubmitting = false;
                return;
            }
        }

        console.log(`[CLEANROOM-GATING] Submitting Rating: ${currentRating} for UID: ${targetBusinessId}`);

        // Submit to the standardized backend endpoint (Step 2)
        try {
            console.log(`[CLEANROOM-GATING] Preparing to submit review...`);
            console.log(`[CLEANROOM-GATING] Request data:`, {
                targetBusinessId,
                rating: currentRating,
                comment,
                email,
                name,
                phone: phone || null,
                consent: true
            });
            
            const response = await fetch('/api/reviews/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                // CRITICAL: Ensure all data points are sent correctly
                body: JSON.stringify({ 
                    targetBusinessId, 
                    rating: currentRating, 
                    comment,
                    email,
                    name,
                    phone: phone || null,
                    consent: true
                })
            });

            console.log(`[CLEANROOM-GATING] Response received:`, {
                status: response.status,
                statusText: response.statusText,
                ok: response.ok
            });

            if (response.ok) {
                const responseData = await response.json();
                console.log(`[CLEANROOM-GATING] Response data:`, responseData);
                console.log("[CLEANROOM-GATING] Submission success.");
                // Post-submission action
                if (currentRating === 5) {
                    // Redirect to Google AFTER successful internal save
                    window.location.href = googleReviewUrl;
                } else {
                    // Show thank you message for 1-4 stars
                    ratingSection.style.display = 'none';
                    contactSection.style.display = 'none';
                    feedbackSection.style.display = 'none';
                    submitSection.style.display = 'none';
                    thankYouSection.style.display = 'block';
                }
            } else {
                const errorData = await response.json().catch(() => ({}));
                console.error(`[CLEANROOM-GATING] API Error Response:`, errorData);
                

                
                throw new Error(`API responded with status: ${response.status}. Details: ${errorData.error || errorData.details || 'Unknown error'}`);
            }
        } catch (error) {
            console.error("[CLEANROOM-GATING] Submission error:", error);
            console.error("[CLEANROOM-GATING] Error details:", {
                message: error.message,
                name: error.name,
                stack: error.stack
            });
            alert("There was an error saving your feedback. Please try again.");
        } finally {
            isSubmitting = false;
        }
    }



    // Auto-initialize with 5 stars selected
    function autoInitializeForm() {
        console.log('[AUTO-INIT] Starting auto-initialization...');
        console.log('[AUTO-INIT] Stars found:', stars.length);
        console.log('[AUTO-INIT] Current rating before:', currentRating);
        
        // Set 5 stars as default
        currentRating = 5;
        console.log('[AUTO-INIT] Current rating after setting to 5:', currentRating);
        
        // Paint the stars
        paint(5);
        console.log('[AUTO-INIT] Paint function called with value 5');
        
        // Show contact section and submit button immediately
        if (contactSection) {
            contactSection.style.display = 'block';
            console.log('[AUTO-INIT] Contact section shown');
        } else {
            console.error('[AUTO-INIT] Contact section not found!');
        }
        
        if (submitSection) {
            submitSection.style.display = 'block';
            console.log('[AUTO-INIT] Submit section shown');
        } else {
            console.error('[AUTO-INIT] Submit section not found!');
        }
        
        // Hide feedback section for 5 stars
        if (feedbackSection) {
            feedbackSection.style.display = 'none';
            console.log('[AUTO-INIT] Feedback section hidden');
        } else {
            console.error('[AUTO-INIT] Feedback section not found!');
        }
        
        // Pre-fill a positive comment
        if (feedbackTextarea) {
            feedbackTextarea.value = "Great experience! Highly recommend this place.";
            console.log('[AUTO-INIT] Comment pre-filled');
        } else {
            console.error('[AUTO-INIT] Feedback textarea not found!');
        }
        

        
        console.log('[AUTO-INIT] Form initialization complete');
    }

    // Star event listeners
    stars.forEach(star => {
        star.addEventListener('mouseover', e => {
            if (isSubmitting) return;
            const val = parseInt(e.currentTarget.dataset.value);
            paint(val);
        });

        star.addEventListener('mouseout', () => {
            if (isSubmitting) return;
            paint(currentRating);
        });

        star.addEventListener('click', e => {
            if (isSubmitting) return;
            const rating = parseInt(e.currentTarget.dataset.value);
            currentRating = rating;
            paint(rating);
            selectRating(rating);
        });
    });

    // Action button event listeners
    if (actionButton5Star) {
        actionButton5Star.addEventListener('click', handleSubmit);
    }

    // Test backend connection
    const testBackendBtn = document.getElementById('test-backend');
    const debugOutput = document.getElementById('debug-output');
    
    if (testBackendBtn && debugOutput) {
        testBackendBtn.addEventListener('click', async () => {
            debugOutput.textContent = 'Testing backend connection...';
            
            try {
                // Test 1: Check if endpoint exists
                const response = await fetch('/api/reviews/submit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        targetBusinessId: targetBusinessId, 
                        rating: 3, 
                        comment: 'Test review from debug button' 
                    })
                });
                
                const responseData = await response.json();
                
                debugOutput.innerHTML = `
                    <strong>Backend Test Results:</strong><br>
                    Status: ${response.status} ${response.statusText}<br>
                    Response: ${JSON.stringify(responseData, null, 2)}<br>
                    Business ID: ${targetBusinessId}<br>
                    Place ID: ${googlePlaceId}
                `;
                
                if (response.ok) {
                    debugOutput.style.color = '#28a745';
                } else {
                    debugOutput.style.color = '#dc3545';
                }
                
            } catch (error) {
                debugOutput.innerHTML = `
                    <strong>Backend Test Failed:</strong><br>
                    Error: ${error.message}<br>
                    Business ID: ${targetBusinessId}<br>
                    Place ID: ${googlePlaceId}
                `;
                debugOutput.style.color = '#dc3545';
            }
        });
    }

    // Auto-initialize the form with 5 stars after a small delay to ensure DOM is ready
    setTimeout(() => {
        console.log('[AUTO-INIT] Delayed initialization starting...');
        autoInitializeForm();
    }, 100);
    
    // Also try immediate initialization as backup
    console.log('[AUTO-INIT] Attempting immediate initialization...');
    autoInitializeForm();
    
    console.log('[CLEANROOM-GATING] Star rating system initialized');
});



