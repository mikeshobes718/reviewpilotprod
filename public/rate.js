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
    const feedbackSection = document.getElementById('feedback-section');
    const thankYouSection = document.getElementById('thank-you-section');
    const stars = Array.from(document.querySelectorAll('.star'));
    const actionButton = document.getElementById('action-button');
    const feedbackTextarea = document.getElementById('feedback-text');

    console.log('[CLEANROOM-GATING] Found elements:', {
        ratingSection: !!ratingSection,
        feedbackSection: !!feedbackSection,
        thankYouSection: !!thankYouSection,
        stars: stars.length,
        actionButton: !!actionButton,
        feedbackTextarea: !!feedbackTextarea
    });

    let currentRating = 0;
    let isSubmitting = false;

    function paint(value) {
        stars.forEach(s => {
            const on = parseInt(s.dataset.value) <= value;
            s.style.color = on ? getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981' : '#CBD5E0';
        });
    }

    // Function to update UI based on rating (Attach this logic to star click events)
    function selectRating(rating) {
        currentRating = rating;
        actionButton.disabled = false;

        if (rating >= 1 && rating <= 4) {
            // 1-4 Stars: Show internal feedback form
            feedbackSection.classList.remove('hidden');
            actionButton.textContent = 'Submit Feedback';
        } else if (rating === 5) {
            // 5 Stars: Hide form, prepare for Google
            feedbackSection.classList.add('hidden');
            actionButton.textContent = 'Continue to Google Reviews';
            feedbackTextarea.value = ''; // Clear textarea
        }
    }

    // Function to handle submission (Attach to action-button click event)
    async function handleSubmit() {
        if (isSubmitting) return;
        isSubmitting = true;

        let comment = null;

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
                comment
            });
            
            const response = await fetch('/api/reviews/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                // CRITICAL: Ensure all data points are sent correctly
                body: JSON.stringify({ targetBusinessId, rating: currentRating, comment })
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
                    ratingSection.classList.add('hidden');
                    feedbackSection.classList.add('hidden');
                    thankYouSection.classList.remove('hidden');
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

    // Action button event listener
    if (actionButton) {
        actionButton.addEventListener('click', handleSubmit);
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

    console.log('[CLEANROOM-GATING] Star rating system initialized');
});



