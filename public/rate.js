// Clean Room Review Pipeline - Public Rating Page
document.addEventListener('DOMContentLoaded', () => {
    const appContainer = document.getElementById('rating-app');
    if (!appContainer) return;

    // CRITICAL: Get canonical Auth UID and Place ID injected by backend
    const targetBusinessId = appContainer.dataset.targetAttributionId;
    const googlePlaceId = appContainer.dataset.placeId;
    const googleReviewUrl = `https://search.google.com/local/writereview?placeid=${googlePlaceId}`;

    console.log(`[CLEANROOM-GATING] Initialized for UID: ${targetBusinessId}, Place ID: ${googlePlaceId}`);

    let currentRating = 0;
    let isSubmitting = false;

    // Function to update UI based on rating
    window.selectRating = (rating) => {
        if (isSubmitting) return;
        
        currentRating = rating;
        const feedbackForm = document.getElementById('feedback-form');
        const actionButton = document.getElementById('action-button');
        
        if (!feedbackForm || !actionButton) {
            console.error('[CLEANROOM-GATING] Required UI elements not found');
            return;
        }

        actionButton.disabled = false;

        if (rating >= 1 && rating <= 4) {
            // 1-4 Stars: Show internal feedback form
            feedbackForm.style.display = 'block';
            actionButton.textContent = 'Submit Feedback';
        } else if (rating === 5) {
            // 5 Stars: Hide form, prepare for Google
            feedbackForm.style.display = 'none';
            actionButton.textContent = 'Continue to Google';
            const feedbackText = document.getElementById('feedback-text');
            if (feedbackText) feedbackText.value = ''; // Clear textarea
        }
    };

    // Function to handle submission
    window.handleSubmit = async () => {
        if (isSubmitting) return;
        isSubmitting = true;

        let comment = null;

        if (currentRating <= 4) {
            const feedbackText = document.getElementById('feedback-text');
            if (feedbackText) {
                comment = feedbackText.value.trim();
                if (!comment) {
                    alert("Please let us know what would make your experience 5 stars.");
                    isSubmitting = false;
                    return;
                }
            }
        }

        console.log(`[CLEANROOM-GATING] Submitting Rating: ${currentRating} for UID: ${targetBusinessId}`);

        // Submit to the standardized backend endpoint
        try {
            const response = await fetch('/api/reviews/submit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    targetBusinessId, 
                    rating: currentRating, 
                    comment 
                })
            });

            if (response.ok) {
                console.log("[CLEANROOM-GATING] Submission success.");
                
                // Post-submission action
                if (currentRating === 5) {
                    // Redirect to Google AFTER successful internal save
                    window.location.href = googleReviewUrl;
                } else {
                    // Show thank you message
                    const ratingSection = document.getElementById('rating-section');
                    const feedbackForm = document.getElementById('feedback-form');
                    const thankYouSection = document.getElementById('thank-you-section');
                    
                    if (ratingSection) ratingSection.style.display = 'none';
                    if (feedbackForm) feedbackForm.style.display = 'none';
                    if (thankYouSection) thankYouSection.style.display = 'block';
                }
            } else {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(`API responded with status: ${response.status}. ${errorData.error || ''}`);
            }
        } catch (error) {
            console.error("[CLEANROOM-GATING] Submission error:", error);
            alert("There was an error saving your feedback. Please try again.");
        } finally {
            isSubmitting = false;
        }
    };

    // Initialize star rating system
    const stars = Array.from(document.querySelectorAll('.star'));
    if (stars.length > 0) {
        stars.forEach(star => {
            star.addEventListener('click', (e) => {
                const rating = parseInt(e.currentTarget.dataset.value);
                selectRating(rating);
                
                // Update star display
                stars.forEach((s, index) => {
                    const starRating = index + 1;
                    s.style.color = starRating <= rating ? 
                        (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981') : 
                        '#CBD5E0';
                });
            });

            star.addEventListener('mouseover', (e) => {
                if (isSubmitting) return;
                const rating = parseInt(e.currentTarget.dataset.value);
                stars.forEach((s, index) => {
                    const starRating = index + 1;
                    s.style.color = starRating <= rating ? 
                        (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981') : 
                        '#CBD5E0';
                });
            });

            star.addEventListener('mouseout', () => {
                if (isSubmitting) return;
                stars.forEach((s, index) => {
                    const starRating = index + 1;
                    s.style.color = starRating <= currentRating ? 
                        (getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981') : 
                        '#CBD5E0';
                });
            });
        });
    }

    // Initialize action button
    const actionButton = document.getElementById('action-button');
    if (actionButton) {
        actionButton.addEventListener('click', handleSubmit);
    }

    console.log('[CLEANROOM-GATING] Initialization complete');
});



