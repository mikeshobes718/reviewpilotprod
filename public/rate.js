document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('rate-root');
  if (!root) return;

  const ratingSection = document.getElementById('rating-section');
  const thankYouSection = document.getElementById('thank-you-section');
  const feedbackSection = document.getElementById('feedback-section');
  const feedbackText = document.getElementById('feedback-text');
  const actionButton = document.getElementById('action-button');
  const stars = Array.from(document.querySelectorAll('.star'));
  let userRating = 0;
  let isSubmitting = false;

  function paint(value) {
    stars.forEach(s => {
      const on = parseInt(s.dataset.value) <= value;
      s.style.color = on ? getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981' : '#CBD5E0';
    });
  }

  stars.forEach(star => {
    star.addEventListener('mouseover', e => {
      if (isSubmitting) return;
      const val = parseInt(e.currentTarget.dataset.value);
      paint(val);
    });
    
    star.addEventListener('mouseout', () => {
      if (isSubmitting) return;
      paint(userRating);
    });

    star.addEventListener('click', async e => {
      if (isSubmitting) return;
      userRating = parseInt(e.currentTarget.dataset.value);
      paint(userRating);

      const businessId = root.getAttribute('data-business-id');
      const placeId = root.getAttribute('data-place-id');

      // 5 stars: submit immediately and redirect to Google
      if (userRating === 5) {
        isSubmitting = true;
        try {
          const meta = document.querySelector('meta[name="csrf-token"]');
          const csrfToken = meta ? meta.getAttribute('content') : '';
          await fetch('/api/v1/reviews', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
            body: JSON.stringify({ businessId, rating: userRating, comment: null })
          });
        } catch (_) {}
        if (placeId) {
          window.location.href = `https://search.google.com/local/writereview?placeid=${encodeURIComponent(placeId)}`;
        } else {
          if (ratingSection) ratingSection.classList.add('hidden');
          if (thankYouSection) thankYouSection.classList.remove('hidden');
        }
        return;
      }

      // 1–4 stars: reveal feedback form
      if (feedbackSection) feedbackSection.classList.remove('hidden');
      if (actionButton) actionButton.textContent = 'Submit Feedback';
    });
  });

  if (actionButton) {
    actionButton.addEventListener('click', async () => {
      if (isSubmitting || userRating === 0) return;
      isSubmitting = true;

      const businessId = root.getAttribute('data-business-id');
      const placeId = root.getAttribute('data-place-id');
      const comment = (userRating <= 4 && feedbackText) ? (feedbackText.value || '').trim() : '';
      if (userRating <= 4 && !comment) { isSubmitting = false; alert('Please provide details about your experience.'); return; }

      try {
        const meta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = meta ? meta.getAttribute('content') : '';

        await fetch('/api/v1/reviews', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
          body: JSON.stringify({ businessId, rating: userRating, comment })
        });
      } catch (error) {
        console.error('Error submitting review:', error);
      }

      if (userRating === 5 && placeId) {
        window.location.href = `https://search.google.com/local/writereview?placeid=${encodeURIComponent(placeId)}`;
      } else {
        if (ratingSection) ratingSection.classList.add('hidden');
        if (feedbackSection) feedbackSection.classList.add('hidden');
        if (thankYouSection) thankYouSection.classList.remove('hidden');
      }
    });
  }
});



