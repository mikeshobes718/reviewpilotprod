document.addEventListener('DOMContentLoaded', () => {
  const root = document.getElementById('rate-root');
  if (!root) return;

  const ratingSection = document.getElementById('rating-section');
  const contactSection = document.getElementById('contact-section');
  const contactTitle = document.getElementById('contact-title');
  const contactSubtitle = document.getElementById('contact-subtitle');
  const contactForm = document.getElementById('contact-form');
  const feedbackWrapper = document.getElementById('feedback-wrapper');
  const feedbackTextarea = document.getElementById('feedback-text');
  const thankYouSection = document.getElementById('thank-you-section');
  const stars = Array.from(document.querySelectorAll('.star'));

  let userRating = 0;

  function paint(value) {
    stars.forEach(s => {
      const on = parseInt(s.dataset.value) <= value;
      s.style.color = on ? getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#10B981' : '#CBD5E0';
      s.classList.toggle('selected', on && value > 0);
    });
  }

  stars.forEach(star => {
    star.addEventListener('mouseover', e => {
      const val = parseInt(e.currentTarget.dataset.value);
      paint(val);
    });
    star.addEventListener('mouseout', () => {
      paint(userRating);
    });
    star.addEventListener('click', e => {
      userRating = parseInt(e.currentTarget.dataset.value);
      paint(userRating);
      handleRating(userRating);
    });
  });

  function handleRating(rating) {
    ratingSection.classList.add('hidden');
    if (rating <= 4) {
      contactTitle.textContent = 'Thanks for your rating';
      contactSubtitle.textContent = 'Please share your contact info and tell us how we can improve.';
      feedbackWrapper.classList.remove('hidden');
      feedbackTextarea.setAttribute('required', 'required');
    } else {
      contactTitle.textContent = 'Almost there!';
      contactSubtitle.textContent = 'Please share your contact info before leaving a public Google review.';
      feedbackWrapper.classList.add('hidden');
      feedbackTextarea.removeAttribute('required');
      feedbackTextarea.value = '';
    }
    contactSection.classList.remove('hidden');
  }

  contactForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!userRating) {
      alert('Please select a star rating first.');
      return;
    }
    const payload = {
      rating: userRating,
      name: document.getElementById('name').value,
      email: document.getElementById('email').value,
      phone: document.getElementById('phone').value,
      feedback: feedbackWrapper.classList.contains('hidden') ? undefined : feedbackTextarea.value,
      type: userRating === 5 ? 'positive' : 'feedback'
    };

    const businessId = root.getAttribute('data-business-id');
    const placeId = root.getAttribute('data-place-id');
    await submitData(`/submit-feedback/${businessId}`, payload, contactSection);
    if (userRating === 5 && placeId) {
      window.location.href = `https://search.google.com/local/writereview?placeid=${encodeURIComponent(placeId)}`;
    }
  });

  async function submitData(url, data, formToHide) {
    try {
      const meta = document.querySelector('meta[name="csrf-token"]');
      const csrfToken = meta ? meta.getAttribute('content') : '';

      if (typeof hcaptcha !== 'undefined' && root.dataset.hcaptchaSiteKey) {
        try {
          const token = await hcaptcha.execute(root.dataset.hcaptchaSiteKey, { action: 'submit' });
          if (token) data.hcaptchaToken = token;
        } catch (_) {}
      }

      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
        body: JSON.stringify(data),
      });

      if (response.ok) {
        formToHide.classList.add('hidden');
        if (data.rating <= 4) {
          thankYouSection.classList.remove('hidden');
        }
      } else {
        alert('There was an error submitting your feedback.');
      }
    } catch (error) {
      console.error('Error:', error);
      alert('An unexpected error occurred.');
    }
  }
});


