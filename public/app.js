(function(){
  try{
    var cookie = document.getElementById('cookie');
    var accept = document.getElementById('accept');
    var toggle = document.getElementById('menu-toggle');
    var overlay = document.getElementById('drawerOverlay');
    var drawer = document.getElementById('drawer');
    var drawerClose = document.getElementById('drawerClose');
    if(cookie && accept){
      var ok = localStorage.getItem('rp_cookie_ok');
      if(!ok){ cookie.style.display = 'flex'; }
      accept.addEventListener('click', function(){
        localStorage.setItem('rp_cookie_ok','1');
        cookie.style.display = 'none';
      });
    }
    function setDrawer(open){
      if(!overlay || !drawer) return;
      if(open){ overlay.classList.add('open'); toggle && toggle.setAttribute('aria-expanded','true'); }
      else { overlay.classList.remove('open'); toggle && toggle.setAttribute('aria-expanded','false'); }
    }
    if(toggle){ toggle.addEventListener('click', function(){ var isOpen = !(overlay && overlay.classList.contains('open')); setDrawer(isOpen); }); }
    if(overlay){ overlay.addEventListener('click', function(e){ if (e.target === overlay) setDrawer(false); }); }
    if(drawerClose){ drawerClose.addEventListener('click', function(){ setDrawer(false); }); }
    
    // Close mobile menu when any menu item is clicked
    var mobileMenuLinks = document.querySelectorAll('#drawer a, #drawer .btn');
    mobileMenuLinks.forEach(function(link) {
      link.addEventListener('click', function() {
        console.log('[MOBILE-MENU] Menu item clicked, closing drawer');
        setDrawer(false);
      });
    });

    // Fade-in on scroll
    var sections = document.querySelectorAll('.fade-section');
    if('IntersectionObserver' in window && sections.length){
      var io = new IntersectionObserver(function(entries){
        entries.forEach(function(entry){ if(entry.isIntersecting){ entry.target.classList.add('visible'); io.unobserve(entry.target); } });
      }, { threshold: 0.15 });
      sections.forEach(function(s){ io.observe(s); });
    } else { sections.forEach(function(s){ s.classList.add('visible'); }); }

    // Testimonials rotator
    var quotes = document.querySelectorAll('.quote-card');
    var idx = 0;
    if (quotes.length){
      function activate(i){ quotes.forEach(function(q){ q.classList.remove('active'); }); quotes[i].classList.add('active'); }
      activate(0);
      setInterval(function(){ idx = (idx + 1) % quotes.length; activate(idx); }, 4000);
    }

    // Hero reviews ticker (placeholder data)
    var ticker = document.querySelector('.reviews-track');
    if (ticker){
      var items = [
        { name:'Alex P.', business:'Rapid HVAC', text:'Outstanding service, easy to set up.', stars:5 },
        { name:'Megan S.', business:'Bloom Spa', text:'Private feedback saved a client relationship.', stars:5 },
        { name:'Carlos R.', business:'Northside Auto', text:'We doubled reviews in 6 weeks.', stars:5 },
        { name:'Alicia D.', business:'BrightSmile Dental', text:'Simple and effective review requests.', stars:5 },
        { name:'Tom L.', business:'Acme Dental', text:'The QR codes work great at checkout.', stars:5 }
      ];
      function starRow(n){ var s=''; for(var i=0;i<n;i++) s+='★'; return s; }
      function appendSet(){ items.forEach(function(it){ var row=document.createElement('div'); row.className='review-item'; var av=document.createElement('div'); av.className='review-avatar'; av.textContent=it.name.charAt(0); var content=document.createElement('div'); content.className='review-content'; var stars=document.createElement('div'); stars.className='review-stars'; stars.textContent=starRow(it.stars); var txt=document.createElement('div'); txt.className='review-text'; txt.textContent=it.text; var meta=document.createElement('div'); meta.className='review-meta'; meta.textContent=it.name+' • '+it.business; content.appendChild(stars); content.appendChild(txt); content.appendChild(meta); row.appendChild(av); row.appendChild(content); ticker.appendChild(row); }); }
      appendSet(); appendSet();
    }
  }catch(_){ }
})();


// Signup form client handling (duplicate email UX)
(function(){
  try{
    var form = document.querySelector('form[action="/signup"]');
    if (!form) return;
    var submitting = false;
    form.addEventListener('submit', async function(ev){
      try {
        if (submitting) return;
        submitting = true;
        ev.preventDefault();
        var fd = new FormData(form);
        var body = new URLSearchParams();
        fd.forEach(function(v,k){ body.append(k,v); });
        var resp = await fetch('/signup', {
          method: 'POST',
          headers: { 'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
          credentials: 'same-origin',
          body: body.toString()
        });
        if (resp.ok) {
          var data = await resp.json().catch(function(){ return null; });
          if (data && data.redirect) { window.location = data.redirect; return; }
          window.location.reload();
          return;
        }
        var data = await resp.json().catch(function(){ return { error: 'GENERIC_SIGNUP_FAILED' }; });
        var container = document.querySelector('.form-container');
        if (!container) { form.insertAdjacentHTML('afterbegin', '<div class="error">Unexpected error.</div>'); return; }
        var old = container.querySelector('.error'); if (old) old.remove();
        if (data && data.error === 'EMAIL_ALREADY_REGISTERED') {
          container.insertAdjacentHTML('afterbegin', '<div class="error">An account with this email already exists. Please <a href="/login">log in</a> instead.</div>');
        } else if (data && data.error === 'PASSWORD_POLICY') {
          container.insertAdjacentHTML('afterbegin', '<div class="error">Password must include at least one symbol (!@#$%).</div>');
        } else {
          container.insertAdjacentHTML('afterbegin', '<div class="error">Signup failed. Try a different email.</div>');
        }
      } catch(e) {
        try { form.submit(); } catch(_) {}
      } finally {
        submitting = false;
      }
    });
  }catch(_){ }
})();

// Phase 4.1: No AJAX handlers for auth forms (server handles submissions)

