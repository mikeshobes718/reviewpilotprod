(function(){
  try{
    var cookie = document.getElementById('cookie');
    var accept = document.getElementById('accept');
    var toggle = document.getElementById('menu-toggle');
    var nav = document.getElementById('nav-links');
    if(cookie && accept){
      var ok = localStorage.getItem('rp_cookie_ok');
      if(!ok){ cookie.style.display = 'flex'; }
      accept.addEventListener('click', function(){
        localStorage.setItem('rp_cookie_ok','1');
        cookie.style.display = 'none';
      });
    }
    if(toggle && nav){
      toggle.addEventListener('click', function(){
        var isOpen = nav.classList.toggle('open');
        toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
      });
    }
  }catch(_){ }
})();


