(function(){
  try{
    var cookie = document.getElementById('cookie');
    var accept = document.getElementById('accept');
    if(cookie && accept){
      var ok = localStorage.getItem('rp_cookie_ok');
      if(!ok){ cookie.style.display = 'flex'; }
      accept.addEventListener('click', function(){
        localStorage.setItem('rp_cookie_ok','1');
        cookie.style.display = 'none';
      });
    }
  }catch(_){ }
})();


