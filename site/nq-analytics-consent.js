(function(){
  var KEY='nq-analytics-consent';
  var choice=null;
  try{choice=localStorage.getItem(KEY);}catch(e){}
  function save(value){try{localStorage.setItem(KEY,value);}catch(e){}}
  function setConsent(value){
    save(value);
    if(value==='granted'&&typeof window.nqLoadGTM==='function')window.nqLoadGTM();
    if(value==='denied'&&window.gtag)window.gtag('consent','update',{analytics_storage:'denied',ad_storage:'denied',ad_user_data:'denied',ad_personalization:'denied'});
    banner.hidden=true;
  }
  var banner=document.createElement('section');
  banner.id='nq-consent-banner';banner.setAttribute('role','region');banner.setAttribute('aria-label','Privacy and analytics preferences');banner.hidden=true;
  banner.innerHTML='<div class="nq-consent-card"><p class="nq-consent-eyebrow">NEXUS-Q · YOUR PRIVACY</p><h2>Help us improve NEXUS-Q</h2><p>We would like to use Google Analytics to understand which pages are useful and improve your experience. Analytics is optional and stays off unless you choose to allow it.</p><div class="nq-consent-actions"><button type="button" data-choice="accept">Accept analytics</button><button type="button" data-choice="reject">Reject analytics</button></div><p class="nq-consent-note">Your choice will not affect access to the site. You can change it at any time. Read our <a href="/privacy">Privacy Policy</a> and <a href="/cookies">Cookie Policy</a>.</p></div>';
  document.addEventListener('DOMContentLoaded',function(){
    document.body.appendChild(banner);
    var prefs=document.createElement('button');prefs.id='nq-consent-preferences';prefs.type='button';prefs.textContent='Privacy preferences';prefs.setAttribute('aria-label','Change analytics consent preferences');document.body.appendChild(prefs);
    banner.addEventListener('click',function(e){var b=e.target.closest('button[data-choice]');if(b)setConsent(b.dataset.choice==='accept'?'granted':'denied');});
    prefs.addEventListener('click',function(){banner.hidden=false;});
    if(choice!=='granted'&&choice!=='denied')banner.hidden=false;
  });
})();
