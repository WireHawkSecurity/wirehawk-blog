---
title: "Subscribe"
layout: "single"
showtoc: false
hideMeta: true
ogImage: "images/og/subscribe.png"
build:
  list: never
---

<div class="subscribe-page">

<p class="subscribe-intro">Get notified when new posts go live.</p>

<div class="subscribe-grid">

<div class="subscribe-card" id="bd-subscribe-card">
<div class="subscribe-card-title">Email Notifications</div>
<p class="subscribe-card-desc">Get an email when a new post is published.</p>
<form id="bd-subscribe-form" action="https://buttondown.com/api/emails/embed-subscribe/WireHawkSecurity" method="post">
<input type="hidden" name="embed" value="1">
<div style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden" aria-hidden="true">
<label>Leave this field empty<input type="text" name="hp_website" tabindex="-1" autocomplete="off"></label>
</div>
<div class="subscribe-email-form">
<input type="email" name="email" placeholder="you@example.com" required autocomplete="email" class="subscribe-email-input" aria-label="Email address">
<button type="submit" class="subscribe-form-btn">Subscribe</button>
</div>
<p class="subscribe-status" id="bd-subscribe-status" role="status" aria-live="polite"></p>
</form>
</div>

<div class="subscribe-card">
<div class="subscribe-card-title">RSS Feed</div>
<p class="subscribe-card-desc">Copy the feed URL below and add it to your preferred reader.</p>
<div class="subscribe-rss-row">
<div class="subscribe-url">https://blog.wirehawksecurity.com/index.xml</div>
<button type="button" class="subscribe-form-btn" onclick="navigator.clipboard.writeText('https://blog.wirehawksecurity.com/index.xml').then(function(){this.textContent='Copied!';var b=this;setTimeout(function(){b.textContent='Copy Link'},2000)}.bind(this))">Copy Link</button>
</div>
</div>

</div>
</div>

<script>
(function () {
  var form = document.getElementById('bd-subscribe-form');
  if (!form) return;

  var card = document.getElementById('bd-subscribe-card');
  var status = document.getElementById('bd-subscribe-status');
  var input = form.querySelector('.subscribe-email-input');
  var btn = form.querySelector('button[type="submit"]');
  var row = form.querySelector('.subscribe-email-form');

  function fail(msg) {
    status.textContent = msg;
    status.className = 'subscribe-status subscribe-status-error';
    btn.disabled = false;
    btn.textContent = 'Subscribe';
  }

  function done() {
    row.remove();
    status.textContent = 'Almost there. Check your inbox for a confirmation link to finish subscribing.';
    status.className = 'subscribe-status subscribe-status-ok';
    card.classList.add('subscribe-card-confirmed');
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();

    if (!input.checkValidity()) {
      input.reportValidity();
      return;
    }

    var hp = form.querySelector('input[name="hp_website"]');
    if (hp && hp.value) {
      done();
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Sending';
    status.textContent = '';
    status.className = 'subscribe-status';

    var body = new URLSearchParams(new FormData(form));
    body.delete('hp_website');

    fetch(form.action, {
      method: 'POST',
      mode: 'no-cors',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    }).then(done, function () {
      fail('Could not reach the server. Check your connection and try again.');
    });
  });
})();
</script>
