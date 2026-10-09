/* WireHawk search landing
   assets/js/wh-landing.js

   Runs on post pages. When the page is opened from a search hit
   (/posts/x/?hl=kinit#code-3), it highlights the query inside the target,
   scrolls the first highlight to the middle of the screen, and flashes the
   block so the eye lands on it. The target is the code block or heading the
   hash names; for a heading, the scope runs to the next h2. Without a hash
   the whole post is in scope.

   The hl parameter is stripped from the address bar afterwards, so a copied
   link stays clean. Escape removes the highlights. */
(function () {
  'use strict';

  var params;
  try { params = new URLSearchParams(location.search); } catch (e) { return; }
  var hl = params.get('hl');
  if (!hl) return;

  var content = document.querySelector('.post-content');
  if (!content) return;

  var terms = hl.toLowerCase().split(/\s+/).filter(function (t) { return t.length > 1; });
  if (!terms.length) return;
  // Longest first, so "certipy-ad" wins over "certipy" when both are typed.
  terms.sort(function (a, b) { return b.length - a.length; });

  var target = null;
  if (location.hash.length > 1) {
    try { target = document.getElementById(decodeURIComponent(location.hash.slice(1))); } catch (e) {}
  }

  // The nodes to search: one code block, one section, or the whole post.
  var scope = [];
  if (target && /^H[2-6]$/.test(target.tagName)) {
    for (var n = target.nextElementSibling; n && n.tagName !== 'H2'; n = n.nextElementSibling) scope.push(n);
  } else if (target && content.contains(target)) {
    scope.push(target);
  } else {
    scope.push(content);
  }

  var SKIP = /^(SCRIPT|STYLE|BUTTON|SVG)$/;

  function markIn(root) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: function (node) {
        for (var p = node.parentNode; p && p !== root.parentNode; p = p.parentNode) {
          if (SKIP.test(p.nodeName.toUpperCase())) return NodeFilter.FILTER_REJECT;
        }
        return node.nodeValue.trim() ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      }
    });
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);

    var marks = [];
    nodes.forEach(function (node) {
      var text = node.nodeValue;
      var lower = text.toLowerCase();
      var ranges = [];
      terms.forEach(function (t) {
        var i = lower.indexOf(t);
        while (i !== -1) {
          var end = i + t.length;
          var overlaps = ranges.some(function (r) { return i < r[1] && end > r[0]; });
          if (!overlaps) ranges.push([i, end]);
          i = lower.indexOf(t, end);
        }
      });
      if (!ranges.length) return;
      ranges.sort(function (a, b) { return a[0] - b[0]; });

      var frag = document.createDocumentFragment();
      var pos = 0;
      ranges.forEach(function (r) {
        if (r[0] > pos) frag.appendChild(document.createTextNode(text.slice(pos, r[0])));
        var m = document.createElement('mark');
        m.className = 'wh-hl';
        m.textContent = text.slice(r[0], r[1]);
        frag.appendChild(m);
        marks.push(m);
        pos = r[1];
      });
      if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
      // PaperMod lays out pre > code as a grid, which turns every child into
      // its own row. Keep the code element's content one child by wrapping
      // the pieces in a single span.
      if (node.parentNode.nodeName === 'CODE') {
        var line = document.createElement('span');
        line.appendChild(frag);
        frag = line;
      }
      node.parentNode.replaceChild(frag, node);
    });
    return marks;
  }

  var marks = [];
  scope.forEach(function (el) { marks = marks.concat(markIn(el)); });

  var block = target && target.tagName === 'PRE' ? target
    : target && target.classList && target.classList.contains('highlight') ? target
    : marks.length ? marks[0].closest('pre') : null;

  function land() {
    var focus = marks[0] || target;
    if (focus) {
      var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      focus.scrollIntoView({ block: 'center', inline: 'nearest', behavior: reduce ? 'auto' : 'smooth' });
    }
    // A code block is focusable (tabindex="0"), so the browser focuses it on
    // the hash jump and draws a focus ring over our accent. Drop that focus.
    if (target && document.activeElement === target && target.blur) target.blur();
    if (block) {
      block.classList.remove('wh-landed');
      void block.offsetWidth;
      block.classList.add('wh-landed');
    }
  }

  // The browser performs its own jump to the hash after parsing. Landing once
  // the page has loaded lets ours win, and centres the line rather than
  // pinning the block's top edge under the header.
  if (document.readyState === 'complete') requestAnimationFrame(land);
  else window.addEventListener('load', function () { requestAnimationFrame(land); });

  try {
    params.delete('hl');
    var qs = params.toString();
    history.replaceState(history.state, '', location.pathname + (qs ? '?' + qs : '') + location.hash);
  } catch (e) {}

  document.addEventListener('keydown', function onKey(e) {
    if (e.key !== 'Escape') return;
    // Escape belongs to the image lightbox while it is open.
    if (document.querySelector('.lightbox-overlay.active')) return;
    marks.forEach(function (m) {
      var parent = m.parentNode;
      if (!parent) return;
      parent.replaceChild(document.createTextNode(m.textContent), m);
      parent.normalize();
    });
    marks = [];
    if (block) block.classList.remove('wh-landed');
    document.removeEventListener('keydown', onKey);
  });
})();
