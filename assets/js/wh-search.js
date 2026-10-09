/* WireHawk search core
   assets/js/wh-search.js

   Used by the Search page (layouts/wh-search.html). Wraps Pagefind and turns
   each matching post into a list of hits, where a hit is either a code block
   (#code-N, from render-codeblock.html) or a prose section (#<heading-id>),
   each with its own snippet and a deep link that lands on that exact spot.

   How the mapping works: Pagefind returns, per page, the word positions of
   every match (`locations`) and every element on the page that has an id
   (`anchors`), each with its own word position. A match belongs to the code
   block whose anchor starts at or before it and whose text is long enough to
   reach it. Otherwise it belongs to the nearest heading above it.

   Why the query is not quoted: a quoted Pagefind search returns only the
   first location of the phrase on each page, which is usually a mention in
   prose, so the command itself was never surfaced. Unquoted, every location
   comes back. The noise unquoted search can pull in (fuzzy and part-word
   matches like "ldap" for "ldap-shell") is removed here instead: a location
   only counts if the word there actually contains a query term, and a page
   only counts if every term survives that check. */
(function (root) {
  'use strict';

  var BASE = '/pagefind/';
  // Pages fetched from Pagefind per query, in its rank order.
  var LIMIT = 30;
  var lib = null;
  var loading = null;

  // Characters that wrap a token in shell output and prose but are not part
  // of what someone would search for: quotes, brackets, trailing punctuation.
  var TRIM = /^[\s'"`([{<,;:]+|[\s'"`)\]}>,;:.!?]+$/g;

  function load() {
    if (lib) return Promise.resolve(lib);
    if (!loading) {
      loading = import(BASE + 'pagefind.js').then(function (m) {
        return Promise.resolve(m.options({ basePath: BASE })).then(function () {
          lib = m;
          return m;
        });
      }).catch(function (e) { loading = null; throw e; });
    }
    return loading;
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  // Query words, trimmed the same way as the words they are matched against,
  // so "Pwn3d!" matches "(Pwn3d!)" in NetExec output.
  function terms(q) {
    return String(q).replace(/"/g, '').split(/\s+/).map(norm).filter(Boolean);
  }

  function norm(word) {
    return String(word || '').toLowerCase().replace(TRIM, '');
  }

  // What Pagefind is asked for. It indexes letters, digits and -_. only, and
  // a query carrying anything else ($krb5tgs$, C:\Users) comes back empty.
  // Those characters become word breaks here; the full term is still what
  // each match is checked against below.
  function pagefindQuery(ts) {
    var parts = [];
    ts.forEach(function (t) {
      t.split(/[^a-z0-9._-]+/).forEach(function (p) { if (p.length > 1) parts.push(p); });
    });
    return parts.join(' ');
  }

  // A term matches a word where it starts the word, follows a separator
  // ("pfx" in "administrator.pfx", "users" in "--users"), or starts a
  // camelCase part ("kerberoast" in "targetedKerberoast"). Not mid-word:
  // "rpc" should not match "msrpc", nor "net" match "internet".
  function hasTerm(raw, t) {
    var orig = String(raw || '').replace(TRIM, '');
    var w = orig.toLowerCase();
    var i = w.indexOf(t);
    while (i !== -1) {
      if (i === 0) return true;
      var prev = orig.charAt(i - 1), cur = orig.charAt(i);
      if (!/[A-Za-z0-9]/.test(prev)) return true;
      if (/[a-z]/.test(prev) && /[A-Z]/.test(cur)) return true;
      i = w.indexOf(t, i + 1);
    }
    return false;
  }

  function wordCount(s) {
    var w = String(s || '').trim();
    return w ? w.split(/\s+/).length : 0;
  }

  function headingText(a) {
    // PaperMod's anchored headings append a "#" link to each h2.
    return String(a.text || '').replace(/\s*#\s*$/, '').trim();
  }

  // Window of words around the matched locations, matched words wrapped in
  // <mark>. `from`/`to` bound the window to one block or one section.
  function snippet(words, locs, from, to, radius, code) {
    var hit = {};
    locs.forEach(function (l) { hit[l] = true; });
    var first = locs[0], last = locs[locs.length - 1];
    var start = Math.max(from, first - radius);
    var end = Math.min(to, last + radius + 1);
    // Long outputs with hits far apart: keep the window around the first hit.
    if (end - start > radius * 4) end = Math.min(to, first + radius * 3);
    var out = [];
    for (var i = start; i < end; i++) {
      var w = hit[i] ? '<mark>' + esc(words[i]) + '</mark>' : esc(words[i]);
      // In a command each token is kept whole when it wraps, so "-target"
      // never splits into "-" and "target" on a narrow screen. search.css
      // lets a token longer than the line (a SID, a hash) break inside.
      out.push(code ? '<span class="wh-tok">' + w + '</span>' : w);
    }
    return (start > from ? '… ' : '') + out.join(' ') + (end < to ? ' …' : '');
  }

  function buildPage(d, q) {
    var ts = terms(q);
    var words = d.content.split(/\s+/);
    var anchors = (d.anchors || []).slice().sort(function (a, b) { return a.location - b.location; });

    var headings = anchors.filter(function (a) { return /^h[2-6]$/.test(a.element); });
    var blocks = anchors.filter(function (a) { return /^code-\d+$/.test(a.id); }).map(function (a) {
      return { a: a, from: a.location, to: a.location + wordCount(a.text) };
    });

    // Keep only locations whose word really contains a term, and note which
    // term each one satisfies.
    var seen = {};
    var locs = (d.locations || []).slice().sort(function (a, b) { return a - b; }).filter(function (l) {
      var ok = false;
      ts.forEach(function (t) { if (hasTerm(words[l], t)) { seen[t] = true; ok = true; } });
      return ok;
    });
    if (!locs.length || ts.some(function (t) { return !seen[t]; })) return null;

    function sectionAt(loc) {
      var s = null;
      for (var i = 0; i < headings.length && headings[i].location <= loc; i++) s = headings[i];
      return s;
    }

    function blockAt(loc) {
      for (var i = 0; i < blocks.length; i++) {
        if (loc >= blocks[i].from && loc < blocks[i].to) return blocks[i];
      }
      return null;
    }

    var groups = {};
    var order = [];
    locs.forEach(function (l) {
      var b = blockAt(l);
      var s = sectionAt(l);
      var key = b ? b.a.id : 'sec:' + (s ? s.id : '');
      if (!groups[key]) {
        groups[key] = { key: key, kind: b ? 'code' : 'text', block: b, section: s, locs: [], terms: {} };
        order.push(key);
      }
      groups[key].locs.push(l);
      ts.forEach(function (t) { if (hasTerm(words[l], t)) groups[key].terms[t] = true; });
    });

    var base = d.url.replace(/[?#].*$/, '');
    var hl = '?hl=' + encodeURIComponent(ts.join(' '));

    var hits = order.map(function (key, i) {
      var g = groups[key];
      var from, to, id;
      if (g.kind === 'code') {
        from = g.block.from; to = g.block.to; id = g.block.a.id;
      } else {
        // Bound a prose snippet to the paragraph run it sits in: after the
        // heading text and any code block above it, before the next heading
        // or code block. Otherwise the window bleeds into the commands.
        var at = g.locs[0];
        from = g.section ? g.section.location + wordCount(g.section.text) : 0;
        to = words.length;
        anchors.forEach(function (a) {
          var end = /^code-\d+$/.test(a.id) ? a.location + wordCount(a.text) : a.location;
          if (end <= at && end > from) from = end;
          if (a.location > at && a.location < to) to = a.location;
        });
        id = g.section ? g.section.id : '';
      }
      return {
        kind: g.kind,
        id: id,
        section: g.section ? headingText(g.section) : 'Introduction',
        href: base + hl + (id ? '#' + id : ''),
        // A command (up to ~40 words) is shown whole: two calls to the same
        // tool often differ only in their last flags. Longer output blocks
        // get a window around the match.
        html: snippet(words, g.locs, from, to, g.kind === 'code' ? (to - from <= 40 ? 40 : 10) : 12, g.kind === 'code'),
        score: Object.keys(g.terms).length,
        order: i
      };
    });

    // Commands first, then prose. Within each, blocks that match more of the
    // query come first, so "certipy-ad auth -ldap-shell" puts the -ldap-shell
    // call ahead of the plain auth call. Ties keep page order.
    // With several words in the query, a block that matches only one of them
    // is usually noise: "certipy-ad auth" should not surface NetExec's
    // "Null Auth:True" line. Keep only hits that match every word, and fall
    // back to partial hits only when the page has none that do.
    if (ts.length > 1) {
      var full = hits.filter(function (h) { return h.score === ts.length; });
      if (full.length) hits = full;
    }

    // A prose hit in a section that already has a matching command adds
    // nothing the command hit does not, and pushes real hits down the list.
    var codeSections = {};
    hits.forEach(function (h) { if (h.kind === 'code') codeSections[h.section] = true; });
    hits = hits.filter(function (h) { return h.kind === 'code' || !codeSections[h.section]; });

    hits.sort(function (a, b) {
      if (a.kind !== b.kind) return a.kind === 'code' ? -1 : 1;
      if (a.score !== b.score) return b.score - a.score;
      return a.order - b.order;
    });

    return {
      url: base,
      title: (d.meta && d.meta.title) || base,
      hits: hits,
      best: hits[0]
    };
  }

  // Resolves to [{ url, title, hits: [...], best }] in Pagefind rank order.
  function search(q) {
    var ts = terms(q);
    var pq = pagefindQuery(ts);
    if (!pq) return Promise.resolve([]);
    return load().then(function (pf) {
      return pf.search(pq);
    }).then(function (res) {
      return Promise.all(res.results.slice(0, LIMIT).map(function (r) { return r.data(); }));
    }).then(function (datas) {
      var n = ts.length;
      var pages = datas.map(function (d) { return buildPage(d, q); }).filter(Boolean);
      // With several words, a post only counts if one block or section holds
      // all of them. Posts where the words are scattered are shown only when
      // no post has them together.
      if (n > 1) {
        var full = pages.filter(function (p) { return p.best.score === n; });
        if (full.length) pages = full;
      }
      return pages;
    });
  }

  root.WHSearch = { load: load, search: search };
})(window);
