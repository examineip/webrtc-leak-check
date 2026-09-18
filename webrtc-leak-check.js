/*!
 * webrtc-leak-check — find out whether WebRTC exposes an IP address that
 * websites can't already see, without the false alarms most leak tests raise.
 *
 * gather() runs in the browser. Everything else is pure and also runs in Node,
 * which is how it is tested.
 * MIT License — https://github.com/examineip/webrtc-leak-check
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.webrtcLeakCheck = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var DEFAULT_STUN = 'stun:stun.l.google.com:19302';

  /* ---------------- IP parsing and classification ---------------- */

  function parseIPv4(s) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (!m) return null;
    var o = m.slice(1).map(Number);
    for (var i = 0; i < 4; i++) if (o[i] > 255) return null;
    return o;
  }

  /* Expand an IPv6 address to 8 hextets (numbers), or null if it isn't one.
   * Handles "::" compression and an embedded IPv4 tail (::ffff:1.2.3.4). */
  function parseIPv6(s) {
    s = String(s).toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
    if (s.indexOf(':') === -1) return null;
    var tail = [];
    var v4 = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
    if (v4) {
      var o = parseIPv4(v4[1]);
      if (!o) return null;
      tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
      s = s.slice(0, -v4[1].length);              // leaves "…:" or "…::"
      if (!/::$/.test(s)) s = s.slice(0, -1);     // drop the single separator colon
    }
    var parts = s.split('::');
    if (parts.length > 2) return null;
    var head = parts[0] ? parts[0].split(':') : [];
    var rest = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
    var want = 8 - tail.length;
    var fill = parts.length === 2 ? want - head.length - rest.length : 0;
    if (fill < 0 || (parts.length === 1 && head.length !== want)) return null;
    var all = head.concat(new Array(fill).fill('0'), rest);
    var out = [];
    for (var i = 0; i < all.length; i++) {
      if (!/^[0-9a-f]{1,4}$/.test(all[i])) return null;
      out.push(parseInt(all[i], 16));
    }
    out = out.concat(tail);
    return out.length === 8 ? out : null;
  }

  /* Canonical form used for comparisons: IPv4 dotted, IPv6 as 8 full hextets. */
  function canonical(ip) {
    var v4 = parseIPv4(ip);
    if (v4) return v4.join('.');
    var v6 = parseIPv6(ip);
    if (!v6) return null;
    // IPv4-mapped (::ffff:a.b.c.d) compares equal to the plain IPv4 address.
    if (v6[0] === 0 && v6[1] === 0 && v6[2] === 0 && v6[3] === 0 && v6[4] === 0 && v6[5] === 0xffff) {
      return [v6[6] >> 8, v6[6] & 255, v6[7] >> 8, v6[7] & 255].join('.');
    }
    return v6.map(function (h) { return ('000' + h.toString(16)).slice(-4); }).join(':');
  }

  function sameIP(a, b) {
    var x = canonical(a), y = canonical(b);
    return x !== null && x === y;
  }

  /* Returns 'public', 'private', 'cgnat', 'loopback', 'link-local', 'unique-local',
   * 'unspecified', 'reserved', or null if it isn't an IP address. Only 'public'
   * addresses can identify you to a website. */
  function scope(ip) {
    var c = canonical(ip);
    if (c === null) return null;
    var v4 = parseIPv4(c);
    if (v4) {
      var a = v4[0], b = v4[1];
      if (a === 0) return 'unspecified';
      if (a === 10) return 'private';
      if (a === 172 && b >= 16 && b <= 31) return 'private';
      if (a === 192 && b === 168) return 'private';
      if (a === 100 && b >= 64 && b <= 127) return 'cgnat';          // RFC 6598 carrier-grade NAT
      if (a === 127) return 'loopback';
      if (a === 169 && b === 254) return 'link-local';
      if (a >= 224) return 'reserved';                               // multicast and 240/4
      return 'public';
    }
    var h = parseIPv6(c);
    if (h.every(function (x) { return x === 0; })) return 'unspecified';
    if (h.slice(0, 7).every(function (x) { return x === 0; }) && h[7] === 1) return 'loopback';
    if ((h[0] & 0xffc0) === 0xfe80) return 'link-local';
    if ((h[0] & 0xfe00) === 0xfc00) return 'unique-local';
    if ((h[0] & 0xff00) === 0xff00) return 'reserved';               // multicast
    if ((h[0] & 0xe000) === 0x2000) return 'public';                 // 2000::/3, global unicast
    return 'reserved';
  }

  /* ---------------- ICE candidate parsing ---------------- */

  /* RFC 8839 candidate-attribute:
   *   candidate:<foundation> <component> <transport> <priority> <address> <port> typ <type> ...
   * Parsing the fields (rather than regex-hunting for anything IP-shaped) avoids
   * picking up raddr/rport or mistaking an mDNS name for an address. */
  function parseCandidate(line) {
    var s = String(line || '').trim().replace(/^a=/, '').replace(/^candidate:/, '');
    var f = s.split(/\s+/);
    if (f.length < 8 || f[6] !== 'typ') return null;
    var address = f[4];
    var mdns = /\.local$/i.test(address);
    var out = {
      foundation: f[0],
      component: Number(f[1]),
      protocol: f[2].toLowerCase(),
      priority: Number(f[3]),
      address: address,
      port: Number(f[5]),
      type: f[7],                                 // host | srflx | prflx | relay
      mdns: mdns,
      scope: mdns ? 'mdns' : scope(address)
    };
    for (var i = 8; i + 1 < f.length; i += 2) {
      if (f[i] === 'raddr') out.relatedAddress = f[i + 1];
      if (f[i] === 'rport') out.relatedPort = Number(f[i + 1]);
    }
    return out;
  }

  /* Reduce parsed candidates to what matters: the distinct public addresses
   * WebRTC exposed, plus counts of the harmless kinds. */
  function summarize(candidates) {
    var pub = [], counts = { public: 0, private: 0, mdns: 0, other: 0 };
    candidates.forEach(function (c) {
      if (!c) return;
      if (c.scope === 'public') {
        counts.public++;
        var k = canonical(c.address);
        if (!pub.some(function (p) { return canonical(p) === k; })) pub.push(c.address);
      } else if (c.scope === 'mdns') counts.mdns++;
      else if (c.scope === 'private' || c.scope === 'cgnat' || c.scope === 'unique-local' || c.scope === 'link-local') counts.private++;
      else counts.other++;
    });
    return { publicAddresses: pub, counts: counts };
  }

  /* ---------------- The verdict ---------------- */

  /**
   * Compare what WebRTC exposed with the address(es) websites see over HTTP.
   *   webrtcPublic: array of public addresses from summarize()
   *   http: { ipv4, ipv6 }  — what an ordinary request from this browser shows
   *
   * A WebRTC address only counts as a leak when we KNOW the HTTP address for that
   * IP family and it is different. If the page only learned your IPv4 address,
   * an IPv6 address from WebRTC is reported as "unverified", not as a leak.
   */
  function verdict(webrtcPublic, http) {
    http = http || {};
    if (webrtcPublic === null) {
      return { result: 'unsupported', leaked: [], matched: [], unverified: [] };
    }
    var leaked = [], matched = [], unverified = [];
    webrtcPublic.forEach(function (ip) {
      var c = canonical(ip);
      var isV4 = c !== null && c.indexOf(':') === -1;
      var known = isV4 ? http.ipv4 : http.ipv6;
      if (!known) unverified.push(ip);
      else if (sameIP(ip, known)) matched.push(ip);
      else leaked.push(ip);
    });
    var result;
    if (leaked.length) result = 'leak';
    else if (unverified.length) result = 'unverified';
    else if (matched.length) result = 'same';          // WebRTC shows what sites already see
    else result = 'nothing-exposed';
    return { result: result, leaked: leaked, matched: matched, unverified: unverified };
  }

  var EXPLAIN = {
    leak: 'WebRTC exposed an address that is different from the one websites see. If you are on a VPN, that is your real address escaping the tunnel.',
    unverified: 'WebRTC exposed an address in an IP family (usually IPv6) this page could not check your normal address for, so it cannot say whether it is a leak.',
    same: 'WebRTC exposed only the address websites already see, so nothing extra is revealed.',
    'nothing-exposed': 'WebRTC exposed no public address. The browser is hiding local addresses behind mDNS names, or WebRTC is routed through the tunnel.',
    unsupported: 'WebRTC is not available in this browser, so nothing can leak through it.'
  };

  /* ---------------- Browser: gather candidates ---------------- */

  /**
   * Gather ICE candidates in the browser. Resolves to
   *   { supported: false } or
   *   { supported: true, candidates: [parsed], raw: [strings], publicAddresses, counts }
   * Nothing is sent anywhere except the STUN binding request to the STUN server.
   */
  function gather(opts) {
    opts = opts || {};
    var RTC = typeof RTCPeerConnection !== 'undefined' ? RTCPeerConnection
      : (typeof webkitRTCPeerConnection !== 'undefined' ? webkitRTCPeerConnection : null);   // eslint-disable-line no-undef
    if (!RTC) return Promise.resolve({ supported: false });
    var stun = opts.stun === undefined ? DEFAULT_STUN : opts.stun;
    var timeout = opts.timeout || 4000;

    return new Promise(function (resolve) {
      var raw = [], done = false, pc;
      function finish() {
        if (done) return;
        done = true;
        try { pc.close(); } catch (e) { /* already closed */ }
        var parsed = raw.map(parseCandidate).filter(Boolean);
        var s = summarize(parsed);
        resolve({ supported: true, candidates: parsed, raw: raw, publicAddresses: s.publicAddresses, counts: s.counts });
      }
      try {
        pc = new RTC({ iceServers: stun ? [{ urls: stun }] : [] });
      } catch (e) {
        return resolve({ supported: false });
      }
      pc.createDataChannel('leak-check');
      pc.onicecandidate = function (e) {
        if (!e.candidate) return finish();
        if (e.candidate.candidate) raw.push(e.candidate.candidate);
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(finish);
      setTimeout(finish, timeout);
    });
  }

  /**
   * Convenience: gather, then compare against the HTTP address(es) you supply.
   * Getting the HTTP address is up to you (any "what is my IP" endpoint works);
   * this library deliberately makes no requests of its own besides STUN.
   */
  function check(http, opts) {
    return gather(opts).then(function (g) {
      var v = verdict(g.supported ? g.publicAddresses : null, http);
      v.explanation = EXPLAIN[v.result];
      v.gathered = g;
      return v;
    });
  }

  return {
    DEFAULT_STUN: DEFAULT_STUN,
    EXPLAIN: EXPLAIN,
    parseIPv4: parseIPv4,
    parseIPv6: parseIPv6,
    canonical: canonical,
    sameIP: sameIP,
    scope: scope,
    parseCandidate: parseCandidate,
    summarize: summarize,
    verdict: verdict,
    gather: gather,
    check: check
  };
});
