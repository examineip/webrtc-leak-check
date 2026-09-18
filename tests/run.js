'use strict';
const lib = require('../webrtc-leak-check.js');
const vectors = require('./vectors.json');

let pass = 0, fail = 0;
function eq(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) pass++;
  else { fail++; console.log('FAIL ' + name + '\n  got  ' + g + '\n  want ' + w); }
}

// --- IPv6 canonicalisation vs Python's ipaddress (tests/vectors.json) ---
let vfail = 0;
for (const v of vectors) {
  const got = lib.canonical(v.in);
  if (got !== v.want) { vfail++; if (vfail < 10) console.log('FAIL vector', v.in, '->', got, 'want', v.want); }
}
eq('ipaddress vectors (' + vectors.length + ')', vfail, 0);

// --- IPv4 ---
eq('v4 ok', lib.canonical('203.0.113.7'), '203.0.113.7');
eq('v4 >255', lib.canonical('203.0.113.256'), null);
eq('not an ip', lib.canonical('abcd.local'), null);
eq('mapped equals v4', lib.sameIP('::ffff:203.0.113.7', '203.0.113.7'), true);
eq('compressed equals expanded', lib.sameIP('2001:db8::1', '2001:0DB8:0:0:0:0:0:0001'), true);

// --- scope ---
const scopes = {
  '8.8.8.8': 'public', '10.1.2.3': 'private', '172.16.0.1': 'private', '172.32.0.1': 'public',
  '192.168.1.10': 'private', '100.64.0.1': 'cgnat', '100.128.0.1': 'public', '127.0.0.1': 'loopback',
  '169.254.10.1': 'link-local', '0.0.0.0': 'unspecified', '224.0.0.251': 'reserved',
  '2a02:4780::1': 'public', 'fe80::1': 'link-local', 'fd12:3456::1': 'unique-local', 'fc00::1': 'unique-local',
  '::1': 'loopback', '::': 'unspecified', 'ff02::fb': 'reserved', '::ffff:10.0.0.1': 'private'
};
for (const [ip, want] of Object.entries(scopes)) eq('scope ' + ip, lib.scope(ip), want);

// --- candidate parsing (real-world shapes from Chrome and Firefox) ---
const host4 = lib.parseCandidate('candidate:842163049 1 udp 1677729535 192.168.1.23 54321 typ host generation 0 ufrag abcd');
eq('host v4 address', host4.address, '192.168.1.23');
eq('host v4 scope', host4.scope, 'private');
eq('host v4 type', host4.type, 'host');

const mdns = lib.parseCandidate('candidate:1 1 udp 2113937151 3f1c7a2e-7b1d-4c2a-9f0e-2b2c8e6a1d44.local 50123 typ host generation 0');
eq('mdns flagged', mdns.mdns, true);
eq('mdns scope', mdns.scope, 'mdns');

const srflx = lib.parseCandidate('a=candidate:3 1 UDP 1686052607 198.51.100.20 61000 typ srflx raddr 0.0.0.0 rport 0 generation 0');
eq('srflx address (not raddr)', srflx.address, '198.51.100.20');
eq('srflx protocol lower-cased', srflx.protocol, 'udp');
eq('srflx raddr kept separately', srflx.relatedAddress, '0.0.0.0');
eq('srflx public', srflx.scope, 'public');

const v6 = lib.parseCandidate('candidate:4 1 udp 2122262783 2001:db8:abcd:12::7 55555 typ host generation 0');
eq('host v6 public', v6.scope, 'public');
eq('garbage', lib.parseCandidate('not a candidate'), null);
eq('empty', lib.parseCandidate(''), null);

// --- summarize: duplicates collapse, harmless kinds are counted, not listed ---
const s = lib.summarize([host4, mdns, srflx, srflx, lib.parseCandidate('candidate:5 1 udp 1 198.51.100.20 1 typ srflx')]);
eq('distinct public', s.publicAddresses, ['198.51.100.20']);
eq('counts', s.counts, { public: 3, private: 1, mdns: 1, other: 0 });

// --- verdict ---
eq('leak', lib.verdict(['198.51.100.20'], { ipv4: '203.0.113.7' }).result, 'leak');
eq('same', lib.verdict(['203.0.113.7'], { ipv4: '203.0.113.7' }).result, 'same');
eq('nothing exposed', lib.verdict([], { ipv4: '203.0.113.7' }).result, 'nothing-exposed');
eq('unsupported', lib.verdict(null, { ipv4: '203.0.113.7' }).result, 'unsupported');
// IPv6 from WebRTC but only IPv4 known over HTTP: not enough to call it a leak
const u = lib.verdict(['2001:db8::7'], { ipv4: '203.0.113.7' });
eq('v6 without http v6 -> unverified', u.result, 'unverified');
eq('unverified list', u.unverified, ['2001:db8::7']);
eq('v6 matches http v6', lib.verdict(['2001:db8::7'], { ipv4: '203.0.113.7', ipv6: '2001:0db8:0:0::7' }).result, 'same');
eq('v6 differs from http v6', lib.verdict(['2001:db8::8'], { ipv6: '2001:db8::7' }).result, 'leak');
eq('leak beats unverified', lib.verdict(['2001:db8::8', '198.51.100.1'], { ipv4: '203.0.113.7' }).result, 'leak');
eq('no http info at all', lib.verdict(['198.51.100.1'], {}).result, 'unverified');

// --- gather() in an environment with no WebRTC ---
lib.gather().then(g => {
  eq('gather without WebRTC', g, { supported: false });
  return lib.check({ ipv4: '203.0.113.7' });
}).then(c => {
  eq('check without WebRTC', c.result, 'unsupported');
  console.log(`${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
});
