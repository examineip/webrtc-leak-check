# webrtc-leak-check

Find out whether **WebRTC exposes an IP address that websites can't already see** — without the false
alarms most "WebRTC leak tests" raise.

One dependency-free file. `gather()` runs in the browser; the parsing and the verdict are pure functions
that also run in Node, which is how they're tested. It powers the WebRTC part of the
[VPN Leak Test on ExamineIP](https://tools.examineip.com/vpn-leak-test/).

```js
// You supply the address websites see over HTTP — from any "what is my IP" endpoint.
const res = await webrtcLeakCheck.check({ ipv4: '203.0.113.7', ipv6: null });

res.result;       // 'leak' | 'same' | 'nothing-exposed' | 'unverified' | 'unsupported'
res.explanation;  // one plain-English sentence
res.leaked;       // public addresses WebRTC exposed that differ from the HTTP address
```

---

## Why another leak test

A WebRTC "leak" means one thing: WebRTC reveals a public address that is **different** from the one
the website already sees — typically your real address escaping a VPN tunnel. Most leak tests get this
wrong in the same few ways:

| Common mistake | Result | What this library does |
|---|---|---|
| Counting `….local` mDNS names as addresses | Everyone on a modern browser "leaks" | mDNS candidates are recognised and never counted |
| Counting private LAN addresses (192.168.x.x) | Alarming but harmless — sites can't use them | Classified by scope; only **public** addresses count |
| Regex-hunting for anything IP-shaped in the candidate line | Picks up `raddr` fields and junk | Parses the candidate fields per RFC 8839 |
| "WebRTC shows an IP" = leak | A user with no VPN is told they're leaking the address the site already has | Compared with the HTTP address: same address → `same`, not `leak` |
| Comparing an IPv6 WebRTC address with an IPv4 HTTP address | Every IPv6 user "leaks" | Only compared within the same IP family; unknown → `unverified` |
| String comparison of IPv6 | `2001:db8::1` ≠ `2001:0db8:0:0:0:0:0:1` | Canonical comparison (IPv4-mapped included) |

Carrier-grade NAT (100.64.0.0/10), link-local, unique-local and multicast ranges are all classified as
non-public.

---

## Results

| `result` | Meaning |
|---|---|
| `leak` | WebRTC exposed a public address that differs from the HTTP address for that IP family |
| `same` | WebRTC exposed only the address websites already see — nothing extra revealed |
| `nothing-exposed` | No public address at all (mDNS masking, or WebRTC routed through the tunnel) |
| `unverified` | WebRTC exposed an address in an IP family you didn't supply an HTTP address for |
| `unsupported` | No WebRTC in this browser, so nothing can leak through it |

`leak` wins over `unverified`: if one address is a proven leak, that's the answer.

---

## API

| Function | Where | Does |
|---|---|---|
| `check(http, opts)` | browser | `gather()` then `verdict()`, plus `explanation` and the raw `gathered` data |
| `gather({ stun, timeout })` | browser | Collects ICE candidates. Default STUN `stun:stun.l.google.com:19302`, 4 s timeout. Pass `stun: null` for host candidates only |
| `verdict(publicAddresses, { ipv4, ipv6 })` | anywhere | The comparison above — pure |
| `parseCandidate(line)` | anywhere | `{ address, port, protocol, type, mdns, scope, relatedAddress, … }` or `null` |
| `summarize(candidates)` | anywhere | Distinct public addresses + counts of public / private / mDNS |
| `scope(ip)` | anywhere | `public`, `private`, `cgnat`, `loopback`, `link-local`, `unique-local`, `unspecified`, `reserved` |
| `canonical(ip)` / `sameIP(a, b)` | anywhere | IPv4/IPv6 normalisation and comparison |

The library makes **no requests of its own** except the STUN binding request inside `gather()`. Getting
the HTTP address is up to you, so you choose the endpoint and nothing is sent anywhere you didn't pick.

```html
<script src="webrtc-leak-check.js"></script>
<script>
  webrtcLeakCheck.check({ ipv4: myIPv4, ipv6: myIPv6 }).then(r => console.log(r.result));
</script>
```

[`demo.html`](demo.html) is a complete working page (it uses ipify for the HTTP address).

---

## What it can't tell you

- **DNS leaks.** A real DNS leak test needs nameservers you control and randomised hostnames; a browser
  alone can't do it, and tests that claim to (by querying a public resolver) only ever see that resolver.
- **Whether the HTTP address is a VPN.** Telling a VPN exit from a home line needs IP-intelligence data
  (ASN, hosting/proxy flags) — not something a WebRTC check can know. The full
  [VPN Leak Test](https://tools.examineip.com/vpn-leak-test/) does that part server-side.
- **Other apps.** It tests this browser only. Desktop apps and the OS can route around a VPN differently.

---

## Tests

```
node tests/run.js
```

- Candidate parsing against real Chrome and Firefox candidate shapes (host, mDNS, srflx with `raddr`, IPv6)
- Scope classification for every special range, IPv4 and IPv6
- Every verdict path, including the IPv4/IPv6 family rules
- **854 IPv6 canonicalisation cases generated by Python's `ipaddress`** — an independent implementation.
  CI regenerates them and fails if they drift from the committed `tests/vectors.json`.

CI runs on Node 18, 20 and 22.

---

## Licence

MIT — see [LICENSE](LICENSE).

Built by [ExamineIP](https://examineip.com/). Plain-English background:
[WebRTC leaks explained](https://examineip.com/webrtc-leak-test/) ·
[Does a VPN hide your IP?](https://examineip.com/does-a-vpn-hide-your-ip-address/)
