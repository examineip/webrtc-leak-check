"""Generate IPv6 canonicalisation vectors from Python's ipaddress module, an
independent implementation, so the JS parser is checked against a reference.
Run with --check to fail if tests/vectors.json is out of date."""
import ipaddress, json, random, sys, pathlib

def want(a):
    """Exploded form, except IPv4-mapped addresses, which compare as plain IPv4."""
    return str(a.ipv4_mapped) if a.ipv4_mapped else a.exploded

rng = random.Random(20260918)
out = []
for _ in range(400):
    a = ipaddress.IPv6Address(rng.getrandbits(128) & rng.choice([
        (1 << 128) - 1,                       # anything
        ((1 << 128) - 1) ^ ((1 << 64) - 1),   # zero low half -> "::" compression
        (1 << 64) - 1,                        # zero high half
        0xffff << 96 | ((1 << 96) - 1),       # sparse
    ]))
    out.append({"in": a.compressed, "want": want(a)})
    out.append({"in": a.exploded.upper(), "want": want(a)})
for s in ["::", "::1", "fe80::1", "2001:db8::", "::ffff:0:0", "1::", "::2:3:4:5:6:7:8"]:
    out.append({"in": s, "want": want(ipaddress.IPv6Address(s))})
# IPv4-mapped addresses compare as their IPv4 form
for _ in range(40):
    v4 = ipaddress.IPv4Address(rng.getrandbits(32))
    out.append({"in": "::ffff:" + str(v4), "want": str(v4)})
bad = ["1:2:3:4:5:6:7:8:9", "1::2::3", "12345::", "g::1", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "::ffff:1.2.3.256"]
for s in bad:
    try:
        ipaddress.IPv6Address(s); raise SystemExit("expected invalid: " + s)
    except ValueError:
        out.append({"in": s, "want": None})

path = pathlib.Path(__file__).with_name("vectors.json")
text = json.dumps(out, indent=0) + "\n"
if "--check" in sys.argv:
    if path.read_text() != text:
        raise SystemExit("vectors.json is out of date - regenerate it")
    print("vectors.json matches ipaddress:", len(out), "cases")
else:
    path.write_text(text)
    print("wrote", len(out), "vectors")
