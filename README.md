# GoTapline

A capturing SOCKS5 proxy that records **UDP datagrams and decrypted TLS in one
file on one timeline**. Built for capturing an iOS/iPadOS device through
Shadowrocket.

The problem it solves: capturing UDP with one tool and HTTPS with another leaves
two files on two clocks that cannot be reliably interleaved. Here both
transports pass through a single process and are stamped from a single monotonic
clock under a single lock, so the recorded order *is* the real order.

Zero third-party dependencies — standard library only.

## Scope

The capture layer does exactly two things: **store raw bytes** and **remove
TLS**. It does not interpret payloads — no HTTP body decoding, no application
crypto, no protocol dissection. Semantic decoding belongs in a separate reader
built against [`FORMAT.md`](FORMAT.md).

`tapdump` is a reference reader that renders the timeline, included to prove the
format round-trips and to give a starting point.

## Build

```sh
go build ./cmd/tapline
go build ./cmd/tapdump
```

## Run

```sh
./tapline -out run.tap -mitm api.example.com
```

`-mitm` may be repeated and may carry a comma-separated list, and the two forms
combine, so these are equivalent:

```sh
./tapline -mitm "a.example.com,*.b.example.com"
./tapline -mitm a.example.com -mitm "*.b.example.com"
```

Startup prints the CA path, its SHA-256, and the address advertised for UDP
relay. Stop with Ctrl-C; the capture is flushed and fsynced so the file always
ends on a record boundary.

Useful flags:

| Flag | Purpose |
|---|---|
| `-listen :1080` | SOCKS5 listen address |
| `-mitm a.com,*.b.com` | SNI name to decrypt. **Repeatable**, and accepts a comma-separated list; the two forms combine. Empty means decrypt nothing |
| `-advertise 192.168.50.10` | IP handed to clients for UDP relay; auto-detected by default |
| `-allow-h2` | offer HTTP/2 when intercepting (see the caveat below) |
| `-record-opaque` | also store ciphertext of connections that were not decrypted |
| `-print-ca` | print the CA path and fingerprint, then exit |

## Device setup (iPad + Shadowrocket)

1. **Install the CA.** Serve `~/.tapline/ca.pem` to the device (AirDrop, or
   `python3 -m http.server` and open the URL in Safari), install the profile,
   then enable it under **Settings → General → About → Certificate Trust
   Settings**. That second step is separate and easy to miss.
2. **Point Shadowrocket at this host**: add a **SOCKS5** server with your Mac's
   LAN IP and port 1080, and enable UDP for it.
3. **Turn OFF Shadowrocket's own HTTPS decryption.** Decryption happens here,
   not there; leaving both on will not work.
4. Add a rule so QUIC falls back to TCP, and make sure it does not swallow the
   UDP you actually want:

   ```
   AND,((PROTOCOL,UDP),(DST-PORT,7200)),PROXY
   AND,((PROTOCOL,UDP),(DST-PORT,443)),REJECT-NO-DROP
   FINAL,PROXY
   ```

   Never blanket-reject UDP — that kills the traffic you came for.

Trusting the CA is unavoidable for TLS interception. Moving decryption off the
device changes *where* plaintext appears, not whether the device must accept the
certificate.

## Reading a capture

```sh
./tapdump run.tap                 # whole timeline
./tapdump -udp run.tap            # UDP flows only
./tapdump -flow 3 run.tap         # one flow
./tapdump -stats run.tap          # summary only
./tapdump -rel -bytes 0 run.tap   # relative time, headers only
```

## Design notes

**Interception is selective, by SNI.** Only allowlisted names are terminated;
everything else is a pure byte tunnel that never sees our certificate. This is
what lets certificate-pinned hosts keep working — intercept them and the app
fails closed. `TestPinnedHostIsNotIntercepted` asserts this property.

**ALPN is `http/1.1` only by default.** iOS apps negotiate HTTP/2, and h2
plaintext is HPACK-compressed binary frames — a reader would need a full HPACK
implementation to read it. Offering only `http/1.1` makes clients downgrade, so
what lands on disk is plainly readable. `-allow-h2` restores h2 if you need to
observe it specifically.

**The upstream TLS session reuses the socket from CONNECT** rather than
re-resolving the hostname, so the capture always reflects the host the client
actually asked for.

**UDP ASSOCIATE advertises a routable address.** Replying with `0.0.0.0` or a
loopback address makes a remote device send datagrams to itself, which fails
silently. Auto-detection refuses to advertise loopback; pass `-advertise` when
it cannot tell.

**Datagram boundaries are preserved.** One UDP DATA record is exactly one
datagram. TLS flows are byte streams and carry no framing, so reassemble per
flow and direction before parsing.

## Tests

```sh
go test ./...
```

- `internal/tapfile` — round-trip, truncation tolerance, corruption detection,
  and the ordering invariant under 16 concurrent writers.
- `internal/socks` — an end-to-end run driving TLS and UDP through the proxy
  simultaneously against local origins, then asserting the capture contains
  decrypted HTTP *and* both UDP directions in one consistent timeline; plus the
  pass-through safety property.
