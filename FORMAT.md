# GoTapline capture format v1

Normative on-disk spec. Write a reader against this document.

All integers are **little-endian** unless stated otherwise. A file is one
`Header` followed by an unbounded sequence of `Record`s. It is append-only and
streamable: you may follow a file that is still being written, and a file cut
short by a crash stays readable up to its last intact record.

## Header — 48 bytes, exactly once

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | `47 4F 54 41 50 4C 4E 00` (`"GOTAPLN\0"`) |
| 8 | 2 | version | `1` |
| 10 | 2 | headerLen | `48`. If a future version is larger, skip `headerLen` bytes |
| 12 | 4 | flags | reserved, `0` |
| 16 | 8 | wallNs | int64 wall clock at t0, Unix nanoseconds |
| 24 | 8 | monoNs | int64 monotonic base at t0. Always `0` in v1 |
| 32 | 4 | pid | writer process id |
| 36 | 12 | reserved | zero |

## Record

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | recLen | uint32, bytes **after** this field |
| 4 | 8 | seq | uint64, starts at 1, strictly increasing, no gaps |
| 12 | 8 | tRelNs | int64 nanoseconds since t0 — **the timeline** |
| 20 | 1 | type | see below |
| 21 | 1 | dir | `0` c2s, `1` s2c, `2` not directional |
| 22 | 2 | flags | reserved, `0` |
| 24 | 4 | flowID | uint32; `0` for records not tied to a flow |
| 28 | 4 | payLen | uint32 |
| 32 | payLen | payload | |
| 32+payLen | 4 | crc32c | Castagnoli, over bytes `[0, 32+payLen)` — **includes recLen** |

So `recLen == 28 + payLen + 4`.

Types: `1` FLOW_OPEN · `2` DATA · `3` FLOW_CLOSE · `4` META.

Absolute time of a record is `wallNs + tRelNs`. Timestamps come from a
monotonic clock, so a wall-clock adjustment mid-capture cannot reorder records
or distort intervals; only the anchor in the header is wall time.

## FLOW_OPEN payload

Self-describing, so a reader needs nothing out of band.

```
proto      u8      1 = tcp, 2 = udp
mode       u8      1 = raw, 2 = tls-plaintext, 3 = tls-opaque
clientLen  u8   + client address, ASCII "host:port"
remoteLen  u8   + remote address, ASCII "host:port"
sniLen     u16  + SNI / Host, may be empty
```

`mode` tells you what subsequent DATA on that flow means:

- `raw` — bytes exactly as they crossed the wire. UDP flows are always raw, and
  each DATA record is **one whole datagram** with the SOCKS5 UDP header already
  stripped. Datagram boundaries are therefore preserved exactly.
- `tls-plaintext` — TLS was terminated; DATA is decrypted application data.
  Records are read-sized chunks of a **byte stream**, so they carry no message
  framing: reassemble per flow and direction before parsing.
- `tls-opaque` — TLS was tunnelled untouched. DATA appears only if the capture
  ran with `-record-opaque`, and is ciphertext.

## DATA payload

Raw bytes, no interpretation. The capture layer deliberately does not decode
application semantics.

## META payload

UTF-8 text. Emitted at start and stop with the run's configuration.

## Reading rules

1. Verify the magic and version; skip `headerLen` bytes total.
2. Loop: read `recLen`; if fewer than 4 bytes remain, stop cleanly.
3. Reject and stop if `recLen < 32` or implausibly large (the writer caps a
   payload at 64 MiB).
4. Read `recLen` bytes; a short read means the file was truncated — stop.
5. Verify crc32c over `recLen ++ body[:len-4]`. A mismatch means corruption —
   stop; do not skip ahead.
6. Treat "stopped early" as normal. A capture killed with SIGKILL ends
   mid-record by design; everything before that point is valid.

Because every record is length-prefixed and checksummed, a reader never has to
guess. Stopping at the first bad record is the correct behaviour: the file is
append-only, so nothing valid can follow something invalid.

## Worked example

A minimal UDP capture, annotated:

```
47 4F 54 41 50 4C 4E 00   magic
01 00  30 00              version 1, headerLen 48
00 00 00 00               flags
.. .. .. .. .. .. .. ..   wallNs
00 00 00 00 00 00 00 00   monoNs
.. .. .. ..               pid
00 x12                    reserved

-- FLOW_OPEN --
3D 00 00 00               recLen = 61
01 00 00 00 00 00 00 00   seq = 1
.. x8                     tRelNs
01                        type = FLOW_OPEN
02                        dir = none
00 00                     flags
01 00 00 00               flowID = 1
1D 00 00 00               payLen = 29
02 01                     proto = udp, mode = raw
13 "192.168.50.35:52199"  client
11 "14.103.235.2:7200"    remote
00 00                     sniLen = 0
.. .. .. ..               crc32c

-- DATA (one datagram) --
28 00 00 00               recLen = 40
02 00 00 00 00 00 00 00   seq = 2
.. x8                     tRelNs
02                        type = DATA
00                        dir = c2s
00 00                     flags
01 00 00 00               flowID = 1
08 00 00 00               payLen = 8
00 00 00 02 21 BB 0A 5D   payload: a Diarkis SYN wrapper + sid bytes
.. .. .. ..               crc32c
```
