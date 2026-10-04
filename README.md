# tcp-pseudo-header

Compute the TCP or UDP Internet checksum over an IPv4 or IPv6 pseudo header
and a caller-supplied segment buffer. Pure functions, no dependencies, no
allocation beyond the small pseudo-header buffer.

## Usage

```js
import {
  tcpChecksumIPv4,
  udpChecksumIPv6,
} from 'tcp-pseudo-header';

const srcIp = new Uint8Array([192, 168, 1, 10]);
const dstIp = new Uint8Array([192, 168, 1, 20]);
const segment = new Uint8Array(20); // your TCP header + payload

const cksum = tcpChecksumIPv4(srcIp, dstIp, segment);
// Write cksum into bytes 16..17 of the TCP header.
```

## Exports

- `computeChecksum(bytes: Uint8Array): number` — RFC 1071 ones'-complement
  sum over a raw byte buffer. Pads odd-length input with a trailing zero byte.
- `tcpChecksumIPv4(srcIp, dstIp, segment): number` — 4-byte IPv4 addresses,
  full TCP segment.
- `udpChecksumIPv4(srcIp, dstIp, datagram): number` — 4-byte IPv4 addresses,
  full UDP datagram.
- `tcpChecksumIPv6(srcIp, dstIp, segment): number` — 16-byte IPv6 addresses,
  full TCP segment.
- `udpChecksumIPv6(srcIp, dstIp, datagram): number` — 16-byte IPv6 addresses,
  full UDP datagram.
- `HEADER_TCP` (6), `HEADER_UDP` (17) — protocol numbers used internally,
  exported for callers building their own headers.

All address arguments are `Uint8Array` and validated for length (4 bytes for
IPv4, 16 bytes for IPv6). Return values are unsigned 16-bit integers
(`0x0000`–`0xFFFF`).

## Why this exists

The transport-layer checksum covers a pseudo header derived from the IP layer
so that a receiver can detect misdelivery, not just bit errors. Building that
pseudo header by hand is mechanical but error-prone — the IPv4 layout uses a
16-bit length field, IPv6 uses a 32-bit length field, and the protocol number
sits in a different byte position in each. This library encodes those layouts
once.

The trade-off: the library computes the mathematical checksum only. It does
not parse IP or TCP headers, does not write the checksum back into a segment,
and does not remap a zero UDP-over-IPv4 result to `0xFFFF`. Callers handle
those policy steps. Keeping the scope narrow means the functions are
trivially composable and have no hidden state.

## The awkward edge

A computed checksum of `0x0000` is valid and means "everything checked out."
For UDP over IPv4, RFC 768 lets a transmitter send `0x0000` in the header to
mean "no checksum was computed," so a real zero must be transmitted as
`0xFFFF`. For UDP over IPv6, the option does not exist and `0x0000` must
always be remapped to `0xFFFF`. Both `udpChecksumIPv4` and `udpChecksumIPv6`
return the raw mathematical value and leave that remap to the caller —
handling it inside the library would make TCP results inconsistent.

## Running the tests

```
node --test
```
