import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  computeChecksum,
  tcpChecksumIPv4,
  tcpChecksumIPv6,
  udpChecksumIPv4,
  udpChecksumIPv6,
  HEADER_TCP,
  HEADER_UDP,
} from '../src/index.js';

/**
 * A packet whose checksum is identically zero is the awkward case for the
 * Internet checksum: the ones' complement of an all-ones sum is 0x0000, which
 * for UDP over IPv4 must be transmitted as 0xFFFF. We exercise both branches.
 */

// A classic self-verifying example: a buffer of all 0xFF words sums to 0xFFFF,
// whose ones' complement is 0x0000. This is the canonical "zero checksum"
// state and a useful probe for off-by-one in the fold step.
test('computeChecksum: all-ones buffer yields 0x0000', () => {
  const buf = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
  assert.equal(computeChecksum(buf), 0x0000);
});

// Symmetric counterpart: a zero buffer sums to 0x0000, complement 0xFFFF.
test('computeChecksum: zero buffer yields 0xFFFF', () => {
  const buf = new Uint8Array(8);
  assert.equal(computeChecksum(buf), 0xffff);
});

test('computeChecksum: odd-length buffer pads trailing zero', () => {
  // [0x00, 0x01, 0x02] is padded to [0x00, 0x01, 0x02, 0x00] => words
  // 0x0001 + 0x0200 = 0x0201, complement 0xFEFE. Verifies the odd-byte
  // path uses big-endian placement (the trailing byte becomes the low
  // byte of the final word).
  const buf = new Uint8Array([0x00, 0x01, 0x02]);
  assert.equal(computeChecksum(buf), 0xfdfe);
});

test('computeChecksum: even and odd equivalents match when pad is zero', () => {
  const even = new Uint8Array([0x12, 0x34, 0x56, 0x78]);
  const odd = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x00]);
  assert.equal(computeChecksum(even), computeChecksum(odd));
});

test('computeChecksum: carries fold correctly across many words', () => {
  // Fill 600 bytes with 0xFFFF. The running sum exceeds 16 bits many times;
  // a buggy fold that stops after one iteration will diverge.
  const buf = new Uint8Array(600).fill(0xff);
  assert.equal(computeChecksum(buf), 0x0000);
});

test('computeChecksum: rejects non-Uint8Array input', () => {
  assert.throws(() => computeChecksum([1, 2, 3, 4]), TypeError);
  assert.throws(() => computeChecksum('abcd'), TypeError);
  assert.throws(() => computeChecksum(null), TypeError);
});

// ---- IPv4 TCP ------------------------------------------------------------

test('tcpChecksumIPv4: matches a hand-computed pseudo-header sum', () => {
  // Tiny segment: two bytes, chosen so the whole pseudo header is one tidy
  // 14-byte block we can sum by hand. src/dst are 0.0.0.1 and 0.0.0.2,
  // proto TCP (6), length 2.
  // Words: 0000 0001 0000 0002 0006 0002 0102
  //   sum  = 0x0000+0x0001+0x0000+0x0002+0x0006+0x0002+0x0102 = 0x010D
  //   comp = 0xFEF2
  const src = new Uint8Array([0, 0, 0, 1]);
  const dst = new Uint8Array([0, 0, 0, 2]);
  const seg = new Uint8Array([0x01, 0x02]);
  assert.equal(tcpChecksumIPv4(src, dst, seg), 0xfef2);
});

test('tcpChecksumIPv4: odd-length segment pads internally via computeChecksum', () => {
  const src = new Uint8Array([10, 0, 0, 1]);
  const dst = new Uint8Array([10, 0, 0, 2]);
  const seg = new Uint8Array([0xff, 0xff, 0xff]); // 3 bytes, odd
  // We don't hardcode the magic value; we verify it equals the direct
  // computation over the manually-built pseudo header.
  const pseudo = new Uint8Array(12 + 3);
  pseudo.set(src, 0);
  pseudo.set(dst, 4);
  pseudo[9] = HEADER_TCP;
  pseudo[10] = 0;
  pseudo[11] = 3;
  pseudo.set(seg, 12);
  assert.equal(tcpChecksumIPv4(src, dst, seg), computeChecksum(pseudo));
});

test('tcpChecksumIPv4: validates IP and segment types', () => {
  const goodIp = new Uint8Array(4);
  const goodSeg = new Uint8Array(2);
  assert.throws(() => tcpChecksumIPv4(new Uint8Array(3), goodIp, goodSeg), TypeError);
  assert.throws(() => tcpChecksumIPv4(goodIp, new Uint8Array(5), goodSeg), TypeError);
  assert.throws(() => tcpChecksumIPv4(goodIp, goodIp, [1, 2]), TypeError);
});

// ---- IPv4 UDP ------------------------------------------------------------

test('udpChecksumIPv4: uses UDP protocol number', () => {
  // Identical setup to the TCP hand case but proto 17 (0x11) and the segment
  // is a UDP datagram. Words: 0000 0001 0000 0002 0011 0002 0102
  //   sum  = 0x0000+0x0001+0x0000+0x0002+0x0011+0x0002+0x0102 = 0x0118
  //   comp = 0xFEE7
  const src = new Uint8Array([0, 0, 0, 1]);
  const dst = new Uint8Array([0, 0, 0, 2]);
  const dg = new Uint8Array([0x01, 0x02]);
  assert.equal(udpChecksumIPv4(src, dst, dg), 0xfee7);
});

test('udpChecksumIPv4: distinct from TCP for same segment', () => {
  const src = new Uint8Array([192, 168, 1, 1]);
  const dst = new Uint8Array([192, 168, 1, 2]);
  const seg = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  assert.notEqual(udpChecksumIPv4(src, dst, seg), tcpChecksumIPv4(src, dst, seg));
});

// ---- IPv6 TCP ------------------------------------------------------------

test('tcpChecksumIPv6: 16-byte addresses required', () => {
  const goodIp = new Uint8Array(16);
  const seg = new Uint8Array(4);
  assert.throws(() => tcpChecksumIPv6(new Uint8Array(15), goodIp, seg), TypeError);
  assert.throws(() => tcpChecksumIPv6(goodIp, new Uint8Array(17), seg), TypeError);
});

test('tcpChecksumIPv6: matches manual pseudo-header construction', () => {
  // Loopback-ish addresses and a 4-byte segment. Build the expected pseudo
  // header by hand and compare to computeChecksum over that buffer. This
  // validates the 32-bit length field and next-header placement without
  // pinning a magic constant that future readers would have to recompute.
  const src = new Uint8Array(16);
  src[15] = 1; // ::1
  const dst = new Uint8Array(16);
  dst[15] = 2; // ::2
  const seg = new Uint8Array([0x00, 0x01, 0x02, 0x03]);

  const pseudo = new Uint8Array(40 + seg.length);
  pseudo.set(src, 0);
  pseudo.set(dst, 16);
  pseudo[35] = 4; // lower byte of 32-bit length
  pseudo[39] = HEADER_TCP;
  pseudo.set(seg, 40);

  assert.equal(tcpChecksumIPv6(src, dst, seg), computeChecksum(pseudo));
});

test('tcpChecksumIPv6: differs from IPv4 for equivalent endpoints', () => {
  const v4 = new Uint8Array([127, 0, 0, 1]);
  const v6 = new Uint8Array(16);
  v6[15] = 1;
  const seg = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
  assert.notEqual(tcpChecksumIPv4(v4, v4, seg), tcpChecksumIPv6(v6, v6, seg));
});

// ---- IPv6 UDP ------------------------------------------------------------

test('udpChecksumIPv6: matches manual pseudo-header construction', () => {
  const src = new Uint8Array(16);
  const dst = new Uint8Array(16);
  dst[15] = 9;
  const dg = new Uint8Array([0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

  const pseudo = new Uint8Array(40 + dg.length);
  pseudo.set(src, 0);
  pseudo.set(dst, 16);
  pseudo[35] = dg.length;
  pseudo[39] = HEADER_UDP;
  pseudo.set(dg, 40);

  assert.equal(udpChecksumIPv6(src, dst, dg), computeChecksum(pseudo));
});

test('udpChecksumIPv6: large length is encoded across 32 bits', () => {
  // 300-byte datagram: length 0x0000012C must occupy pseudo[32..35], with
  // the non-zero bytes at pseudo[34] (0x01) and pseudo[35] (0x2C). Compare
  // against a hand-built header.
  const src = new Uint8Array(16);
  const dst = new Uint8Array(16);
  const dg = new Uint8Array(300).fill(0xab);

  const pseudo = new Uint8Array(40 + dg.length);
  pseudo.set(src, 0);
  pseudo.set(dst, 16);
  pseudo[34] = 0x01; // 0x012C >>> 8 within the 32-bit length field
  pseudo[35] = 0x2c;
  pseudo[39] = HEADER_UDP;
  pseudo.set(dg, 40);

  assert.equal(udpChecksumIPv6(src, dst, dg), computeChecksum(pseudo));
});
