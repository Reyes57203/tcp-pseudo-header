/**
 * IPv4/IPv6 pseudo-header checksum computation for TCP and UDP segments.
 *
 * The Internet checksum (RFC 1071) is the ones' complement of the ones'
 * complement sum of all 16-bit words in a block of data. For TCP (RFC 793)
 * and UDP (RFC 768), the "block" conceptually includes a pseudo header
 * derived from the IP header so that a receiver can confirm the segment
 * belongs to the expected flow and was not misdelivered.
 *
 * This module builds that pseudo header in memory, concatenates it with the
 * caller-supplied segment buffer, and folds the sum into a single 16-bit
 * value. UDP permits a zero checksum to mean "not computed" (RFC 768), and
 * IPv6 requires the checksum length field to be a 32-bit value (RFC 2460) —
 * both handled below.
 */

/** Header protocol number for TCP (RFC 790). */
export const HEADER_TCP = 6;
/** Header protocol number for UDP (RFC 790). */
export const HEADER_UDP = 17;

/**
 * Compute the Internet checksum (RFC 1071) of a given byte sequence.
 *
 * The algorithm sums all 16-bit big-endian words, carrying any overflow
 * back into the low-order bits, and returns the ones' complement. A result
 * of 0xFFFF means every bit was already accounted for; for UDP over IPv4
 * the caller is responsible for deciding whether to transmit 0xFFFF or to
 * remap it to 0x0000 (see RFC 768) — this routine performs only the math.
 *
 * An odd-length input is padded with a single trailing zero byte, as
 * required by RFC 1071 §1.2. This is the only deviation from a literal
 * reading of the buffer, and it never mutates the caller's array.
 *
 * @param {Uint8Array} bytes - data to checksum
 * @returns {number} the 16-bit checksum as an unsigned integer (0x0000..0xFFFF)
 */
export function computeChecksum(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError('bytes must be a Uint8Array');
  }

  let sum = 0;
  const len = bytes.length;
  const limit = len - (len & 1); // even cutoff, leaves the last odd byte if present

  for (let i = 0; i < limit; i += 2) {
    sum += (bytes[i] << 8) | bytes[i + 1];
  }

  if (limit !== len) {
    // Trailing odd byte: RFC 1071 §1.2 mandates a zero pad on the right.
    sum += bytes[len - 1] << 8;
  }

  // Fold high-order carry bits back into the low-order 16 bits.
  // Two iterations suffice for any 32-bit accumulator of 16-bit words.
  sum = (sum & 0xffff) + (sum >>> 16);
  sum = (sum & 0xffff) + (sum >>> 16);

  return (~sum) & 0xffff;
}

/**
 * Compute the TCP checksum over an IPv4 pseudo header.
 *
 * @param {Uint8Array} srcIp - 4-byte IPv4 source address
 * @param {Uint8Array} dstIp - 4-byte IPv4 destination address
 * @param {Uint8Array} segment - full TCP segment (header + body)
 * @returns {number} 16-bit checksum
 */
export function tcpChecksumIPv4(srcIp, dstIp, segment) {
  return checksumIPv4(srcIp, dstIp, segment, HEADER_TCP);
}

/**
 * Compute the UDP checksum over an IPv4 pseudo header.
 *
 * @param {Uint8Array} srcIp - 4-byte IPv4 source address
 * @param {Uint8Array} dstIp - 4-byte IPv4 destination address
 * @param {Uint8Array} datagram - full UDP datagram (header + body)
 * @returns {number} 16-bit checksum
 */
export function udpChecksumIPv4(srcIp, dstIp, datagram) {
  return checksumIPv4(srcIp, dstIp, datagram, HEADER_UDP);
}

/**
 * Compute the TCP checksum over an IPv6 pseudo header (RFC 2460 §8.1).
 *
 * @param {Uint8Array} srcIp - 16-byte IPv6 source address
 * @param {Uint8Array} dstIp - 16-byte IPv6 destination address
 * @param {Uint8Array} segment - full TCP segment (header + body)
 * @returns {number} 16-bit checksum
 */
export function tcpChecksumIPv6(srcIp, dstIp, segment) {
  return checksumIPv6(srcIp, dstIp, segment, HEADER_TCP);
}

/**
 * Compute the UDP checksum over an IPv6 pseudo header (RFC 2460 §8.1).
 *
 * IPv6 forbids the UDP "no checksum" shortcut: a computed zero MUST be
 * transmitted as 0xFFFF. This function returns the raw mathematical value;
 * the caller is expected to map 0x0000 to 0xFFFF when writing the header.
 *
 * @param {Uint8Array} srcIp - 16-byte IPv6 source address
 * @param {Uint8Array} dstIp - 16-byte IPv6 destination address
 * @param {Uint8Array} datagram - full UDP datagram (header + body)
 * @returns {number} 16-bit checksum
 */
export function udpChecksumIPv6(srcIp, dstIp, datagram) {
  return checksumIPv6(srcIp, dstIp, datagram, HEADER_UDP);
}

/**
 * Build the IPv4 pseudo header, append the segment, and checksum the whole.
 * The pseudo header layout (RFC 793 §3.1) is:
 *   src (4) | dst (4) | zero (1) | proto (1) | tcp-length (2)
 */
function checksumIPv4(srcIp, dstIp, segment, proto) {
  if (!(srcIp instanceof Uint8Array) || srcIp.length !== 4) {
    throw new TypeError('srcIp must be a 4-byte Uint8Array');
  }
  if (!(dstIp instanceof Uint8Array) || dstIp.length !== 4) {
    throw new TypeError('dstIp must be a 4-byte Uint8Array');
  }
  if (!(segment instanceof Uint8Array)) {
    throw new TypeError('segment must be a Uint8Array');
  }

  const pseudo = new Uint8Array(12 + segment.length);
  pseudo.set(srcIp, 0);
  pseudo.set(dstIp, 4);
  pseudo[8] = 0;
  pseudo[9] = proto;
  const segLen = segment.length;
  pseudo[10] = (segLen >>> 8) & 0xff;
  pseudo[11] = segLen & 0xff;
  pseudo.set(segment, 12);

  return computeChecksum(pseudo);
}

/**
 * Build the IPv6 pseudo header, append the segment, and checksum the whole.
 * The pseudo header layout (RFC 2460 §8.1) is:
 *   src (16) | dst (16) | upper-layer-len (4) | zeros (3) | next-header (1)
 *
 * The length field is 32 bits here (not 16 as in IPv4) because IPv6 jumbograms
 * can exceed 65535 bytes. The next-header field carries the upper-layer
 * protocol number, not the IPv6 next-header chain value — callers pass the
 * final transport protocol (TCP or UDP).
 */
function checksumIPv6(srcIp, dstIp, segment, proto) {
  if (!(srcIp instanceof Uint8Array) || srcIp.length !== 16) {
    throw new TypeError('srcIp must be a 16-byte Uint8Array');
  }
  if (!(dstIp instanceof Uint8Array) || dstIp.length !== 16) {
    throw new TypeError('dstIp must be a 16-byte Uint8Array');
  }
  if (!(segment instanceof Uint8Array)) {
    throw new TypeError('segment must be a Uint8Array');
  }

  const pseudo = new Uint8Array(40 + segment.length);
  pseudo.set(srcIp, 0);
  pseudo.set(dstIp, 16);
  const segLen = segment.length;
  // 32-bit length, big-endian. Segment lengths above 2^32 are not representable
  // in a typed-array view, so we drop the upper half silently — it is always
  // zero for any buffer JavaScript can actually allocate.
  pseudo[32] = (segLen >>> 24) & 0xff;
  pseudo[33] = (segLen >>> 16) & 0xff;
  pseudo[34] = (segLen >>> 8) & 0xff;
  pseudo[35] = segLen & 0xff;
  pseudo[36] = 0;
  pseudo[37] = 0;
  pseudo[38] = 0;
  pseudo[39] = proto;
  pseudo.set(segment, 40);

  return computeChecksum(pseudo);
}
