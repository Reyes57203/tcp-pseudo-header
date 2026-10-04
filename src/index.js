/**
 * Public entry point for the tcp-pseudo-header library.
 *
 * Exposes the checksum computation for IPv4 and IPv6 pseudo headers over
 * TCP or UDP segments. All routines are pure and allocation-free aside
 * from the small fixed buffers required for the pseudo header itself.
 */
import {
  computeChecksum,
  tcpChecksumIPv4,
  tcpChecksumIPv6,
  udpChecksumIPv4,
  udpChecksumIPv6,
  HEADER_TCP,
  HEADER_UDP,
} from './core.js';

export {
  computeChecksum,
  tcpChecksumIPv4,
  tcpChecksumIPv6,
  udpChecksumIPv4,
  udpChecksumIPv6,
  HEADER_TCP,
  HEADER_UDP,
};
