/*  Copyright (C) 2011-2026  P.D. Buchan (pdbuchan@gmail.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Send an IPv6 ICMP neighbor solicitation packet.
// Change hoplimit and specify interface using ancillary
// data method.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netinet/icmp6.h>    // struct nd_neighbor_solicit, which contains icmp6_hdr, ND_NEIGHBOR_SOLICIT
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip6.h>      // struct ip6_hdr
#include <arpa/inet.h>        // inet_ntop()
#include <netdb.h>            // struct addrinfo
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/socket.h>      // structs msghdr and cmsghdr
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno, perror()

// Define some constants.
#define SLLA_OPTLEN 8         // Source Link-Layer Address option length.
#define TEXT_STRINGLEN 80     // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp6_checksum (struct ip6_hdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, sd, status, ifindex, cmsglen, hoplimit;
  ssize_t bytes;
  struct addrinfo hints;
  struct addrinfo *res;
  struct sockaddr_in6 *ipv6, src, dst, dst_snmc;
  struct ip6_hdr iphdr;
  struct nd_neighbor_solicit nshdr;
  struct msghdr msghdr;
  struct ifreq ifr;
  struct cmsghdr *cmsghdr1, *cmsghdr2;
  struct in6_pktinfo *pktinfo;
  struct iovec iov;
  char *target, *source, *interface;
  void *tmp;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&nshdr, 0, sizeof (nshdr));
  memset (&msghdr, 0, sizeof (msghdr));

  // Allocate memory for various arrays.
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (TEXT_STRINGLEN);  // Can be hostname or IPv6 address.
  source = allocate_strmem (INET6_ADDRSTRLEN);

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Source IPv6 unicast address of the node sending the solicitation.
  // You need to fill this out.
  snprintf (source, INET6_ADDRSTRLEN, "2001:db8::214:51ff:fe2f:1556");

  // Target hostname or IPv6 address of the node whose link-layer address we're trying to resolve.
  // You need to fill this out.
  snprintf (target, TEXT_STRINGLEN, "target");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = 0;  // Address resolution only; any socket type.
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (source, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for source.\nError message: %s\n", gai_strerror (status));
    return (EXIT_FAILURE);
  }
  memset (&src, 0, sizeof (src));
  memcpy (&src, res->ai_addr, res->ai_addrlen);
  freeaddrinfo (res);

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  memset (&dst, 0, sizeof (dst));
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  memset (&dst_snmc, 0, sizeof (dst_snmc));
  memcpy (&dst_snmc, res->ai_addr, res->ai_addrlen); 

  // Report target's unicast address.
  ipv6 = (struct sockaddr_in6 *) res->ai_addr;
  tmp = &(ipv6->sin6_addr);
  memset (target, 0, INET6_ADDRSTRLEN * sizeof (char));
  if (inet_ntop (AF_INET6, tmp, target, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target's unicast address.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "Target unicast IPv6 address: %s\n", target);
  freeaddrinfo (res);

  // Convert target's IPv6 unicast address to solicited-node multicast address.
  // Section 2.7.1 of RFC 4291.
  dst_snmc.sin6_addr.s6_addr[0] = 255;
  dst_snmc.sin6_addr.s6_addr[1] = 2;
  for (i = 2; i < 11; i++) {
    dst_snmc.sin6_addr.s6_addr[i] = 0;
  }
  dst_snmc.sin6_addr.s6_addr[11] = 1;
  dst_snmc.sin6_addr.s6_addr[12] = 255;

  // Use iphdr (i.e., struct ip6_hdr) to carry source and destination IPv6 addresses to ICMP checksum function.
  iphdr.ip6_src = src.sin6_addr;
  iphdr.ip6_dst = dst_snmc.sin6_addr;

  // Report target's solicited-node multicast address.
  ipv6 = (struct sockaddr_in6 *) &dst_snmc;
  tmp = &(ipv6->sin6_addr);
  memset (target, 0, INET6_ADDRSTRLEN * sizeof (char));
  if (inet_ntop (AF_INET6, tmp, target, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target's solicited-node multicast address.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "Target solicited-node multicast address: %s\n", target);

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up soliciting node's (i.e., source's) interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  n = snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if ((n < 0) || (n >= (int) sizeof (ifr.ifr_name))) {
    fprintf (stderr, "Invalid interface name: %s\n", interface);
    exit (EXIT_FAILURE);
  }
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    fprintf (stderr, "ioctl(SIOCGIFHWADDR) failed to get source MAC address.\nError message: %s\n", strerror (errno));
    close (sd);
    exit (EXIT_FAILURE);
  }
  close (sd);

  // Report soliciting node MAC address to stdout.
  fprintf (stdout, "MAC address for interface %s is ", interface);
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", (uint8_t) ifr.ifr_addr.sa_data[i], (i < 5) ? ":" : "\n");
  }

  // Find interface index from interface name.
  // This will be put in cmsghdr data in order to specify the interface we want to use.
  if ((ifindex = if_nametoindex (interface)) == 0) {
    status = errno; 
    fprintf (stderr, "if_nametoindex(\"%s\") failed to obtain interface index.\nError message: %s\n", interface, strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "Soliciting node's index for interface %s is %d\n", interface, ifindex);

  // Neighbor Solicitation Header (ICMPV6 header)

  // Message Type (8 bits): Neighbor Solicitation
  nshdr.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;

  // Message Code (8 bits): Not used for neighbor solicitation; set to 0.
  nshdr.nd_ns_hdr.icmp6_code = 0;

  // ICMP header checksum (16 bits): Set to 0 when calculating checksum.
  nshdr.nd_ns_hdr.icmp6_cksum = htons(0);

  // Reserved (32 bits): Must be set to zero.
  nshdr.nd_ns_reserved = htonl(0);

  // Target address (16 bytes): Unicast (not multicast) IPv6 address of the device whose link-layer address we're trying to resolve.
  nshdr.nd_ns_target = dst.sin6_addr;

  // ICMP data

  // Copy soliciting node's MAC address into neighbor solicitation options buffer (i.e., icmp_data).
  uint8_t icmp_data[SLLA_OPTLEN];  // Source Link-Layer Address option.
  icmp_data[0] = 1;  // Option Type - "source link layer address" (Section 4.6 of RFC 4861)
  icmp_data[1] = SLLA_OPTLEN / 8;  // Option Length - units of 8 octets (RFC 4861)
  for (i = 0; i < 6; i++) {
    icmp_data[i + 2] = (uint8_t) ifr.ifr_addr.sa_data[i];
  }

  // Build ICMP message for ICMP checksum calculation.
  uint8_t icmp_msg[sizeof (struct nd_neighbor_solicit) + sizeof (icmp_data)];
  memset (icmp_msg, 0, sizeof (icmp_msg));
  memcpy (icmp_msg, &nshdr, sizeof (struct nd_neighbor_solicit));
  memcpy (icmp_msg + sizeof (struct nd_neighbor_solicit), icmp_data, sizeof (icmp_data));

  // Prepare the msghdr structure.
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = &dst_snmc;             // Destination IPv6 address (solicited node multicast) as socket address structure
  msghdr.msg_namelen = sizeof (dst_snmc);  // Size of socket address structure

  memset (&iov, 0, sizeof (iov));
  iov.iov_base = (uint8_t *) icmp_msg;
  iov.iov_len = sizeof (icmp_msg);
  msghdr.msg_iov = &iov;  // Scatter/gather array (If sending multiple buffers at once, iov would be an array.)
  msghdr.msg_iovlen = 1;  // Number of elements in scatter/gather array

  // Allocate control-message buffer for hop limit and packet-info ancillary data.
  cmsglen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (*pktinfo));
  msghdr.msg_control = allocate_ustrmem (cmsglen);
  msghdr.msg_controllen = cmsglen;

  // Change hop limit to 255 as required for neighbor solicitation (RFC 4861).
  hoplimit = 255;
  cmsghdr1 = CMSG_FIRSTHDR (&msghdr);
  cmsghdr1->cmsg_level = IPPROTO_IPV6;
  cmsghdr1->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit.
  cmsghdr1->cmsg_len = CMSG_LEN (sizeof (int));
  *(int *) CMSG_DATA (cmsghdr1) = hoplimit;

  // Specify source interface index for this packet via cmsghdr data.
  cmsghdr2 = CMSG_NXTHDR (&msghdr, cmsghdr1);
  cmsghdr2->cmsg_level = IPPROTO_IPV6;
  cmsghdr2->cmsg_type = IPV6_PKTINFO;  // We want to specify interface here.
  cmsghdr2->cmsg_len = CMSG_LEN (sizeof (*pktinfo));
  pktinfo = (struct in6_pktinfo *) CMSG_DATA (cmsghdr2);
  memset (pktinfo, 0, sizeof (*pktinfo));
  pktinfo->ipi6_ifindex = ifindex;
  pktinfo->ipi6_addr = src.sin6_addr;

  nshdr.nd_ns_hdr.icmp6_cksum = icmp6_checksum (iphdr, icmp_msg, sizeof (icmp_msg));
  memcpy (icmp_msg, &nshdr, sizeof (struct nd_neighbor_solicit));  // Save ICMP header with checksum to datagram.
  fprintf (stdout, "Checksum: %x\n", ntohs (nshdr.nd_ns_hdr.icmp6_cksum));

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Send datagram.
  bytes = sendmsg (sd, &msghdr, 0);
  if (bytes == -1) {
    status = errno;
    fprintf (stderr, "sendmsg() failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  // Check for short send.
  if (bytes != (ssize_t) sizeof (icmp_msg)) {
    fprintf (stderr, "sendmsg() sent %zd bytes but expected to send %zd bytes.\n", bytes, (ssize_t) sizeof (icmp_msg));
    exit (EXIT_FAILURE);
  }
  close (sd);

  // Free allocated memory.
  free (interface);
  free (target);
  free (source);
  free (msghdr.msg_control);

  return (EXIT_SUCCESS);
}

// Computing the internet checksum (RFC 1071).
// Note that the internet checksum is not guaranteed to preclude collisions.
uint16_t
checksum (uint8_t *addr, int len) {

  int count = len;
  uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += ((uint16_t) addr[0] << 8) + addr[1];
    addr += 2;
    count -= 2;
  }

  // Add left-over byte, if any. For an odd-length buffer, the
  // remaining byte is the high-order byte of the final 16-bit word.
  if (count > 0) {
    sum += ((uint16_t) addr[0] << 8);
  }

  // Fold the accumulated sum into 16 bits by repeatedly adding
  // carries back into the low 16 bits (one's-complement arithmetic).
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's-complement of sum. Return it in network byte order
  // so it can be copied directly into the packet header.
  answer = ~sum;

  return (htons (answer));
}

// Build IPv6 ICMP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
icmp6_checksum (struct ip6_hdr iphdr, uint8_t *icmp_msg, int icmp_len) {

  uint8_t *buf, *ptr, cvalue = IPPROTO_ICMPV6;
  uint16_t answer = 0;
  uint32_t lvalue;

  if (icmp_len < 0) {
    fprintf (stderr, "ERROR: icmp_len must not be negative in icmp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (icmp_len < 4) {
    fprintf (stderr, "ERROR: icmp_len is too small to hold ICMP header in icmp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (icmp_msg == NULL) {
    fprintf (stderr, "ERROR: icmp_msg is NULL in icmp6_checksum().\n");
    exit (EXIT_FAILURE);
  }

  // Allocate memory for buffer.
  buf = allocate_ustrmem (40 + icmp_len + 1);  // Add 1 for possible padding.
  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy Upper-Layer Packet Length into buf (32 bits).
  lvalue = htonl (icmp_len);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);

  // Copy ICMP header and ICMP data.
  memcpy (ptr, icmp_msg, icmp_len);

  // ICMP checksum field is bytes 2 and 3 of the ICMP message.
  // Set to zero for checksum calculation.
  buf[40 + 2] = 0;
  buf[40 + 3] = 0;

  answer = checksum (buf, 40 + icmp_len);

  // Free allocated memory.
  free (buf);

  return (answer);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %d in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = calloc (len, sizeof (char));
  if (tmp != NULL) {
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %d in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = calloc (len, sizeof (uint8_t));
  if (tmp != NULL) {
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}
