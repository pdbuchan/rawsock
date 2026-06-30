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

// Send an IPv6 ICMP echo request datagram.
// Changes hoplimit using ancillary data method.
// Use setsockopt() to bind socket to interface.
// Includes ICMP data.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <sys/socket.h>       // struct msghdr
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>    // struct icmp6_hdr, ICMP6_ECHO_REQUEST
#include <netdb.h>            // struct addrinfo
#include <net/if.h>           // struct ifreq

#include <errno.h>            // errno

// Define some constants.
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp6_checksum (struct ip6_hdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int n, status, icmp_datalen, sd, cmsglen, hoplimit;
  ssize_t bytes;
  char *interface, *target, *source;
  struct ip6_hdr iphdr;
  struct icmp6_hdr icmphdr;
  struct addrinfo hints, *res;
  struct sockaddr_in6 src, dst;
  socklen_t srclen;
  struct ifreq ifr;
  struct msghdr msghdr;
  struct cmsghdr *cmsghdr;
  struct iovec iov;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&icmphdr, 0, sizeof (icmphdr));
  memset (&msghdr, 0, sizeof (msghdr));

  // Allocate memory for various arrays.
  source = allocate_strmem (INET6_ADDRSTRLEN);
  target = allocate_strmem (HOSTNAME_LEN);
  interface = allocate_strmem (sizeof (ifr.ifr_name));

  // Interface to send datagram through.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Copy interface name into ifreq structure for SO_BINDTODEVICE.
  memset (&ifr, 0, sizeof (ifr));
  n = snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if ((n < 0) || (n >= (int) sizeof (ifr.ifr_name))) {
    fprintf (stderr, "Invalid interface name: %s\n", interface);
    exit (EXIT_FAILURE);
  }

  // Source IPv6 address: you need to fill this out
  snprintf (source, INET6_ADDRSTRLEN, "%s", "2001:db8::214:51ff:fe2f:1556");

  // Destination hostname or IPv6 address: you need to fill this out
  snprintf (target, HOSTNAME_LEN, "%s", "ipv6.google.com");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = 0;  // Address resolution only; any socket type.
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Use iphdr (i.e., struct ip6_hdr) to carry source and destination IPv6 addresses to ICMP checksum function.

  // Resolve source using getaddrinfo().
  if ((status = getaddrinfo (source, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for source.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  memset (&src, 0, sizeof (src));
  memcpy (&src, res->ai_addr, res->ai_addrlen);
  srclen = res->ai_addrlen;
  iphdr.ip6_src = src.sin6_addr;
  freeaddrinfo (res);

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  memset (&dst, 0, sizeof (dst));
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  iphdr.ip6_dst = dst.sin6_addr;
  freeaddrinfo (res);

  // ICMP header

  // Message Type (8 bits): echo request
  icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

  // Message Code (8 bits): Not used for Echo Request and Echo Reply; Set to 0.
  icmphdr.icmp6_code = 0;

  // ICMP header checksum (16 bits): Set to 0 when calculating checksum.
  icmphdr.icmp6_cksum = 0;

  // Identifier (16 bits): Usually pid of sending process; Pick a number.
  icmphdr.icmp6_id = htons (5);

  // Sequence Number (16 bits): Starts at 0.
  icmphdr.icmp6_seq = htons (0);

  // ICMP data
  uint8_t icmp_data[4] = {'T', 'e', 's', 't'};
  icmp_datalen = sizeof (icmp_data);

  // Build ICMP message for ICMP checksum calculation.
  uint8_t icmp_msg[ICMP_HDRLEN + sizeof (icmp_data)];
  memset (icmp_msg, 0, sizeof (icmp_msg));
  memcpy (icmp_msg, &icmphdr, ICMP_HDRLEN);
  memcpy (icmp_msg + ICMP_HDRLEN, icmp_data, icmp_datalen);

  // Compose the msghdr structure.
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = &dst;             // pointer to socket address structure
  msghdr.msg_namelen = sizeof (dst);  // size of socket address structure

  memset (&iov, 0, sizeof (iov));
  iov.iov_base = (uint8_t *) icmp_msg;
  iov.iov_len = sizeof (icmp_msg);
  msghdr.msg_iov = &iov;  // Scatter/gather array (If sending multiple buffers at once, iov would be an array.)
  msghdr.msg_iovlen = 1;  // Number of elements in scatter/gather array

  // Allocate ancillary control data for the Hop Limit control message.
  cmsglen = CMSG_SPACE (sizeof (int));
  msghdr.msg_control = allocate_ustrmem (cmsglen);
  msghdr.msg_controllen = cmsglen;

  // Change hop limit to 255.
  hoplimit = 255;
  cmsghdr = CMSG_FIRSTHDR (&msghdr);
  cmsghdr->cmsg_level = IPPROTO_IPV6;
  cmsghdr->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit in this example.
  cmsghdr->cmsg_len = CMSG_LEN (sizeof (int));
  *(int *) CMSG_DATA (cmsghdr) = hoplimit;

  // ICMP header checksum (16 bits): Set to 0 when calculating checksum.
  // Already set to 0 above.
  icmphdr.icmp6_cksum = icmp6_checksum (iphdr, icmp_msg, sizeof (icmp_msg));
  memcpy (icmp_msg, &icmphdr, ICMP_HDRLEN);  // Save ICMP header with checksum to datagram.
  fprintf (stdout, "Checksum: 0x%x\n", ntohs (icmphdr.icmp6_cksum));

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Bind the socket descriptor to the source address.
  if (bind (sd, (struct sockaddr *) &src, srclen) != 0) {
    status = errno;
    fprintf (stderr, "bind() Failed to bind the socket descriptor to the source address.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface by name.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, ifr.ifr_name, strlen (ifr.ifr_name) + 1) < 0) {
    status = errno;
    fprintf (stderr, "setsockopt(SOL_SOCKET, SO_BINDTODEVICE) failed.\nError message: %s\n", strerror (status));
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
  free (source);
  free (target);
  free (interface);
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

  // Checksum is one's complement of sum. Return it in network byte order
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
