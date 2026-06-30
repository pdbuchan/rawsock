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

// Send a "cooked" IPv6 ICMP Echo Request datagram via packet socket.
// Need to specify the next-hop destination MAC address.
// Includes some ICMP data.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_ICMPV6, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>    // struct icmp6_hdr, ICMP6_ECHO_REQUEST
#include <arpa/inet.h>        // inet_pton(), inet_ntop()
#include <net/if.h>           // IFNAMSIZ
#include <linux/if_ether.h>   // ETH_P_IPV6
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)

#include <errno.h>            // errno

// Define some constants
#define IP6_HDRLEN 40         // IPv6 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp6_checksum (struct ip6_hdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int status, icmp_datalen, datagram_length, sd;
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct icmp6_hdr icmphdr;
  uint8_t *datagram;
  struct addrinfo hints, *res;
  struct sockaddr_in6 dst;
  struct sockaddr_ll device;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&icmphdr, 0, sizeof (icmphdr));

  // Allocate memory for various arrays.
  datagram = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (IFNAMSIZ);
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);

  // Interface to send datagram through.
  snprintf (interface, IFNAMSIZ, "enp7s0");

  // Destination Ethernet MAC address: You need to fill these out.
  // For off-link destinations, this is normally the next-hop router's MAC address.
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv6 address: you need to fill this out
  snprintf (src_ip, INET6_ADDRSTRLEN, "2001:db8::214:51ff:fe2f:1556");

  // Destination hostname or IPv6 address: you need to fill this out
  snprintf (target, HOSTNAME_LEN, "ipv6.google.com");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = 0;  // Address resolution only; any socket type.
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  memset (&dst, 0, sizeof (dst));
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  if (inet_ntop (AF_INET6, &dst.sin6_addr, dst_ip, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out device's sockaddr_ll struct.
  memset (&device, 0, sizeof (device));
  device.sll_family = AF_PACKET;
  device.sll_protocol = htons (ETH_P_IPV6);
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    status = errno;
    fprintf (stderr, "if_nametoindex(\"%s\") failed to obtain interface index.\nError message: %s\n", interface, strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "Index for interface %s is %d\n", interface, device.sll_ifindex);
  memcpy (device.sll_addr, dst_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  uint8_t icmp_data[4] = {'T', 'e', 's', 't'};
  icmp_datalen = 4;

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): ICMP header + ICMP data
  iphdr.ip6_plen = htons (ICMP_HDRLEN + icmp_datalen);

  // Next header (8 bits): 58 for ICMP
  iphdr.ip6_nxt = IPPROTO_ICMPV6;

  // Hop limit (8 bits): Default to maximum value.
  iphdr.ip6_hops = 255;

  // Source IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv6 address (128 bits)
  if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // ICMP header

  // Message Type (8 bits): echo request
  icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

  // Message Code (8 bits): Not used for Echo Request and Echo Reply; set to 0.
  icmphdr.icmp6_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  icmphdr.icmp6_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp6_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp6_cksum = 0;

  // Fill out IPv6 datagram.

  // Datagram length = IP header + ICMP header + ICMP data
  datagram_length = IP6_HDRLEN + ICMP_HDRLEN + icmp_datalen;

  // IPv6 header
  memcpy (datagram, &iphdr, IP6_HDRLEN);

  // ICMP header
  memcpy (datagram + IP6_HDRLEN, &icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (datagram + IP6_HDRLEN + ICMP_HDRLEN, icmp_data, icmp_datalen);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  // Already set to 0 above.
  icmphdr.icmp6_cksum = icmp6_checksum (iphdr, datagram + IP6_HDRLEN, ICMP_HDRLEN + icmp_datalen);
  memcpy (datagram + IP6_HDRLEN, &icmphdr, ICMP_HDRLEN);  // Save ICMP header with checksum to datagram.
  fprintf (stdout, "Checksum: 0x%x\n", ntohs (icmphdr.icmp6_cksum));

  // Open raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_IPV6))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Send datagram to socket.
  bytes = sendto (sd, datagram, datagram_length, 0, (struct sockaddr *) &device, sizeof (device));
  if (bytes == -1) {
    status = errno;
    fprintf (stderr, "sendto() failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  // Check for short send.
  if (bytes != datagram_length) {
    fprintf (stderr, "sendto() sent %zd bytes but expected to send %d bytes.\n", bytes, datagram_length);
    exit(EXIT_FAILURE);
  }

  close (sd);

  // Free allocated memory.
  free (datagram);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);

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
