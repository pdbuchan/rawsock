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

// Send a "cooked" IPv4 ICMP packet via raw socket.
// Need to specify destination MAC address.
// Values set for echo request packet, includes some ICMP data.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ECHO
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <net/if.h>           // IFNAMSIZ
#include <linux/if_ether.h>   // ETH_P_IP
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <time.h>             // time()

#include <errno.h>            // errno, perror()

// Define some constants
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes
uint16_t icmp4_checksum (uint8_t *, int);
uint16_t checksum (uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

int
main (void) {

  int status, icmp_datalen, datagram_length, sd, ip_flags[4] = {0};
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct icmp icmphdr;
  uint8_t *icmpdata, *datagram;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  void *tmp;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&icmphdr, 0, sizeof (icmphdr));

  // Allocate memory for various arrays.
  icmpdata = allocate_ustrmem (IP_MAXPACKET);
  datagram = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (IFNAMSIZ);
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Interface to send datagram through.
  snprintf (interface, IFNAMSIZ, "%s", "enp7s0");

  // Destination Ethernet MAC address: You need to fill these out.
  // For off-link destinations, this is normally the next-hop router's MAC address.
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Destination hostname or IPv4 address: you need to fill this out
  snprintf (target, HOSTNAME_LEN, "%s", "www.google.com");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;  // Address resolution only; any socket type.
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

  // Fill out device's sockaddr_ll struct.
  memset (&device, 0, sizeof (device));
  device.sll_family = AF_PACKET;
  device.sll_protocol = htons (ETH_P_IP);
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    status = errno;
    fprintf (stderr, "if_nametoindex(\"%s\") failed to obtain interface index.\nError message: %s\n", interface, strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "Index for interface %s is %d\n", interface, device.sll_ifindex);
  memcpy (device.sll_addr, dst_mac, 6);
  device.sll_halen = 6;

  // ICMP data
  icmpdata[0] = (uint8_t) 'T';
  icmpdata[1] = (uint8_t) 'e';
  icmpdata[2] = (uint8_t) 's';
  icmpdata[3] = (uint8_t) 't';
  icmp_datalen = 4;

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + icmp_datalen);

  // IPv4 Identification field (16 bits)
  iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): Not used for Echo Request and Echo Reply; set to 0.
  icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits)
  icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp_cksum = 0;

  // Fill out IPv4 datagram.

  // Datagram length = IP header + ICMP header + ICMP data
  datagram_length = IP4_HDRLEN + ICMP_HDRLEN + icmp_datalen;

  // IPv4 header
  memcpy (datagram, &iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (datagram + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (datagram + IP4_HDRLEN + ICMP_HDRLEN, icmpdata, icmp_datalen);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  // Already set to 0 above.
  icmphdr.icmp_cksum = icmp4_checksum (datagram + IP4_HDRLEN, ICMP_HDRLEN + icmp_datalen);
  memcpy (datagram + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);  // Save ICMP header with checksum to datagram.

  // Open raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_IP))) < 0) {
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

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (icmpdata);
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

// Calculate IPv4 ICMP checksum.
// Computes the ICMPv4 checksum over an arbitrary complete ICMP message:
//
//   ICMP header + ICMP data
//
// The IPv4 ICMP checksum does not require the composition of a pseudo-header.
// The ICMP checksum field is always bytes 2 and 3 of the ICMP message.
// This routine makes a private copy of the message, zeros those two bytes,
// and computes the Internet checksum over the whole ICMP message.
//
// This makes the function suitable for Echo, Destination Unreachable,
// Time Exceeded, Router Advertisement, Router Solicitation, and other
// ICMPv4 message types, provided the caller supplies the complete ICMP
// message exactly as it will appear after the IPv4 header.
//   icmp_msg points to the beginning of the ICMP message, not the IPv4 header.
//   icmp_len is the total ICMP message length: ICMP header + ICMP data.
uint16_t
icmp4_checksum (uint8_t *icmp_msg, int icmp_len) {

  uint8_t *buf;
  uint16_t answer;

  if (icmp_len < 4) {
    fprintf (stderr, "ERROR: icmp_len must be at least 4 bytes in icmp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  if (icmp_msg == NULL) {
    fprintf (stderr, "ERROR: icmp_msg is NULL in icmp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  buf = allocate_ustrmem (icmp_len);

  memcpy (buf, icmp_msg, icmp_len);

  // ICMP checksum field is bytes 2 and 3 of the ICMP message.
  // Set to zero for checksum calculation.
  buf[2] = 0;
  buf[3] = 0;

  answer = checksum (buf, icmp_len);

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

// Allocate memory for an array of ints.
int *
allocate_intmem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %d in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = calloc (len, sizeof (int));
  if (tmp != NULL) {
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}
