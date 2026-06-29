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

// Send an IPv4 router advertisement packet via raw socket.
// Stack fills out layer 2 (data link) information (MAC addresses) for us.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp, ICMP_ROUTERADVERT
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <net/if.h>           // struct ifreq, IFNAMSIZ
#include <time.h>             // time()

#include <errno.h>            // errno, perror()

// ICMP header for Router Advertisement
typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint8_t num_addrs;
  uint8_t entry_size;
  uint16_t lifetime;
} ICMP_HDR;

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // IPv4 ICMP header length excluding data
#define TEXT_STRINGLEN 80     // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp4_checksum (uint8_t *, int);
char *allocate_strmem (int);
char **allocate_strmemp (int);
uint8_t *allocate_ustrmem (int);
uint8_t **allocate_ustrmemp (int);
int32_t *allocate_int32mem (int);

int
main (void) {

  int i, status, sd, ip_flags[4] = {0}, icmp_msglen, datagram_length;
  ssize_t bytes;
  const int on = 1;
  char *interface, *src_ip, *dst_ip, **addrs;
  struct ip iphdr;
  ICMP_HDR icmphdr;
  uint8_t **addru, *datagram;
  int32_t *pref;
  struct sockaddr_in sin;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&icmphdr, 0, sizeof (icmphdr));

  // Allocate memory for various arrays.
  datagram = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (IFNAMSIZ);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Interface to send datagram through.
  snprintf (interface, IFNAMSIZ, "%s", "enp7s0");

  // Source IPv4 address (the advertising router) (32 bits): you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.3");

  // Destination IPv4 address ("all devices" multicast address) (32 bits)
  snprintf (dst_ip, INET_ADDRSTRLEN, "%s", "224.0.0.1");

  // Number of IPv4 addresses associated with this router that are included in this advertisement (8 bits)
  icmphdr.num_addrs = 1;  // You choose how many addresses will be advertised.

  // Allocate memory for Router Addresses and Preference Levels.
  addrs = allocate_strmemp (icmphdr.num_addrs);
  addru = allocate_ustrmemp (icmphdr.num_addrs);
  for (i = 0; i < icmphdr.num_addrs; i++) {
    addrs[i] = allocate_strmem (TEXT_STRINGLEN);
    addru[i] = allocate_ustrmem (4);
  }
  pref = allocate_int32mem (icmphdr.num_addrs);

  // Router Address 1: You need to enter an IPv4 address.
  snprintf (addrs[0], TEXT_STRINGLEN, "192.168.1.1");

  // Router Address 1 Preference Level (32 bit two's complement value): You need to fill this out.
  // When more than one Router Address is present, this indicates which
  // address the router would prefer hosts to use. Higher means greater preference.
  pref[0] = htonl (1000);

  // Router Address 2 ...
  // Router Address 2 Preference Level ... etc ...

  // Convert all router addresses from presentation to network format.
  for (i = 0; i < (int) icmphdr.num_addrs; i++) {

    // Router IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, addrs[i], addru[i])) != 1) {
      if (status == 0) {
        fprintf (stderr, "inet_pton() failed for source address %s.\nError message: Invalid address\n", addrs[i]);
      } else if (status < 0) {
        fprintf (stderr, "inet_pton() failed for source address %s.\nError message: %s\n", addrs[i], strerror (errno));
      }
      exit (EXIT_FAILURE);
    }

  }  // Next Router Address

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + data
  // See ICMP header below.

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

  // Time-to-Live (8 bits): traditionally for IPv4, it should be link-local. i.e., TTL = 1
  iphdr.ip_ttl = 1;

  // Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits): Convert from presentation to network format.
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address ("all devices" multicast address) (32 bits): Convert from presentation to network format.
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

  // ICMP header (Router Advertisement)

  // Message Type (8 bits): router advertisement
  icmphdr.type = ICMP_ROUTERADVERT;

  // Message Code (8 bits): see RFC 1256
  icmphdr.code = 0;

  // ICMP data

  // Address entry size in units of 32 bit words (8 bits): Always 2.
  // Each entry is 32 bits for address + 32 bits for address preference, therefore entry_size = 2.
  icmphdr.entry_size = 2;

  // Lifetime of validity for this advertisement in seconds (16 bits): Typical value used here.
  icmphdr.lifetime = htons (1800);

  // Compose datagram

  // IPv4 header
  memcpy (datagram, &iphdr, IP4_HDRLEN);  // IPv4 header

  // ICMP message (Router Advertisement)
  icmphdr.checksum = 0;  // IPv4 header checksum (16 bits): Set to 0 for checksum calculation.
  memcpy (datagram + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);  // ICMP header
  icmp_msglen = ICMP_HDRLEN;
  for (i = 0; i < (int) icmphdr.num_addrs; i++) {
    memcpy (datagram + IP4_HDRLEN + ICMP_HDRLEN + (i * 8), addru[i], sizeof (uint32_t));  // Router Address (32 bits)
    memcpy (datagram + IP4_HDRLEN + ICMP_HDRLEN + (i * 8) + 4, &pref[i], sizeof (uint32_t));  // Router Address Preference (32 bits)
    icmp_msglen += 8;
  }

  // Total length of datagram (16 bits): IP header + ICMP message (ICMP header + ICMP data)
  // Calculate IPv4 header checksum.
  iphdr.ip_len = htons (IP4_HDRLEN + icmp_msglen);
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);  // Was previously initialized to 0 above.
  memcpy (datagram, &iphdr, IP4_HDRLEN);  // Save IPv4 header with checksum to datagram.

  // ICMP header checksum (16 bits): Set to 0 when calculating checksum.
  // Already set to 0 above.
  icmphdr.checksum = icmp4_checksum (datagram + IP4_HDRLEN, icmp_msglen);
  memcpy (datagram + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);  // Save ICMP header with checksum to datagram.

  // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
  // For that, we need to specify a destination for the kernel in order for it
  // to decide where to send the raw datagram. We fill in a struct in_addr with
  // the desired destination IP address, and pass this structure to the sendto() function.
  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;

  // Submit request for a raw socket descriptor.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set flag so socket expects us to provide IPv4 header.
  if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
    status = errno;
    fprintf (stderr, "setsockopt(IP_HDRINCL) failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface name.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, interface, strnlen (interface, IFNAMSIZ) + 1) < 0) {
    status = errno;
    fprintf (stderr, "setsockopt(SOL_SOCKET, SO_BINDTODEVICE) failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Send datagram to socket.
  datagram_length = IP4_HDRLEN + icmp_msglen;
  bytes = sendto (sd, datagram, datagram_length, 0, (struct sockaddr *) &sin, sizeof (sin));
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
  free (datagram);
  free (interface);
  free (src_ip);
  free (dst_ip);
  for (i = 0; i < (int) icmphdr.num_addrs; i++) {
    free (addrs[i]);
    free (addru[i]);
  }
  free (addrs);
  free (addru);
  free (pref);

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

// Allocate memory for an array of pointers to arrays of chars.
char **
allocate_strmemp (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %d in allocate_strmemp().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = calloc (len, sizeof (char *));
  if (tmp != NULL) {
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array in allocate_strmemp().\n");
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

// Allocate memory for an array of pointers to arrays of unsigned chars.
uint8_t **
allocate_ustrmemp (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %d in allocate_ustrmemp().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = calloc (len, sizeof (uint8_t *));
  if (tmp != NULL) {
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array in allocate_ustrmemp().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of int32_t.
int32_t *
allocate_int32mem (int len) {

  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %d in allocate_int32mem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = calloc (len, sizeof (int32_t));
  if (tmp != NULL) {
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array in allocate_int32mem().\n");
    exit (EXIT_FAILURE);
  }
}
