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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // ICMP_ROUTERADVERT
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <net/if.h>           // struct ifreq, IFNAMSIZ
#include <time.h>             // time()

#include <errno.h>            // errno, perror()

// Define a struct for an IPv4 ICMP router advertisement header
typedef struct _ra_hdr ra_hdr;
struct _ra_hdr {
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint16_t icmp_cksum;
  uint8_t num_addrs;
  uint8_t entry_size;
  uint16_t lifetime;
  uint8_t addrs[2040];
};

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // IPv4 ICMP header length excluding data
#define TEXT_STRINGLEN 80     // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int status, sd, ip_flags[4] = {0}, datagram_length;
  ssize_t bytes;
  const int on = 1;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  ra_hdr rahdr;
  uint8_t *datagram;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4, src, sin;
  void *tmp;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&rahdr, 0, sizeof (rahdr));

  // Allocate memory for various arrays.
  datagram = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (IFNAMSIZ);
  target = allocate_strmem (TEXT_STRINGLEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Interface to send datagram through.
  snprintf (interface, IFNAMSIZ, "%s", "enp7s0");

  // Source IPv4 address (the advertising router): you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.3");

  // Destination IPv4 address ("all devices" multicast address)
  snprintf (target, INET_ADDRSTRLEN, "%s", "224.0.0.1");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Put source IP into sockaddr_in struct using getaddrinfo().
  if ((status = getaddrinfo (src_ip, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for source address.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  memset (&src, 0, sizeof (src));
  memcpy (&src, res->ai_addr, res->ai_addrlen);
  freeaddrinfo (res);

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

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

  // ICMP header

  // Message Type (8 bits): router advertisement
  rahdr.icmp_type = ICMP_ROUTERADVERT;

  // Message Code (8 bits): see RFC 1256
  rahdr.icmp_code = 0;

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  rahdr.icmp_cksum = 0;

  // Number of IP addresses associated with this router that are included in this advertisement (8 bits)
  rahdr.num_addrs = 1;

  // Total length of datagram (16 bits): IP header + ICMP header (8 bytes * number of addresses)
  // Calculate IPv4 header checksum.
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + (rahdr.num_addrs * 8));
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

  // Address entry size (8 bits): in units of 32 bit words
  // Each entry is 32 bits for address + 32 bits for address preference
  rahdr.entry_size = 2;

  // Lifetime of validity of this advertisement in seconds (16 bits): typical value
  rahdr.lifetime = htons (1800);

  // Router address entry 1 (32 bits): used default Cisco value of 192.168.1.1 as example
  memcpy (&rahdr.addrs, &src.sin_addr, sizeof (uint32_t));

  // Router address preference 1 (32 bits): choose a number
  // Higher means more preference.
  rahdr.addrs[4] = 0x00;
  rahdr.addrs[5] = 0x00;
  rahdr.addrs[6] = 0x00;
  rahdr.addrs[7] = 0xff;

  // Prepare IPv4 datagram.

  // First part is an IPv4 header.
  memcpy (datagram, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

  // Next part of datagram is upper layer protocol header.
  memcpy ((datagram + IP4_HDRLEN), &rahdr, (ICMP_HDRLEN + (rahdr.num_addrs * 8)) * sizeof (uint8_t));

  // Calculate ICMP header checksum
  rahdr.icmp_cksum = checksum ((uint8_t *) (datagram + IP4_HDRLEN), ICMP_HDRLEN + (rahdr.num_addrs * 8));
  memcpy ((datagram + IP4_HDRLEN), &rahdr, (ICMP_HDRLEN + (rahdr.num_addrs * 8)) * sizeof (uint8_t));

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
  datagram_length = IP4_HDRLEN + ICMP_HDRLEN + (rahdr.num_addrs * 8);
  bytes = sendto (sd, datagram, datagram_length, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr));
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

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum. Return it in network byte order
  // so it can be copied directly into the packet header.
  answer = ~sum;

  return (htons (answer));
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
