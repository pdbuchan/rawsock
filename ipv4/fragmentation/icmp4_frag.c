/*  Copyright (C) 2012-2026  P.D. Buchan (pdbuchan@gmail.com)

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

// Send an IPv4 ICMP packet via raw socket at the link layer (ethernet frame)
// with a large amount of ICMP data requiring fragmentation.
// Need to have destination MAC address.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#define __FAVOR_BSD           // Use BSD-style networking structures. e.g., struct tcphdr
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
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_IP, ETH_P_ALL
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <time.h>             // time()

#include <errno.h>            // errno, perror()

// Define some constants.
#define ETH_HDRLEN ETH_HLEN   // Ethernet header length
#define IP4_HDRLEN 20         // IPv4 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define MAX_FRAGS 3120        // Maximum number of packet fragments (int) (65535 - ICMP_HDRLEN) / (IP4_HDRLEN + 1 data byte))
#define TEXT_STRINGLEN 80     // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp4_checksum (uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

int
main (void) {

  int i, n, status, frame_length, sd, icmp_datalen, bufferlen;
  int ip_flags[4] = {0}, mtu, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct icmp icmphdr;
  uint8_t *icmpdata, *buffer, *src_mac, *icmp_msg, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;
  FILE *fi;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&icmphdr, 0, sizeof (icmphdr));

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  icmpdata = allocate_ustrmem (IP_MAXPACKET);
  icmp_msg = allocate_ustrmem (IP_MAXPACKET);
  ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (TEXT_STRINGLEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor for using ioctl().\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to get interface maximum transmission unit (MTU).
  memset (&ifr, 0, sizeof (ifr));
  n = snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if ((n < 0) || (n >= (int) sizeof (ifr.ifr_name))) {
    fprintf (stderr, "Invalid interface name: %s\n", interface);
    exit (EXIT_FAILURE);
  }
  if (ioctl (sd, SIOCGIFMTU, &ifr) < 0) {
    fprintf (stderr, "ioctl(SIOCGIFMTU) failed to get interface MTU.\nError message: %s\n", strerror (errno));
    close (sd);
    exit (EXIT_FAILURE);
  }
  mtu = ifr.ifr_mtu;
  fprintf (stdout, "Current MTU of interface %s is: %d\n", interface, mtu);
  if ((mtu <= IP4_HDRLEN) || ((mtu - IP4_HDRLEN) < 8)) {
    fprintf (stderr, "MTU is too small for fragmentation.\n");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
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

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // Report source MAC address to stdout.
  fprintf (stdout, "MAC address for interface %s is ", interface);
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", src_mac[i], (i < 5) ? ":" : "\n");
  }

  // Set destination MAC address: you need to fill these out
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Destination hostname or IPv4 address: you need to fill this out
  snprintf (target, TEXT_STRINGLEN, "%s", "www.google.com");

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
    fprintf (stderr, "inet_ntop() failed for target.\nError message: %s\n", strerror (status));
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
  memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  // Get ICMP data.
  i = 0;
  fi = fopen ("data", "r");
  if (fi == NULL) {
    fprintf (stderr, "Can't open file 'data'.\n");
    exit (EXIT_FAILURE);
  }
  while ((n = fgetc (fi)) != EOF) {
    if (i >= (IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN)) {
      fprintf (stderr, "Payload too large.\n");
      exit (EXIT_FAILURE);
    }
    icmpdata[i] = (uint8_t) n;
    i++;
  }
  fclose (fi);
  icmp_datalen = i;
  fprintf (stdout, "Upper layer protocol header length (bytes): %d\n", ICMP_HDRLEN);
  fprintf (stdout, "Payload length (bytes): %d\n", icmp_datalen);

  // Length of fragmentable portion of packet.
  bufferlen = ICMP_HDRLEN + icmp_datalen;
  fprintf (stdout, "Total fragmentable data (bytes): %d\n", bufferlen);

  // Allocate memory for a buffer for fragmentable portion.
  buffer = allocate_ustrmem (bufferlen);

  // Determine how many ethernet frames we'll need.
  memset (len, 0, MAX_FRAGS * sizeof (int));
  memset (offset, 0, MAX_FRAGS * sizeof (int));
  i = 0;
  c = 0;  // Variable c is index to buffer, which contains upper layer protocol header and data.
  while (c < bufferlen) {

    // Do we still need to fragment remainder of fragmentable portion?
    if ((bufferlen - c) > (mtu - IP4_HDRLEN)) {  // Yes
      len[i] = mtu - IP4_HDRLEN;  // len[i] is amount of fragmentable part we can include in this frame.

    } else {  // No
      len[i] = bufferlen - c;  // len[i] is amount of fragmentable part we can include in this frame.
    }
    c += len[i];

    // If not last fragment, make sure we have an even number of 8-byte blocks.
    // Reduce length as necessary.
    if (c < bufferlen) {
      while ((len[i]%8) > 0) {
        len[i]--;
        c--;
      }
    }
    fprintf (stdout, "Frag: %d,  Data (bytes): %d,  Data Offset (8-byte blocks): %d\n", i, len[i], offset[i]);
    i++;
    if (i >= MAX_FRAGS) {
     fprintf (stderr, "Too many fragments.\n");
       exit (EXIT_FAILURE);
    }
    offset[i] = (len[i-1] / 8) + offset[i-1];
  }
  nframes = i;
  fprintf (stdout, "Total number of frames to send: %d\n", nframes);

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits)
  // iphdr.ip_len is set for each fragment in loop below.

  // IPv4 Identification field (16 bits)
  iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits)

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

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 for checksum calculation.
  icmphdr.icmp_cksum = 0;

  // Build ICMP message for ICMP checksum calculation.
  memset (icmp_msg, 0, IP_MAXPACKET * sizeof (uint8_t));
  memcpy (icmp_msg, &icmphdr, ICMP_HDRLEN * sizeof (uint8_t));
  memcpy (icmp_msg + ICMP_HDRLEN, icmpdata, icmp_datalen * sizeof (uint8_t));

  // ICMP header checksum (16 bits)
  icmphdr.icmp_cksum = icmp4_checksum (icmp_msg, ICMP_HDRLEN + icmp_datalen);
  memcpy (icmp_msg, &icmphdr, ICMP_HDRLEN);  // Save ICMP header with checksum to datagram.

  // Build fragmentable portion (ICMP header + ICMP data) of packet in buffer array.
  memcpy (buffer, icmp_msg, ICMP_HDRLEN + icmp_datalen);

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Loop through fragments.
  for (i = 0; i < nframes; i++) {

    // Set ethernet frame contents to zero initially.
    memset (ether_frame, 0, (ETH_HDRLEN + IP_MAXPACKET) * sizeof (uint8_t));

    // Fill out ethernet frame header.

    // Copy destination and source MAC addresses to ethernet frame.
    memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Next is ethernet type code (ETH_P_IP for IPv4).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IP / 256;
    ether_frame[13] = ETH_P_IP % 256;

    // Next is ethernet frame data (IPv4 header + fragment).

    // Total length of datagram (16 bits): IP header + fragment
    iphdr.ip_len = htons (IP4_HDRLEN + len[i]);

    // More fragments following flag (1 bit)
    if ((nframes > 1) && (i < (nframes - 1))) {
      ip_flags[2] = 1u;
    } else {
      ip_flags[2] = 0u;
    }

    // Fragmentation offset (13 bits)
    ip_flags[3] = offset[i];

    // Flags, and Fragmentation offset (3, 13 bits)
    iphdr.ip_off = htons ((ip_flags[0] << 15)
                        + (ip_flags[1] << 14)
                        + (ip_flags[2] << 13)
                        +  ip_flags[3]);

    // IPv4 header checksum (16 bits)
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

    // Copy IPv4 header to ethernet frame.
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

    // Copy fragmentable portion of packet to ethernet frame.
    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, buffer + (offset[i] * 8), len[i] * sizeof (uint8_t));

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + fragment)
    frame_length = ETH_HDRLEN + IP4_HDRLEN + len[i];

    // Send ethernet frame to socket.
    fprintf (stdout, "Sending fragment: %d\n", i);
    bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
    if (bytes == -1) {
      status = errno;
      fprintf (stderr, "sendto() failed.\nError message: %s\n", strerror (status));
      exit (EXIT_FAILURE);
    }
    // Check for short send.
    if (bytes != frame_length) {
      fprintf (stderr, "sendto() sent %zd bytes but expected to send %d bytes.\n", bytes, frame_length);
      exit(EXIT_FAILURE);
    }
  }  // End loop nframes

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (src_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (icmpdata);
  free (icmp_msg);
  free (buffer);

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
