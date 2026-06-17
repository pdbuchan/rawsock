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

// Send an IPv4 UDP packet via raw socket at the link layer (ethernet frame)
// with a large payload requiring fragmentation.
// Need to have destination MAC address.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>      // struct udphdr
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
#define UDP_HDRLEN  8         // UDP header length, excludes data
#define MAX_FRAGS 3120        // Maximum number of packet fragments (int) (65535 - UDP_HDRLEN) / (IP4_HDRLEN + 1 data byte))
#define TEXT_STRINGLEN 80     // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t udp4_checksum (struct ip, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, frame_length, sd;
  int ip_flags[4] = {0}, mtu, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct udphdr udphdr;
  int payloadlen, bufferlen;
  uint8_t *payload, *buffer, *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;
  FILE *fi;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&udphdr, 0, sizeof (udphdr));

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  payload = allocate_ustrmem (IP_MAXPACKET);
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
  dst_mac[0] = 0x0c;
  dst_mac[1] = 0x9d;
  dst_mac[2] = 0x92;
  dst_mac[3] = 0x02;
  dst_mac[4] = 0x58;
  dst_mac[5] = 0x58;

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Destination URL or IPv4 address
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

  // Get UDP data.
  i = 0;
  fi = fopen ("data", "r");
  if (fi == NULL) {
    fprintf (stderr, "Can't open file 'data'.\n");
    exit (EXIT_FAILURE);
  }
  while ((n=fgetc (fi)) != EOF) {
    if (i >= (IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN)) {
      fprintf (stderr, "Payload too large.\n");
      exit (EXIT_FAILURE);
    }
    payload[i] = n;
    i++;
  }
  fclose (fi);
  payloadlen = i;
  fprintf (stdout, "Upper layer protocol header length (bytes): %d\n", UDP_HDRLEN);
  fprintf (stdout, "Payload length (bytes): %d\n", payloadlen);

  // Length of fragmentable portion of packet.
  bufferlen = UDP_HDRLEN + payloadlen;
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
      while ((len[i] % 8) > 0) {
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

  // Transport layer protocol (8 bits): 17 for UDP
  iphdr.ip_p = IPPROTO_UDP;

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

  // UDP header

  // Source port number (16 bits): pick a number
  udphdr.source = htons (4950);

  // Destination port number (16 bits): pick a number
  udphdr.dest = htons (4950);

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.len = htons (UDP_HDRLEN + payloadlen);

  // UDP checksum (16 bits)
  udphdr.check = 0;
  udphdr.check = udp4_checksum (iphdr, udphdr, payload, payloadlen);

  // Build fragmentable portion of packet in buffer array.
  // UDP header
  memcpy (buffer, &udphdr, UDP_HDRLEN * sizeof (uint8_t));
  // UDP data
  memcpy (buffer + UDP_HDRLEN, payload, payloadlen * sizeof (uint8_t));

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
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (payload);
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

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {

  int udp_segment_len, chksumlen = 0;
  uint8_t *buf, *ptr;
  uint16_t answer = 0;

  if (payloadlen < 0) {
    fprintf (stderr, "ERROR: payloadlen must not be negative in udp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((payloadlen > 0) && (payload == NULL)) {
    fprintf (stderr, "ERROR: payload is NULL but payloadlen > 0 in udp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  udp_segment_len = UDP_HDRLEN + payloadlen;

  // Allocate memory for buffer.
  buf = allocate_ustrmem (12 + udp_segment_len + 1);  // Add 1 for possible padding.
  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen++;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf, if any.
  if (payloadlen > 0) {
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;
  }

  // Pad to the next 16-bit boundary
  if (payloadlen % 2) {
    *ptr = 0;
    chksumlen++;
  }

  answer = checksum ((uint8_t *) buf, chksumlen);

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
