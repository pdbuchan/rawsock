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

// Send an IPv6 ICMP packet via raw socket at the link layer (Ethernet frame)
// with a large amount of ICMP data requiring fragmentation.
// Need to have destination MAC address.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // socket()
#include <netinet/in.h>       // IPPROTO_ICMPV6, IPPROTO_FRAGMENT, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>    // struct icmp6_hdr, ICMP6_ECHO_REQUEST
#include <arpa/inet.h>        // inet_pton(), inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_IPV6
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)

#include <errno.h>            // errno

// Define some constants.
#define ETH_HDRLEN ETH_HLEN   // Ethernet header length
#define MAC_LEN 6             // Length of a hardware (MAC) address
#define IP6_HDRLEN 40         // IPv6 header length
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define FRG_HDRLEN 8          // IPv6 fragment header
#define MAX_FRAGS 3119        // Maximum number of packet fragments
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp6_checksum (struct ip6_hdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, icmp_datalen, fragbufferlen, frame_length, sd;
  int mtu, frag_flags[2] = {0}, c, nframes, offset[MAX_FRAGS], len[MAX_FRAGS];
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct icmp6_hdr icmphdr;
  struct ip6_frag fraghdr;
  uint8_t *icmp_data, *fragbuffer, src_mac[MAC_LEN] = {0}, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in6 dst;
  struct sockaddr_ll device;
  struct ifreq ifr;
  FILE *fi;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&icmphdr, 0, sizeof (icmphdr));

  // Allocate memory for various arrays.
  icmp_data = allocate_ustrmem (IP_MAXPACKET);
  ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "enp7s0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET6, SOCK_DGRAM, 0)) < 0) {
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
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    fprintf (stderr, "ioctl(SIOCGIFHWADDR) failed to get source MAC address.\nError message: %s\n", strerror (errno));
    close (sd);
    exit (EXIT_FAILURE);
  }
  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, sizeof (src_mac));

  // Report source MAC address to stdout.
  fprintf (stdout, "MAC address for interface %s is ", interface);
  for (i = 0; i < (int) sizeof (src_mac); i++) {
    fprintf (stdout, "%02x%s", src_mac[i], (i < (int) sizeof (src_mac) - 1) ? ":" : "\n");
  }

  // Destination Ethernet MAC address: You need to fill these out.
  // For off-link destinations, this is normally the next-hop router's MAC address.
  uint8_t dst_mac[MAC_LEN] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv6 address: You need to fill this out.
  snprintf (src_ip, INET6_ADDRSTRLEN, "2001:db8::214:51ff:fe2f:1556");

  // Destination hostname or IPv6 address: You need to fill this out.
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
  memcpy (device.sll_addr, dst_mac, sizeof (dst_mac));
  device.sll_halen = sizeof (dst_mac);

  // Get ICMP data.
  i = 0;
  fi = fopen ("data", "r");
  if (fi == NULL) {
    fprintf (stderr, "Can't open file 'data'.\n");
    exit (EXIT_FAILURE);
  }
  while ((n = fgetc (fi)) != EOF) {
    if (i >= (IP_MAXPACKET - IP6_HDRLEN - ICMP_HDRLEN)) {
      fprintf (stderr, "Payload too large.\n");
      exit (EXIT_FAILURE);
    }
    icmp_data[i] = n;
    i++;
  }
  fclose (fi);
  icmp_datalen = i;
  fprintf (stdout, "Upper layer protocol header length (bytes): %d\n", ICMP_HDRLEN);
  fprintf (stdout, "Payload length (bytes): %d\n", icmp_datalen);

  // Length of fragmentable portion of packet.
  fragbufferlen = ICMP_HDRLEN + icmp_datalen;
  fprintf (stdout, "Total fragmentable data (bytes): %d\n", fragbufferlen);

  // Allocate memory for the fragmentable portion.
  fragbuffer = allocate_ustrmem (fragbufferlen);

  // Determine how many Ethernet frames we'll need.
  memset (len, 0, MAX_FRAGS * sizeof (int));
  memset (offset, 0, MAX_FRAGS * sizeof (int));
  i = 0;
  c = 0;  // Variable c is index to buffer, which contains upper layer protocol header and data.
  while (c < fragbufferlen) {

    // Do we still need to fragment remainder of fragmentable portion?
    if ((fragbufferlen - c) > (mtu - IP6_HDRLEN - FRG_HDRLEN)) {  // Yes
      len[i] = mtu - IP6_HDRLEN - FRG_HDRLEN;  // len[i] is amount of fragmentable part we can include in this frame.

    } else {  // No
      len[i] = fragbufferlen - c;  // len[i] is amount of fragmentable part we can include in this frame.
    }
    c += len[i];

    // If not last fragment, make sure we have an even number of 8-byte blocks.
    // Reduce length as necessary.
    if (c < fragbufferlen) {
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
    offset[i] = (len[i - 1] / 8) + offset[i - 1];
  }
  nframes = i;
  fprintf (stdout, "Total number of frames to send: %d\n", nframes);

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits)
  // iphdr.ip6_plen is set for each fragment in loop below.

  // Next header (8 bits): Temporary value; final Next Header chain is set after the ICMP checksum.
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

  // Identifier (16 bits): Usually pid of sending process; pick a number.
  icmphdr.icmp6_id = htons (1000);

  // Sequence Number (16 bits): Starts at 0.
  icmphdr.icmp6_seq = htons (0);

  // ICMP header checksum (16 bits): Set to 0 when calculating checksum.
  icmphdr.icmp6_cksum = 0;

  // Build buffer array containing fragmentable portion.

  // ICMP header
  memcpy (fragbuffer, &icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (fragbuffer + ICMP_HDRLEN, icmp_data, icmp_datalen);

  // ICMP header checksum (16 bits)
  // Already set to 0 above.
  icmphdr.icmp6_cksum = icmp6_checksum (iphdr, fragbuffer, ICMP_HDRLEN + icmp_datalen);
  memcpy (fragbuffer, &icmphdr, ICMP_HDRLEN);  // Save ICMP header with checksum to datagram.
  fprintf (stdout, "Checksum: 0x%x\n", ntohs (icmphdr.icmp6_cksum));

  // IPv6 next header (8 bits)
  if (nframes == 1)  {
    iphdr.ip6_nxt = IPPROTO_ICMPV6;  // 58 for ICMP
  } else {
    iphdr.ip6_nxt = IPPROTO_FRAGMENT;  // 44 for Fragmentation extension header
  }

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IPV6))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Loop through fragments.
  for (i = 0; i < nframes; i++) {

    // Set Ethernet frame contents to zero initially.
    memset (ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);

    // Fill out Ethernet frame header.

    // Copy destination and source MAC addresses to Ethernet frame.
    memcpy (ether_frame, dst_mac, sizeof (dst_mac));
    memcpy (ether_frame + sizeof (dst_mac), src_mac, sizeof (src_mac));

    // EtherType (16 bits): ETH_P_IPV6
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_IPV6 / 256;
    ether_frame[13] = ETH_P_IPV6 % 256;

    // Next is Ethernet frame data (IPv6 header + fragment).

    // Payload length (16 bits): See 4.5 of RFC 2460.
    if (nframes == 1) {
      iphdr.ip6_plen = htons (len[i]);
    } else {
      iphdr.ip6_plen = htons (FRG_HDRLEN + len[i]);
    }

    // Copy IPv6 header to Ethernet frame.
    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN);

    // Fill out and copy fragmentation extension header to Ethernet frame.
    if (nframes > 1) {
      fraghdr.ip6f_nxt = IPPROTO_ICMPV6;  // Upper layer protocol
      fraghdr.ip6f_reserved = 0;  // Reserved
      frag_flags[1] = 0;  // Reserved
      if (i < (nframes - 1)) {
        frag_flags[0] = 1;  // More fragments to follow
      } else {
        frag_flags[0] = 0;  // This is the last fragment
      }
      fraghdr.ip6f_offlg = htons ((offset[i] << 3) + frag_flags[0] + (frag_flags[1] <<1));
      fraghdr.ip6f_ident = htonl (31415);
      memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &fraghdr, FRG_HDRLEN);
    }

    // Copy fragmentable portion of packet to Ethernet frame.
    if (nframes == 1) {
      memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, fragbuffer, fragbufferlen);
    } else {
      memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN + FRG_HDRLEN, fragbuffer + (offset[i] * 8), len[i]);
    }

    // Ethernet frame length = Ethernet header (MAC + MAC + Ethernet type) + Ethernet data (IPv6 header + [fragment header] + fragment)
    if (nframes == 1) {
      frame_length = ETH_HDRLEN + IP6_HDRLEN + len[i];
    } else {
      frame_length = ETH_HDRLEN + IP6_HDRLEN + FRG_HDRLEN + len[i];
    }

    // Send Ethernet frame to socket.
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
      exit (EXIT_FAILURE);
    }
  }

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (icmp_data);
  free (fragbuffer);

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

// Build ICMPv6 pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
icmp6_checksum (struct ip6_hdr iphdr, uint8_t *icmp_msg, int icmp_len) {

  uint8_t *buf, *ptr, cvalue = IPPROTO_ICMPV6;
  uint16_t answer = 0;
  uint32_t lvalue;

  if (icmp_len < 0) {
    fprintf (stderr, "ERROR: icmp_len must not be negative in icmp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (icmp_len < ICMP_HDRLEN) {
    fprintf (stderr, "ERROR: icmp_len is too small to hold an ICMPv6 header in icmp6_checksum().\n");
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
