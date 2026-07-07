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

// Send an IPv6 TCP packet via raw socket at the link layer (Ethernet frame).
// Need to have destination MAC address.
// Values set for SYN packet with two TCP options: TCP Maximum Segment Size, TCP Timestamp

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#define __FAVOR_BSD           // Use BSD-style networking structures. e.g., struct tcphdr
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // socket()
#include <netinet/in.h>       // IPPROTO_TCP, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton(), inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_IPV6
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <time.h>             // time()

#include <errno.h>            // errno

// Define some constants.
#define ETH_HDRLEN ETH_HLEN   // Ethernet header length
#define MAC_LEN 6             // Length of a hardware (MAC) address
#define IP6_HDRLEN 40         // IPv6 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define MAX_TCP_OPTIONS 10    // Maximum number of TCP options
#define TCP_MAX_OPTLEN 40     // Maximum length of a TCP option
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t tcp6_checksum (struct ip6_hdr, struct tcphdr, uint8_t *, int, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
uint8_t **allocate_ustrmemp (int);
int *allocate_intmem (int);

int
main (void) {

  int i, n, c, status, nopt, *tcp_optlen, buf_len, frame_length, sd, tcp_flags[8] = {0};
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip6_hdr iphdr;
  struct tcphdr tcphdr;
  uint8_t **tcp_options, *opt_buffer, src_mac[MAC_LEN] = {0}, *ether_frame;
  uint32_t seq;
  struct addrinfo hints, *res;
  struct sockaddr_in6 dst;
  struct sockaddr_ll device;
  struct ifreq ifr;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&tcphdr, 0, sizeof (tcphdr));

  // Allocate memory for various arrays.
  ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
  tcp_optlen = allocate_intmem (MAX_TCP_OPTIONS);
  tcp_options = allocate_ustrmemp (MAX_TCP_OPTIONS);
  for (i = 0; i < MAX_TCP_OPTIONS; i++) {
    tcp_options[i] = allocate_ustrmem (TCP_MAX_OPTLEN);
  }
  opt_buffer = allocate_ustrmem (TCP_MAX_OPTLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "enp7s0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET6, SOCK_DGRAM, 0)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor for using ioctl().\nError message: %s\n", strerror (status));
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
  memset (&hints, 0, sizeof (struct addrinfo));
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

  // Number of TCP options
  nopt = 2;

  // First TCP option - Maximum segment size
  tcp_optlen[0] = 0;
  tcp_options[0][tcp_optlen[0]++] = 2u;    // Option kind 2 = maximum segment size
  tcp_options[0][tcp_optlen[0]++] = 4u;    // This option kind is 4 bytes long
  tcp_options[0][tcp_optlen[0]++] = 0x1u;  // Set maximum segment size to 0x100 = 256
  tcp_options[0][tcp_optlen[0]++] = 0x0u;

  // Second TCP option - Timestamp option
  tcp_optlen[1] = 0;
  tcp_options[1][tcp_optlen[1]++] = 8u;    // Option kind 8 = Timestamp option (TSOPT)
  tcp_options[1][tcp_optlen[1]++] = 10u;   // This option is 10 bytes long
  tcp_options[1][tcp_optlen[1]++] = 0x2u;  // Set the sender's timestamp (TSval) (4 bytes) (need SYN set to be valid)
  tcp_options[1][tcp_optlen[1]++] = 0x3u;
  tcp_options[1][tcp_optlen[1]++] = 0x4u;
  tcp_options[1][tcp_optlen[1]++] = 0x5u;
  // Timestamp (TSecr) (4 bytes): Zero in an initial SYN without ACK.
  tcp_options[1][tcp_optlen[1]++] = 0x0u;
  tcp_options[1][tcp_optlen[1]++] = 0x0u;
  tcp_options[1][tcp_optlen[1]++] = 0x0u;
  tcp_options[1][tcp_optlen[1]++] = 0x0u;

  // Copy all TCP options into single options buffer.
  buf_len = 0;
  c = 0;  // index to opt_buffer
  for (i = 0; i < nopt; i++) {
    memcpy (opt_buffer + c, tcp_options[i], tcp_optlen[i]);
    c += tcp_optlen[i];
    buf_len += tcp_optlen[i];
  }

  // Pad to the next 4-byte boundary.
  while ((buf_len % 4) != 0) {
    opt_buffer[buf_len] = 0;
    buf_len++;
  }

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): TCP header + TCP options
  iphdr.ip6_plen = htons (TCP_HDRLEN + buf_len);

  // Next header (8 bits): 6 for TCP
  iphdr.ip6_nxt = IPPROTO_TCP;

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

  // TCP header

  // Source port number (16 bits)
  // Some random, high ephemeral port number; Some firewalls dislike packets claiming to originate from Port 80.
  tcphdr.th_sport = htons (49152 + (rand () % 16384));

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits): Random initial sequence number (ISN)
  seq = ((uint32_t) rand () << 16) | ((uint32_t) rand () & 0xffff);
  tcphdr.th_seq = htonl (seq);

  // Acknowledgement number (32 bits): Not used in an initial SYN.
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): Should be 0.
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): Size of TCP header + length of options, in 32-bit words.
  tcphdr.th_off = (TCP_HDRLEN + buf_len) / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit): Set to 1.
  tcp_flags[1] = 1;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 0;

  // ACK flag (1 bit)
  tcp_flags[4] = 0;

  // URG flag (1 bit)
  tcp_flags[5] = 0;

  // ECE flag (1 bit)
  tcp_flags[6] = 0;

  // CWR flag (1 bit)
  tcp_flags[7] = 0;

  tcphdr.th_flags = 0;
  for (i = 0; i < 8; i++) {
    tcphdr.th_flags += (tcp_flags[i] << i);
  }

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits): Set to 0 for checksum calculation.
  tcphdr.th_sum = 0;
  tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr, opt_buffer, buf_len, NULL, 0);

  // Fill out Ethernet frame header.

  // Ethernet frame length = Ethernet header (MAC + MAC + Ethernet type) + Ethernet data (IP header + TCP header + TCP options)
  frame_length = ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN + buf_len;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, sizeof (dst_mac));
  memcpy (ether_frame + sizeof (dst_mac), src_mac, sizeof (src_mac));

  // EtherType (16 bits): ETH_P_IPV6
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_IPV6 / 256;
  ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is Ethernet frame data (IPv6 header + TCP header + TCP options).

  // IPv6 header
  memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN);

  // TCP header
  memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN);

  // TCP options
  memcpy (ether_frame + ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN, opt_buffer, buf_len);

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Send Ethernet frame to socket.
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

  // Close socket descriptor.
  close (sd);

  // Free allocated memory.
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (tcp_optlen);
  for (i = 0; i < MAX_TCP_OPTIONS; i++) {
    free (tcp_options[i]);
  }
  free (tcp_options);
  free (opt_buffer);

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

// Build IPv6 TCP pseudo-header and call checksum function.
// This version supports any combination of TCP options and TCP data:
//   options == NULL and opt_len == 0        : no TCP options
//   tcp_data == NULL and tcp_datalen == 0   : no TCP data
//   options + tcp_data                      : TCP options followed by TCP data
//
// The caller must set tcphdr.th_off before calling this function. th_off is
// the TCP header length in 32-bit words, so it must include any TCP options.
// For example:
//   tcphdr.th_off = (TCP_HDRLEN + opt_len) / 4;
//
// opt_len should normally be padded to a 4-byte boundary before calling this
// function, because TCP options are part of the TCP header and the TCP header
// length is measured in 32-bit words.
uint16_t
tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr, uint8_t *options, int opt_len, uint8_t *tcp_data, int tcp_datalen) {

  int tcp_hdrlen, tcp_segment_len, chksumlen = 0;
  uint8_t *buf, *ptr, cvalue;
  uint16_t answer = 0;
  uint32_t lvalue;

  cvalue = IPPROTO_TCP;

  if (opt_len < 0) {
    fprintf (stderr, "ERROR: opt_len must not be negative in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (tcp_datalen < 0) {
    fprintf (stderr, "ERROR: tcp_datalen must not be negative in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((opt_len > 0) && (options == NULL)) {
    fprintf (stderr, "ERROR: options is NULL but opt_len > 0 in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((tcp_datalen > 0) && (tcp_data == NULL)) {
    fprintf (stderr, "ERROR: tcp_data is NULL but tcp_datalen > 0 in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }

  tcp_hdrlen = tcphdr.th_off * 4;
  tcp_segment_len = tcp_hdrlen + tcp_datalen;

  if (tcp_hdrlen < TCP_HDRLEN) {
    fprintf (stderr, "ERROR: TCP header length is too small in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (tcp_hdrlen != (TCP_HDRLEN + opt_len)) {
    fprintf (stderr, "ERROR: TCP header length does not match TCP_HDRLEN + opt_len in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((opt_len % 4) != 0) {
    fprintf (stderr, "ERROR: TCP option length must be padded to a 4-byte boundary in tcp6_checksum().\n");
    exit (EXIT_FAILURE);
  }

  // Allocate memory for buffer.
  buf = allocate_ustrmem (40 + tcp_segment_len + 1);  // Add 1 for possible padding.
  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (tcp_segment_len);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy TCP options to buf, if any. TCP options come immediately after
  // the fixed 20-byte TCP header and before any TCP data.
  if (opt_len > 0) {
    memcpy (ptr, options, opt_len);
    ptr += opt_len;
    chksumlen += opt_len;
  }

  // Copy TCP data to buf, if any.
  if (tcp_datalen > 0) {
    memcpy (ptr, tcp_data, tcp_datalen);
    ptr += tcp_datalen;
    chksumlen += tcp_datalen;
  }

  // Pad to the next 16-bit boundary. The padding byte is used only for
  // checksum calculation and is not part of the TCP segment length.
  if ((tcp_segment_len % 2) != 0) {
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
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmemp().\n");
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
