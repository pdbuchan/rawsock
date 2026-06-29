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

// Send a "cooked" IPv4 HTTP GET packet via raw socket.
// Need to specify destination MAC address.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#define __FAVOR_BSD           // Use BSD-style networking structures. e.g., struct tcphdr
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <net/if.h>           // IFNAMSIZ
#include <linux/if_ether.h>   // ETH_P_IP
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <time.h>             // time()

#include <errno.h>            // errno, perror()

// Define some constants.
#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define TEXT_STRINGLEN 80     // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, status, datagram_length, sd, ip_flags[4] = {0}, tcp_flags[8] = {0}, tcp_datalen;
  ssize_t bytes;
  char *interface, *src_ip, *dst_ip;
  struct ip iphdr;
  struct tcphdr tcphdr;
  char *tcp_data, *url, *directory, *filename;
  uint8_t *datagram;
  uint32_t seq;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  void *tmp;

  memset (&iphdr, 0, sizeof (iphdr));
  memset (&tcphdr, 0, sizeof (tcphdr));

  // Allocate memory for various arrays.
  datagram = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (IFNAMSIZ);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  tcp_data = allocate_strmem (IP_MAXPACKET);
  url = allocate_strmem (TEXT_STRINGLEN);
  directory = allocate_strmem (TEXT_STRINGLEN);
  filename = allocate_strmem (TEXT_STRINGLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Set TCP data.
  snprintf (url, TEXT_STRINGLEN, "%s", "www.google.com");
  snprintf (directory, TEXT_STRINGLEN, "/some_directory_path/");
  snprintf (filename, TEXT_STRINGLEN, "filename");  // File we want to get
  snprintf (tcp_data, IP_MAXPACKET, "GET %s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", directory, filename, url);
  tcp_datalen = strnlen (tcp_data, IP_MAXPACKET);

  // Interface to send datagram through.
  snprintf (interface, IFNAMSIZ, "%s", "enp7s0");

  // Destination Ethernet MAC address: You need to fill these out.
  // For off-link destinations, this is normally the next-hop router's MAC address.
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (url, NULL, &hints, &res)) != 0) {
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
  memcpy (device.sll_addr, dst_mac, 6);
  device.sll_halen = 6;

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + TCP header + TCP data
  iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + tcp_datalen);

  // IPv4 Identificaiton field (16 bits)
  iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 1;

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

  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

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
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = htons (49152 + (rand () % 16384));  // Some random, high ephemeral port number; Some firewalls dislike packets claiming to originate from Port 80.

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits): random initial sequence number (ISN)
  seq = ((uint32_t) rand () << 16) | ((uint32_t) rand () & 0xffff);
  tcphdr.th_seq = htonl (seq);

  // Acknowledgement number (32 bits): 0 for this demonstration packet.
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // FIN flag (1 bit)
  tcp_flags[0] = 0;

  // SYN flag (1 bit)
  tcp_flags[1] = 0;

  // RST flag (1 bit)
  tcp_flags[2] = 0;

  // PSH flag (1 bit)
  tcp_flags[3] = 1;

  // ACK flag (1 bit)
  tcp_flags[4] = 1;

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

  // TCP checksum (16 bits)
  tcphdr.th_sum = 0;
  tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, NULL, 0, (uint8_t *) tcp_data, tcp_datalen);

  // Fill out IPv4 datagram.

  // Datagram length = IP header + TCP header + TCP data
  datagram_length = IP4_HDRLEN + TCP_HDRLEN + tcp_datalen;

  // IPv4 header
  memcpy (datagram, &iphdr, IP4_HDRLEN);

  // TCP header
  memcpy (datagram + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);

  // TCP data
  memcpy (datagram + IP4_HDRLEN + TCP_HDRLEN, tcp_data, tcp_datalen);

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
  free (datagram);
  free (interface);
  free (src_ip);
  free (dst_ip);
  free (tcp_data);
  free (url);
  free (directory);
  free (filename);

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

// Build IPv4 TCP pseudo-header and call checksum function.
// This version supports any combination of TCP options and TCP data:
//   options  == NULL and opt_len == 0       : no TCP options
//   tcp_data == NULL and tcp_datalen == 0   : no TCP data
//   options + tcp_data                      : TCP options followed by TCP data
//
// The caller must set tcphdr.th_off before calling this function.  th_off is
// the TCP header length in 32-bit words, so it must include any TCP options.
// For example:
//   tcphdr.th_off = (TCP_HDRLEN + opt_len) / 4;
//
// opt_len should normally be padded to a 4-byte boundary before calling this
// function, because TCP options are part of the TCP header and the TCP header
// length is measured in 32-bit words.
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *options, int opt_len, uint8_t *tcp_data, int tcp_datalen) {

  int tcp_hdrlen, tcp_segment_len, chksumlen = 0;
  uint8_t *buf, *ptr, cvalue;
  uint16_t svalue, answer = 0;

  if (opt_len < 0) {
    fprintf (stderr, "ERROR: opt_len must not be negative in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (tcp_datalen < 0) {
    fprintf (stderr, "ERROR: tcp_datalen must not be negative in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((opt_len > 0) && (options == NULL)) {
    fprintf (stderr, "ERROR: options is NULL but opt_len > 0 in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((tcp_datalen > 0) && (tcp_data == NULL)) {
    fprintf (stderr, "ERROR: tcp_data is NULL but tcp_datalen > 0 in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  tcp_hdrlen = tcphdr.th_off * 4;
  tcp_segment_len = tcp_hdrlen + tcp_datalen;

  if (tcp_hdrlen < TCP_HDRLEN) {
    fprintf (stderr, "ERROR: TCP header length is too small in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (tcp_hdrlen != (TCP_HDRLEN + opt_len)) {
    fprintf (stderr, "ERROR: TCP header length does not match TCP_HDRLEN + opt_len in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((opt_len % 4) != 0) {
    fprintf (stderr, "ERROR: TCP option length must be padded to a 4-byte boundary in tcp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  // Allocate memory for buffer.
  buf = allocate_ustrmem (12 + tcp_segment_len + 1);  // Add 1 for possible padding.
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

  // Copy TCP length to buf (16 bits): TCP header + TCP tcp_data.
  svalue = htons (tcp_segment_len);
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

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
  // Zero, since we don't know it yet.
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
