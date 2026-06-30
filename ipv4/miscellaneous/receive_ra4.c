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

// Receive an IPv4 router advertisement and extract
// various information stored in the ethernet frame.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <sys/socket.h>       // socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_ICMP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip, IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_ntop()
#include <poll.h>             // poll()
#include <time.h>             // clock_gettime()
#include <netinet/ip_icmp.h>  // ICMP_ROUTERADVERT
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_IP, ETH_P_ALL

#include <errno.h>            // errno

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
#define ETH_HDRLEN ETH_HLEN  // Ethernet header length
#define IP4_HDRLEN 20        // IPv4 header length
#define ICMP_HDRLEN 8        // IPv4 ICMP header length excluding data
#define TIMEOUT 60000        // Request timeout in milliseconds

// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, offset, sd, status, iphdrlen, ip_total_len, timeout;
  ssize_t bytes;
  uint32_t preference;
  struct timespec start, now;
  struct pollfd pfd;
  uint8_t *ether_frame;
  struct ip *iphdr;
  ICMP_HDR *icmphdr;
  char *src_ip, *dst_ip;

  // Allocate memory for various arrays.
  ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Submit request for a raw socket descriptor.
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Listen for incoming ethernet frame from socket sd.
  // We expect a router advertisment ethernet frame of the form:
  //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
  //     + ethernet data (IPv4 header + RA header)
  // Keep at it until we get a router advertisement.
  pfd.fd = sd;
  pfd.events = POLLIN;
  if (clock_gettime (CLOCK_MONOTONIC, &start) < 0) {
    status = errno;
    fprintf (stderr, "clock_gettime() failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  for (;;) {
    if (clock_gettime (CLOCK_MONOTONIC, &now) < 0) {
      status = errno;
      fprintf (stderr, "clock_gettime() failed.\nError message: %s\n", strerror (status));
      exit (EXIT_FAILURE);
    }
    timeout = TIMEOUT - (int) (((now.tv_sec - start.tv_sec) * 1000) + ((now.tv_nsec - start.tv_nsec) / 1000000));
    if (timeout <= 0) {
      fprintf (stderr, "No router advertisement within %d milliseconds.\n", TIMEOUT);
      exit (EXIT_FAILURE);
    }
    status = poll (&pfd, 1, timeout);
    if (status < 0) {
      if (errno == EINTR) {
        continue;  // System call interrupted by a signal before completion. Retry.
      } else {
        fprintf (stderr, "poll() failed.\nError message: %s\n", strerror (errno));
        exit (EXIT_FAILURE);
      }
    }
    if (status == 0) {
      fprintf (stderr, "No router advertisement within %d milliseconds.\n", TIMEOUT);
      exit (EXIT_FAILURE);
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      fprintf (stderr, "poll() returned an error event: %hd\n", pfd.revents);
      exit (EXIT_FAILURE);
    }

    // If pfd has POLLIN set in revents, then sd (i.e., pfd.fd) is ready for reading.
    if (pfd.revents & POLLIN) {
      memset (ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);
      if ((bytes = recv (sd, ether_frame, ETH_HDRLEN + IP_MAXPACKET, 0)) < 0) {
        if (errno == EINTR) {
          continue;  // System call interrupted by a signal before completion. Retry.
        } else {
          fprintf (stderr, "recv() failed.\nError message: %s\n", strerror (errno));
          exit (EXIT_FAILURE);
        }
      }

      // Check for sufficient bytes to parse ethernet, IP, and ICMP headers.
      if (bytes < (ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN)) {
        continue;
      }
      if ((((ether_frame[12]) << 8) + ether_frame[13]) != ETH_P_IP) {
        continue;
      }
      iphdr = (struct ip *) (ether_frame + ETH_HDRLEN);

      // Ensure IP header length reported by IP header is consistent with bytes received.
      iphdrlen = iphdr->ip_hl * 4;
      if ((iphdrlen < IP4_HDRLEN) || (bytes < (ETH_HDRLEN + iphdrlen + ICMP_HDRLEN))) {
        continue;
      }

      // Ensure IPv4 total length is consistent with received bytes and large enough
      // to contain IPv4 header and ICMP router advertisement header.
      ip_total_len = ntohs (iphdr->ip_len);
      if ((ip_total_len < (iphdrlen + ICMP_HDRLEN)) ||
          (bytes < (ETH_HDRLEN + ip_total_len))) {
        continue;
      }

      // Ensure we have an ICMP packet.
      if (iphdr->ip_p != IPPROTO_ICMP) {
        continue;
      }

      // Ensure we have a Router Advertisement.
      icmphdr = (ICMP_HDR *) (ether_frame + ETH_HDRLEN + iphdrlen);
      if (icmphdr->type != ICMP_ROUTERADVERT) {
        continue;
      }
      if (icmphdr->code != 0) {
        continue;
      }

      // Ensure valid Address Entry Size (units of 32-bit words); Must be 2.
      if (icmphdr->entry_size != 2) {
        continue;
      }

      // Ensure IPv4 total length and received bytes are consistent with number of
      // addresses the Router Advertisement claims.
      if ((ip_total_len < (iphdrlen + ICMP_HDRLEN + (icmphdr->num_addrs * icmphdr->entry_size * 4))) ||
          (bytes < (ETH_HDRLEN + ip_total_len))) {
        continue;
      }
      break;
    }
  }
  close (sd);

  // Print out contents of received ethernet frame.
  fprintf (stdout, "\nRECEIVED ETHERNET FRAME\n");
  fprintf (stdout, "  Ethernet frame header:\n");
  fprintf (stdout, "    Destination MAC address (expect 01:00:5e:00:00:01 associated with IPv4 all-devices multi-cast address): ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", ether_frame[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Source MAC address: ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", ether_frame[i + 6], (i < 5) ? ":" : "\n");
  }
  // Next is ethernet type code (ETH_P_IP for IPv4 packets).
  // http://www.iana.org/assignments/ethernet-numbers
  fprintf (stdout, "    Ethernet type code (2048 = IPv4): %u\n\n", ((ether_frame[12]) << 8) + ether_frame[13]);

  fprintf (stdout, "  IPv4 header\n");
  fprintf (stdout, "    IPv4 transport layer protocol (1 = ICMP): %u\n", iphdr->ip_p);
  if (inet_ntop (AF_INET, &(iphdr->ip_src), src_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for received source address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "    Source IPv4 address: %s\n", src_ip);
  if (inet_ntop (AF_INET, &(iphdr->ip_dst), dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for received destination address.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "    Destination IPv4 address (expect IPv4 all-devices multi-cast address 224.0.0.1): %s\n\n", dst_ip);
  fprintf (stdout, "  ICMP Message (Router Advertisement)\n");
  fprintf (stdout, "    ICMP message type (9 = Router Advertisement): %u\n", icmphdr->type);
  fprintf (stdout, "    ICMP message code: %u\n", icmphdr->code);
  fprintf (stdout, "    Router address entry size (in units of 32-bit words): %u\n", icmphdr->entry_size);
  fprintf (stdout, "    Lifetime of validity of Router Advertisement (seconds): %u\n", ntohs (icmphdr->lifetime));
  fprintf (stdout, "    Number of IPv4 addresses associated with router: %u\n", icmphdr->num_addrs);
  offset = ETH_HDRLEN + iphdrlen + ICMP_HDRLEN;  // Start of list of addresses and preference levels within ethernet frame
  for (i = 0; i < icmphdr->num_addrs; i++) {
    fprintf (stdout, "      Router %d IPv4 address: %u.%u.%u.%u\n",
     i, ether_frame[offset + 0],
        ether_frame[offset + 1],
        ether_frame[offset + 2],
        ether_frame[offset + 3]);
    memcpy (&preference, ether_frame + offset + 4, sizeof (preference));
    fprintf (stdout, "      Router %d preference level: %d\n", i, (int32_t) ntohl (preference));
    offset += (icmphdr->entry_size * 4);
  }

  free (ether_frame);
  free (src_ip);
  free (dst_ip);

  return (EXIT_SUCCESS);
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
