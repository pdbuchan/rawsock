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

// Receive an IPv6 router advertisement and extract
// various information stored in the datagram.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netinet/icmp6.h>    // struct nd_router_advert, which contains icmp6_hdr, ND_ROUTER_ADVERT
#include <netinet/in.h>       // IPPROTO_IPV6, IPPROTO_ICMPV6
#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <arpa/inet.h>        // inet_ntop()
#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // structs msghdr and cmsghdr
#include <net/if.h>           // struct ifreq
#include <poll.h>             // poll()
#include <time.h>             // clock_gettime()

#include <errno.h>            // errno

// Define some constants.
#define TIMEOUT 60000         // Request timeout in milliseconds
#define SLLA_OPTLEN 8         // Source Link-Layer Address option length.

// Function prototypes
static void *find_ancillary (struct msghdr *, int);
static uint8_t *find_nd_option (uint8_t *, ssize_t, size_t, uint8_t);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, status, sd, on, rcv_ifindex, hoplimit, timeout;
  ssize_t bytes;
  char *interface, *destination;
  struct nd_router_advert *rahdr;
  uint8_t *datagram, *opt, *slla;
  struct msghdr msghdr;
  struct iovec iov;
  struct ifreq ifr;
  struct in6_pktinfo *pktinfo;
  struct timespec start, now;
  struct pollfd pfd;

  // Allocate memory for various arrays.
  datagram = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  destination = allocate_strmem (INET6_ADDRSTRLEN);

  // Interface to receive datagram on.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Prepare msghdr for recvmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;

  memset (&iov, 0, sizeof (iov));
  iov.iov_base = (uint8_t *) datagram;
  iov.iov_len = IP_MAXPACKET;
  msghdr.msg_iov = &iov;  // Scatter/gather array (If sending multiple buffers at once, iov would be an array.)
  msghdr.msg_iovlen = 1;  // Number of elements in scatter/gather array

  msghdr.msg_control = allocate_ustrmem (CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (struct in6_pktinfo)));
  msghdr.msg_controllen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (struct in6_pktinfo));

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set flag so we receive hop limit from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof (on))) < 0) {
    status = errno;
    fprintf (stderr, "setsockopt(IPPROTO_IPV6, IPV6_RECVHOPLIMIT) failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set flag so we receive destination address from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof (on))) < 0) {
    status = errno;
    fprintf (stderr, "setsockopt(IPPROTO_IPV6, IPV6_RECVPKTINFO) failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Bind socket to interface by name.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, interface, strnlen (interface, IFNAMSIZ) + 1) < 0) {
    status = errno;
    fprintf (stderr, "setsockopt(SOL_SOCKET, SO_BINDTODEVICE) failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  rahdr = (struct nd_router_advert *) datagram;

  // Listen for incoming ICMPv6 messages.
  // A raw IPv6 socket with IPPROTO_ICMPV6 returns the ICMPv6 message,
  // beginning with the ICMPv6 header. The IPv6 header is not included;
  // selected IPv6 header fields are returned as ancillary data.
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
      fprintf (stderr, "No IPv6 Router Advertisement within %d milliseconds.\n", TIMEOUT);
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
      fprintf (stderr, "No IPv6 Router Advertisement within %d milliseconds.\n", TIMEOUT);
      exit (EXIT_FAILURE);
    }
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      fprintf (stderr, "poll() returned an error event: %hd\n", pfd.revents);
      exit (EXIT_FAILURE);
    }

    // If pfd has POLLIN set in revents, then sd (i.e., pfd.fd) is ready for reading.
    if (pfd.revents & POLLIN) {

      memset (datagram, 0, IP_MAXPACKET);
      msghdr.msg_controllen = CMSG_SPACE (sizeof (int)) + CMSG_SPACE (sizeof (struct in6_pktinfo));  // Reset: recvmsg() modifies msg_controllen.
      msghdr.msg_flags = 0;  // Reset: recvmsg() modifies msg_flags.
      if ((bytes = recvmsg (sd, &msghdr, 0)) < 0) {
        if (errno == EINTR) {
          continue;  // System call interrupted by a signal before completion. Retry.
        } else {
          fprintf (stderr, "recvmsg() failed.\nError message: %s\n", strerror (errno));
          exit (EXIT_FAILURE);
        }
      }

      // Check for sufficient bytes for Router Advertisement struct.
      if (bytes < (ssize_t) sizeof (struct nd_router_advert)) {
        continue;
      }

      // Check for IPv6 Router Advertisement.
      if (rahdr->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT) continue;

      // Received IPv6 Router Advertisement.
      break;
    }
  }
  close (sd);

  // Ancillary data
  fprintf (stdout, "\nIPv6 header data:\n");
  opt = find_ancillary (&msghdr, IPV6_HOPLIMIT);
  if (opt == NULL) {
    fprintf (stderr, "Unknown hop limit\n");
    exit (EXIT_FAILURE);
  }
  hoplimit = *(int *) opt;
  if (hoplimit != 255) {
    fprintf (stderr, "Invalid Hop Limit for Router Advertisement: %d\n", hoplimit);
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "  Hop limit: %d\n", hoplimit);

  pktinfo = find_ancillary (&msghdr, IPV6_PKTINFO);
  if (pktinfo == NULL) {
    fprintf (stderr, "Unknown destination address/interface index\n");
    exit (EXIT_FAILURE);
  }

  if (inet_ntop (AF_INET6, &(pktinfo->ipi6_addr), destination, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed for received destination address/interface index.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "  Destination address: %s\n", destination);

  rcv_ifindex = pktinfo->ipi6_ifindex;
  fprintf (stdout, "  Destination interface index: %d\n", rcv_ifindex);

  // ICMPv6 header data
  fprintf (stdout, "\nICMPv6 header data:\n");
  fprintf (stdout, "  Type (134 = Router Advertisement): %u\n", rahdr->nd_ra_hdr.icmp6_type);
  fprintf (stdout, "  Code: %u\n", rahdr->nd_ra_hdr.icmp6_code);
  fprintf (stdout, "  Checksum: %x\n", ntohs (rahdr->nd_ra_hdr.icmp6_cksum));
  fprintf (stdout, "  Hop limit recommended by this router (0 is no recommendation): %u\n", rahdr->nd_ra_curhoplimit);
  fprintf (stdout, "  Managed address configuration flag: %u\n", rahdr->nd_ra_flags_reserved >> 7);
  fprintf (stdout, "  Other stateful configuration flag: %u\n", (rahdr->nd_ra_flags_reserved >> 6) & 1);
  fprintf (stdout, "  Mobile home agent flag: %u\n", (rahdr->nd_ra_flags_reserved >> 5) & 1);
  fprintf (stdout, "  Router lifetime as default router (s): %u\n", ntohs (rahdr->nd_ra_router_lifetime));
  fprintf (stdout, "  Reachable time (ms): %u\n", ntohl (rahdr->nd_ra_reachable));
  fprintf (stdout, "  Retransmission time (ms): %u\n", ntohl (rahdr->nd_ra_retransmit));

  // Search all Neighbor Discovery options for the Source Link-Layer Address option.
  slla = find_nd_option (datagram, bytes, sizeof (struct nd_router_advert), ND_OPT_SOURCE_LINKADDR);
  if (slla != NULL && slla[1] == 1) {  // Length 1 means 8 octets total: 2 bytes option header + 6-byte MAC address.
    fprintf (stdout, "\nSource Link-Layer Address option:\n");
    fprintf (stdout, "  Type: %u\n", slla[0]);
    fprintf (stdout, "  Length: %u (units of 8 octets)\n", slla[1]);
    fprintf (stdout, "  MAC address: ");
    for (i = 2; i < 7; i++) {
      fprintf (stdout, "%02x:", slla[i]);
    }
    fprintf (stdout, "%02x\n", slla[7]);
  } else {
    fprintf (stdout, "No Source Link-Layer Address option present.\n");
  }

  // Free allocated memory.
  free (datagram);
  free (interface);
  free (destination);
  free (msghdr.msg_control);

  return (EXIT_SUCCESS);
}

// Search ancillary data for desired control-message type.
static void *
find_ancillary (struct msghdr *msg, int cmsg_type) {

  struct cmsghdr *cmsg = NULL;

  for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type)) {
      return (CMSG_DATA (cmsg));
    }
  }

  return (NULL);
}

// Search received message for desired option.
static uint8_t *
find_nd_option (uint8_t *msg, ssize_t msglen, size_t fixed_hdrlen, uint8_t opt_type) {
  
  size_t offset, optlen;

  if ((msg == NULL) || (msglen < 0) || ((size_t) msglen < fixed_hdrlen)) {
    return (NULL);
  }

  offset = fixed_hdrlen;
  while (offset + 2 <= (size_t) msglen) {

    // Neighbor Discovery option length is in units of 8 octets.
    // A zero-length option is malformed; stop to avoid an infinite loop.
    if (msg[offset + 1] == 0) {
      return (NULL);
    }
    optlen = (size_t) msg[offset + 1] * 8;

    // Stop if the claimed option length runs past the received message.
    if (offset + optlen > (size_t) msglen) {
      return (NULL);
    }

    if (msg[offset] == opt_type) {
      return (&msg[offset]);
    }

    offset += optlen;
  }

  return (NULL);
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
