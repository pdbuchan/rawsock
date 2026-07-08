/*  Copyright (C) 2026  P.D. Buchan (pdbuchan@gmail.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
*/

// Perform a traceroute by sending IPv6 TCP, UDP, or ICMPv6 packets via
// raw socket at the link layer (Ethernet frame).
// Need to have destination MAC address.
// TCP set for SYN, UDP for port unreachable, ICMPv6 for echo request (ping).

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#define __FAVOR_BSD           // Use BSD-style networking structures. e.g., struct tcphdr
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy(), strlen()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo, getaddrinfo(), getnameinfo()
#include <sys/socket.h>       // socket(), bind()
#include <netinet/in.h>       // IPPROTO_TCP, IPPROTO_ICMPV6, IPPROTO_UDP, INET6_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>    // struct icmp6_hdr
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>      // struct udphdr
#include <fcntl.h>            // fcntl()
#include <poll.h>             // poll()
#include <arpa/inet.h>        // inet_pton(), inet_ntop()
#include <sys/ioctl.h>        // ioctl()
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_IPV6, ETH_P_ALL
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <limits.h>           // HOST_NAME_MAX
#include <time.h>             // time(), clock_gettime(), CLOCK_MONOTONIC
#include <errno.h>            // errno

// Define some constants.
#define ETH_HDRLEN ETH_HLEN   // Ethernet header length
#define MAC_LEN 6             // Length of a hardware (MAC) address
#define IP6_HDRLEN 40         // IPv6 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define UDP_HDRLEN 8          // UDP header length, excludes data
#define ICMP_HDRLEN 8         // ICMPv6 header length for Echo Request, excludes data
#define TIMEOUT 2             // Time for receive socket to wait for a reply (s)
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes.
uint16_t checksum (uint8_t *, int);
uint16_t icmp6_checksum (struct ip6_hdr, uint8_t *, int);
uint16_t tcp6_checksum (struct ip6_hdr, struct tcphdr, uint8_t *, int, uint8_t *, int);
uint16_t udp6_checksum (struct ip6_hdr, struct udphdr, uint8_t *, int);
int create_tcp_frame (uint8_t *, char *, char *, uint8_t *, uint8_t *, uint16_t, int, uint8_t *, int);
int create_icmp_frame (uint8_t *, char *, char *, uint8_t *, uint8_t *, uint16_t, uint16_t, int, uint8_t *, int);
int create_udp_frame (uint8_t *, char *, char *, uint8_t *, uint8_t *, uint16_t, uint16_t, int, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, frame_length, sd, sendsd, recsd, flags, node, trylim, trycount, timeout_ms;
  int packet_type, done, datalen, resolve, maxhops, probes, num_probes, probe_index;
  int ip_payload_len, inner_payload_len;
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip, *rec_ip, *tcp_dat, *icmp_dat, *udp_dat;
  char hostname[HOST_NAME_MAX];
  struct ip6_hdr *iphdr, *inner_ip;
  struct tcphdr *tcphdr, *inner_tcp;
  struct icmp6_hdr *icmphdr, *inner_icmp;
  struct udphdr *inner_udp;
  uint8_t src_mac[MAC_LEN] = {0};
  uint8_t *snd_ether_frame, *rec_ether_frame, *data;
  uint16_t tcp_sport, icmpid, icmpseq, udp_sport, udp_dport;
  struct addrinfo hints, *res;
  struct sockaddr_in6 dst, sa;
  struct sockaddr_ll device, from;
  struct ifreq ifr;
  socklen_t fromlen;
  struct timespec t1, t2;
  struct pollfd pfd;
  double elapsed, remaining;

  // Choose whether to resolve IPs to hostnames: 0 = do not resolve, 1 = resolve.
  resolve = 0;

  // Number of probes per node.
  num_probes = 3;

  // Choose type of packet to send: 1 = TCP, 2 = ICMPv6, 3 = UDP
  packet_type = 1;

  // Maximum number of hops allowed.
  maxhops = 30;

  // Random number seed
  srand ((unsigned) time (NULL));

  // ICMPv6 Identifier (16 bits): Usually pid of sending process; You can choose.
  icmpid = htons (1000);

  // UDP source port (16 bits): You can choose.
  udp_sport = htons (4950);

  // Allocate memory for various arrays.
  tcp_dat = allocate_strmem (IP_MAXPACKET);
  icmp_dat = allocate_strmem (IP_MAXPACKET);
  udp_dat = allocate_strmem (IP_MAXPACKET);
  data = allocate_ustrmem (IP_MAXPACKET);
  rec_ip = allocate_strmem (INET6_ADDRSTRLEN);
  snd_ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  rec_ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET6_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN);

  // Payloads for TCP, UDP, and ICMPv6 packets.
  memset (tcp_dat, 0, IP_MAXPACKET);  // No TCP data.
  snprintf (icmp_dat, IP_MAXPACKET, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");
  snprintf (udp_dat, IP_MAXPACKET, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");

  // Check for acceptable payload lengths.
  if (strlen (tcp_dat) > (IP_MAXPACKET - IP6_HDRLEN - TCP_HDRLEN)) {
    fprintf (stderr, "Maximum TCP data length exceeded. Maximum length is %d\n", IP_MAXPACKET - IP6_HDRLEN - TCP_HDRLEN);
    exit (EXIT_FAILURE);
  }
  if (strlen (icmp_dat) > (IP_MAXPACKET - IP6_HDRLEN - ICMP_HDRLEN)) {
    fprintf (stderr, "Maximum ICMPv6 data length exceeded. Maximum length is %d\n", IP_MAXPACKET - IP6_HDRLEN - ICMP_HDRLEN);
    exit (EXIT_FAILURE);
  }
  if (strlen (udp_dat) > (IP_MAXPACKET - IP6_HDRLEN - UDP_HDRLEN)) {
    fprintf (stderr, "Maximum UDP data length exceeded. Maximum length is %d\n", IP_MAXPACKET - IP6_HDRLEN - UDP_HDRLEN);
    exit (EXIT_FAILURE);
  }

  // Interface to send packet through.
  // You need to put your network interface name here.
  snprintf (interface, sizeof (ifr.ifr_name), "enp7s0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET6, SOCK_DGRAM, 0)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor for using ioctl().\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface and get MAC address.
  memset (&ifr, 0, sizeof (ifr));
  n = snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if ((n < 0) || (n >= (int) sizeof (ifr.ifr_name))) {
    fprintf (stderr, "Invalid interface name: %s\n", interface);
    close (sd);
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

  // Show target of traceroute.
  switch (packet_type) {

    case 1:  // TCP
      fprintf (stdout, "\nTCP traceroute to %s (%s)\n", target, dst_ip);
      fprintf (stdout, "Using TCP source ports in the high ephemeral range.\n");
      break;

    case 2:  // ICMPv6
      fprintf (stdout, "\nICMPv6 traceroute to %s (%s)\n", target, dst_ip);
      break;

    case 3:  // UDP
      fprintf (stdout, "\nUDP traceroute to %s (%s)\n", target, dst_ip);
      break;

    default:
      fprintf (stderr, "Unknown packet type: %d\n", packet_type);
      exit (EXIT_FAILURE);

  }  // End switch

  // Submit request for a raw socket descriptor to send.
  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get send socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Submit request for a raw socket descriptor to receive.
  // Use ETH_P_IPV6 in order to only look at IPv6 packets; could use ETH_P_ALL but likely slower on a busy network.
  if ((recsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IPV6))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get receive socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Bind receive socket to the chosen interface.
  if (bind (recsd, (struct sockaddr *) &device, sizeof (device)) < 0) {
    status = errno;
    fprintf (stderr, "bind() failed to bind receive socket to interface.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set receive socket to be non-blocking. We will use poll() to monitor the socket for incoming data.
  // First, obtain existing flags from receive socket.
  if ((flags = fcntl (recsd, F_GETFL, 0)) == -1) {
    status = errno;
    fprintf (stderr, "fcntl() failed to obtain flags from receive socket.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set flag to make receive socket non-blocking.
  if (fcntl (recsd, F_SETFL, flags | O_NONBLOCK) == -1) {
    status = errno;
    fprintf (stderr, "fcntl() failed to set non-blocking flag on receive socket.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set maximum number of tries for a host before incrementing Hop Limit and moving on.
  trylim = 3;

  // Start at Hop Limit = 1. i.e., one hop.
  node = 1;

  // Initialize some parameters.
  done = 0;
  trycount = 0;
  probes = 0;

  // OUTER SEND LOOP: incrementing TTL each cycle, exiting when we get our target IP address.
  for (;;) {

    // Create probe packet.
    probe_index = ((node - 1) * num_probes) + probes;
    tcp_sport = htons (49152 + probe_index % 16384);  // Some high ephemeral port number.
    icmpseq = htons (probe_index);  // ICMPv6 sequence number (16 bits).
    udp_dport = htons (33434 + probe_index);  // UDP destination port (16 bits).

    memset (snd_ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);
    switch (packet_type) {

      case 1:  // TCP
        datalen = strlen (tcp_dat);
        memcpy (data, tcp_dat, datalen);
        create_tcp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, tcp_sport, node, data, datalen);
        frame_length = ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN + datalen;
        break;

      case 2:  // ICMPv6
        datalen = strlen (icmp_dat);
        memcpy (data, icmp_dat, datalen);
        create_icmp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, icmpid, icmpseq, node, data, datalen);
        frame_length = ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN + datalen;
        break;

      case 3:  // UDP
        datalen = strlen (udp_dat);
        memcpy (data, udp_dat, datalen);
        create_udp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, udp_sport, udp_dport, node, data, datalen);
        frame_length = ETH_HDRLEN + IP6_HDRLEN + UDP_HDRLEN + datalen;
        break;

      default:
        fprintf (stderr, "Unknown packet type: %d\n", packet_type);
        exit (EXIT_FAILURE);

    }  // End switch

    // Send Ethernet frame to socket.
    bytes = sendto (sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
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

    // Increment probe count.
    probes++;

    // Start timer.
    if (clock_gettime (CLOCK_MONOTONIC, &t1) < 0) {
      status = errno;
      fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
      exit (EXIT_FAILURE);
    }

    // Listen for incoming Ethernet frame from socket recsd.
    //
    // If we have not reached the destination because Hop Limit reached 0,
    // we expect an ICMPv6 Time Exceeded message containing the invoking packet:
    //     Ethernet header + outer IPv6 header + ICMPv6 header +
    //     inner IPv6 header + TCP/ICMPv6/UDP header.
    //
    // If we have reached our destination, we expect one of:
    //     IPv6 header + TCP (SYN-ACK or RST)
    //     IPv6 header + ICMPv6 Echo Reply + payload
    //     Outer IPv6 header + ICMPv6 Destination Unreachable/Port Unreachable +
    //       inner IPv6 header + UDP header.
    //
    // Keep listening for up to TIMEOUT seconds, or until a reply is received.

    // INNER RECEIVE LOOP
    for (;;) {

      memset (rec_ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);
      memset (&from, 0, sizeof (from));
      fromlen = sizeof (from);

      // Set up pollfd structure for poll().
      memset (&pfd, 0, sizeof (pfd));
      pfd.fd = recsd;
      pfd.events = POLLIN;

      // Calculate elapsed and remaining times.
      if (clock_gettime (CLOCK_MONOTONIC, &t2) < 0) {
        status = errno;
        fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
        exit (EXIT_FAILURE);
      }
      elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;
      remaining = TIMEOUT - elapsed;

      if (remaining <= 0.0) {
        fprintf (stdout, "%2d  No reply within %d seconds.\n", node, TIMEOUT);
        trycount++;
        break;
      }

      timeout_ms = (int) (remaining * 1000.0);  // milliseconds.
      if (timeout_ms < 1) timeout_ms = 1;

      // Wait for data to be available on our receive socket, or until we time out.
      status = poll (&pfd, 1, timeout_ms);
      if (status < 0) {
        status = errno;
        if (status == EINTR) {
          continue;
        } else {
          fprintf (stderr, "poll() failed. Error message: %s\n", strerror (status));
          exit (EXIT_FAILURE);
        }
      }

      // Receive socket timed out.
      if (status == 0) {
        fprintf (stdout, "%2d  No reply within %d seconds.\n", node, TIMEOUT);
        trycount++;
        break;  // Break out of receive loop.
      }

      // Check for socket error conditions reported by poll().
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        fprintf (stderr, "poll() reported socket error: revents = 0x%x.\n", pfd.revents);
        exit (EXIT_FAILURE);
      }

      // If pfd has POLLIN set in revents, then recsd (i.e., pfd.fd) is ready for reading.
      if (pfd.revents & POLLIN) {

        // Read available data from recsd.
        bytes = recvfrom (recsd, rec_ether_frame, ETH_HDRLEN + IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen);

        // Deal with error conditions first.
        if (bytes < 0) {
          status = errno;
          if ((status == EINTR) || (status == EAGAIN) || (status == EWOULDBLOCK)) {
            continue;
          } else {
            fprintf (stderr, "recvfrom() failed. Error message: %s\n", strerror (status));
            exit (EXIT_FAILURE);
          }
        }

        // Check for sufficient bytes to parse Ethernet and IPv6 headers.
        if (bytes < (ETH_HDRLEN + IP6_HDRLEN)) continue;

      // poll() returned, but no readable data was available; keep listening.
      } else {
        continue;
      }

      // Check for an IPv6 Ethernet frame. If not, ignore and keep listening.
      if (((rec_ether_frame[12] << 8) + rec_ether_frame[13]) != ETH_P_IPV6) continue;

      // Determine offset to IPv6 header.
      iphdr = (struct ip6_hdr *) (rec_ether_frame + ETH_HDRLEN);

      // Check for IPv6 version.
      if ((iphdr->ip6_vfc >> 4) != 6) continue;

      // Check for malformed or truncated packet.
      ip_payload_len = ntohs (iphdr->ip6_plen);
      if (bytes < (ETH_HDRLEN + IP6_HDRLEN + ip_payload_len)) continue;

      // This example does not parse received IPv6 extension headers.
      if ((iphdr->ip6_nxt != IPPROTO_ICMPV6) && (iphdr->ip6_nxt != IPPROTO_TCP)) continue;

      // Determine offsets to possible headers.
      icmphdr = (struct icmp6_hdr *) (rec_ether_frame + ETH_HDRLEN + IP6_HDRLEN);
      tcphdr = (struct tcphdr *) (rec_ether_frame + ETH_HDRLEN + IP6_HDRLEN);

      // Did we get an ICMPv6 Time Exceeded?
      // i.e., Hop Limit reached 0 before packet reached destination.
      if ((iphdr->ip6_nxt == IPPROTO_ICMPV6) &&
          (ip_payload_len >= ICMP_HDRLEN) &&
          (icmphdr->icmp6_type == ICMP6_TIME_EXCEEDED)) {

        // Check for malformed packet.
        inner_ip = (struct ip6_hdr *) (rec_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN);
        if (((uint8_t *) inner_ip + IP6_HDRLEN) > rec_ether_frame + bytes) continue;
        if ((inner_ip->ip6_vfc >> 4) != 6) continue;

        inner_payload_len = ntohs (inner_ip->ip6_plen);
        if (((uint8_t *) inner_ip + IP6_HDRLEN + inner_payload_len) > rec_ether_frame + bytes) {
          // Routers are not required to return the entire invoking packet,
          // but we need enough to identify the inner transport header.
        }

        // Ensure embedded packet belongs to our probe.
        switch (packet_type) {

          case 1:  // TCP; many routers provide only the first 8 bytes of TCP header in this reply.
            if (((uint8_t *) inner_ip + IP6_HDRLEN + 8) > rec_ether_frame + bytes) continue;
            inner_tcp = (struct tcphdr *) ((uint8_t *) inner_ip + IP6_HDRLEN);
            if (inner_ip->ip6_nxt != IPPROTO_TCP) continue;
            if (inner_tcp->th_sport != tcp_sport) continue;
            if (inner_tcp->th_dport != htons (80)) continue;
            break;

          case 2:  // ICMPv6.
            if (((uint8_t *) inner_ip + IP6_HDRLEN + ICMP_HDRLEN) > rec_ether_frame + bytes) continue;
            inner_icmp = (struct icmp6_hdr *) ((uint8_t *) inner_ip + IP6_HDRLEN);
            if (inner_ip->ip6_nxt != IPPROTO_ICMPV6) continue;
            if (inner_icmp->icmp6_id != icmpid) continue;
            if (inner_icmp->icmp6_seq != icmpseq) continue;
            break;

          case 3:  // UDP.
            if (((uint8_t *) inner_ip + IP6_HDRLEN + UDP_HDRLEN) > rec_ether_frame + bytes) continue;
            inner_udp = (struct udphdr *) ((uint8_t *) inner_ip + IP6_HDRLEN);
            if (inner_ip->ip6_nxt != IPPROTO_UDP) continue;
            if (inner_udp->uh_sport != udp_sport) continue;
            if (inner_udp->uh_dport != udp_dport) continue;
            break;

        } // End switch.

        // Initialize count of tries.
        trycount = 0;

        // Stop timer and calculate how long it took to get a reply.
        if (clock_gettime (CLOCK_MONOTONIC, &t2) < 0) {
          status = errno;
          fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
          exit (EXIT_FAILURE);
        }
        elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;

        // Extract source IPv6 address from received Ethernet frame.
        if (inet_ntop (AF_INET6, &(iphdr->ip6_src), rec_ip, INET6_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed for received source address.\nError message: %s\n", strerror (status));
          exit (EXIT_FAILURE);
        }

        // Report source IP address and time for reply.
        if (resolve == 0) {
          fprintf (stdout, "%2d  %s  %g ms (%zd bytes received)", node, rec_ip, elapsed * 1000.0, bytes);
        } else {
          memset (&sa, 0, sizeof (sa));
          sa.sin6_family = AF_INET6;
          if ((status = inet_pton (AF_INET6, rec_ip, &sa.sin6_addr)) != 1) {
            if (status == 0) {
              fprintf (stderr, "inet_pton() failed for received source address.\nError message: Invalid address\n");
            } else if (status < 0) {
              fprintf (stderr, "inet_pton() failed for received source address.\nError message: %s\n", strerror (errno));
            }
            exit (EXIT_FAILURE);
          }
          if ((status = getnameinfo ((struct sockaddr *) &sa, sizeof (sa), hostname, sizeof (hostname), NULL, 0, 0)) != 0) {
            fprintf (stderr, "getnameinfo() failed for received source address.\nError message: %s\n", gai_strerror (status));
            exit (EXIT_FAILURE);
          }
          fprintf (stdout, "%2d  %s (%s)  %g ms (%zd bytes received)", node, rec_ip, hostname, elapsed * 1000.0, bytes);
        }

        if (probes < num_probes) {
          fprintf (stdout, " : ");
          break;  // Break out of receive loop and probe this node again.
        } else {
          fprintf (stdout, "\n");
          node++;  // Increment Hop Limit.
          probes = 0;
          break;  // Break out of receive loop and probe next node in route.
        }
      }  // End of ICMPv6 Time Exceeded conditional.

      // Did we reach our destination?
      // TCP SYN-ACK or RST means TCP SYN packet reached destination node.
      // ICMPv6 Echo Reply means ICMPv6 Echo Request packet reached destination node.
      // ICMPv6 Destination Unreachable / Port Unreachable means UDP packet reached destination node.
      if (((iphdr->ip6_nxt == IPPROTO_TCP) &&
           (ip_payload_len >= TCP_HDRLEN) &&
           (((tcphdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) || (tcphdr->th_flags & TH_RST))) ||
          ((iphdr->ip6_nxt == IPPROTO_ICMPV6) &&
           (ip_payload_len >= ICMP_HDRLEN) &&
           (icmphdr->icmp6_type == ICMP6_ECHO_REPLY) &&
           (icmphdr->icmp6_code == 0)) ||
          ((iphdr->ip6_nxt == IPPROTO_ICMPV6) &&
           (ip_payload_len >= ICMP_HDRLEN) &&
           (icmphdr->icmp6_type == ICMP6_DST_UNREACH) &&
           (icmphdr->icmp6_code == ICMP6_DST_UNREACH_NOPORT))) {

        // Stop timer and calculate how long in ms it took to get a reply.
        if (clock_gettime (CLOCK_MONOTONIC, &t2) < 0) {
          status = errno;
          fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
          exit (EXIT_FAILURE);
        }
        elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;

        // Ensure received packet is not malformed and is a reply to our probe, not other network traffic.
        switch (packet_type) {

          case 1:  // TCP.
            if (iphdr->ip6_nxt != IPPROTO_TCP) continue;
            if (ip_payload_len < TCP_HDRLEN) continue;
            if (tcphdr->th_sport != htons (80)) continue;
            if (tcphdr->th_dport != tcp_sport) continue;
            break;

          case 2:  // ICMPv6.
            if (iphdr->ip6_nxt != IPPROTO_ICMPV6) continue;
            if (ip_payload_len < ICMP_HDRLEN) continue;
            if (icmphdr->icmp6_type != ICMP6_ECHO_REPLY) continue;
            if (icmphdr->icmp6_code != 0) continue;
            if (icmphdr->icmp6_id != icmpid) continue;
            if (icmphdr->icmp6_seq != icmpseq) continue;
            break;

          case 3:  // UDP.
            if (iphdr->ip6_nxt != IPPROTO_ICMPV6) continue;
            if (ip_payload_len < ICMP_HDRLEN) continue;
            if (icmphdr->icmp6_type != ICMP6_DST_UNREACH) continue;
            if (icmphdr->icmp6_code != ICMP6_DST_UNREACH_NOPORT) continue;

            inner_ip = (struct ip6_hdr *) (rec_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN);
            if (((uint8_t *) inner_ip + IP6_HDRLEN) > rec_ether_frame + bytes) continue;
            if ((inner_ip->ip6_vfc >> 4) != 6) continue;
            if (((uint8_t *) inner_ip + IP6_HDRLEN + UDP_HDRLEN) > rec_ether_frame + bytes) continue;
            inner_udp = (struct udphdr *) ((uint8_t *) inner_ip + IP6_HDRLEN);
            if (inner_ip->ip6_nxt != IPPROTO_UDP) continue;
            if (inner_udp->uh_sport != udp_sport) continue;
            if (inner_udp->uh_dport != udp_dport) continue;
            break;

        }  // End switch.

        // Extract source IPv6 address from received Ethernet frame.
        if (inet_ntop (AF_INET6, &(iphdr->ip6_src), rec_ip, INET6_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed for received source address.\nError message: %s\n", strerror (status));
          exit (EXIT_FAILURE);
        }

        // Report source IP address and time for reply.
        fprintf (stdout, "%2d  %s  %g ms", node, rec_ip, elapsed * 1000.0);
        if (probes < num_probes) {
          fprintf (stdout, " : ");
          break;  // Break out of receive loop and probe this node again.
        } else {
          fprintf (stdout, "\n");
          done = 1;
          break;  // Break out of receive loop and finish.
        }
      }  // End of reached-destination conditional.
    }  // End of receive loop.

    // Reached destination node.
    if (done == 1) {
      fprintf (stdout, "Traceroute complete.\n\n");
      break;  // Break out of send loop.

    // Reached maxhops.
    } else if (node > maxhops) {
      fprintf (stdout, "Reached maximum number of hops. Maximum is set to %d hops.\n", maxhops);
      break;  // Break out of send loop.
    }

    // We ran out of tries; move on to next node unless we reached maxhops limit.
    if (trycount == trylim) {
      fprintf (stdout, "%2d  Node won't respond after %d probes.\n", node, trylim);
      node++;  // Increment Hop Limit.
      probes = 0;
      trycount = 0;
      continue;
    }
  }  // End of send loop.

  // Close socket descriptors.
  close (sendsd);
  close (recsd);

  // Free allocated memory.
  free (tcp_dat);
  free (icmp_dat);
  free (udp_dat);
  free (data);
  free (snd_ether_frame);
  free (rec_ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (rec_ip);

  return (EXIT_SUCCESS);
}

// Create a TCP Ethernet frame.
int
create_tcp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                  uint16_t tcp_sport, int hop_limit, uint8_t *data, int datalen) {

  int status;
  uint32_t seq;
  struct ip6_hdr iphdr = {0};
  struct tcphdr tcphdr = {0};

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): TCP header + TCP data
  iphdr.ip6_plen = htons (TCP_HDRLEN + datalen);

  // Next Header (8 bits): TCP
  iphdr.ip6_nxt = IPPROTO_TCP;

  // Hop Limit (8 bits)
  iphdr.ip6_hops = hop_limit;

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
  tcphdr.th_sport = tcp_sport;

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits): Random initial sequence number (ISN).
  seq = ((uint32_t) rand () << 16) | ((uint32_t) rand () & 0xffff);
  tcphdr.th_seq = htonl (seq);

  // Acknowledgement number (32 bits): Not used in an initial SYN.
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): Should be 0.
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): Size of TCP header in 32-bit words.
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits): SYN
  tcphdr.th_flags = TH_SYN;

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits): Set to 0 for checksum calculation.
  tcphdr.th_sum = 0;
  tcphdr.th_sum = tcp6_checksum (iphdr, tcphdr, NULL, 0, data, datalen);

  // Fill out Ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, MAC_LEN);
  memcpy (snd_ether_frame + MAC_LEN, src_mac, MAC_LEN);

  // EtherType (16 bits): ETH_P_IPV6
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IPV6 / 256;
  snd_ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is Ethernet frame data (IPv6 header + TCP header + TCP data).

  // IPv6 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN);

  // TCP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &tcphdr, TCP_HDRLEN);

  // TCP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN + TCP_HDRLEN, data, datalen);

  return (EXIT_SUCCESS);
}

// Create an ICMPv6 Ethernet frame.
int
create_icmp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                   uint16_t icmpid, uint16_t icmpseq, int hop_limit, uint8_t *data, int datalen) {

  int status;
  struct ip6_hdr iphdr = {0};
  struct icmp6_hdr icmphdr = {0};

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): ICMPv6 header + ICMPv6 data
  iphdr.ip6_plen = htons (ICMP_HDRLEN + datalen);

  // Next Header (8 bits): ICMPv6
  iphdr.ip6_nxt = IPPROTO_ICMPV6;

  // Hop Limit (8 bits)
  iphdr.ip6_hops = hop_limit;

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

  // ICMPv6 header

  // Message Type (8 bits): Echo Request
  icmphdr.icmp6_type = ICMP6_ECHO_REQUEST;

  // Message Code (8 bits): 0 for Echo Request
  icmphdr.icmp6_code = 0;

  // Identifier (16 bits)
  icmphdr.icmp6_id = icmpid;

  // Sequence Number (16 bits)
  icmphdr.icmp6_seq = icmpseq;

  // ICMPv6 checksum (16 bits): Set to 0 for checksum calculation.
  icmphdr.icmp6_cksum = 0;

  // Fill out Ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, MAC_LEN);
  memcpy (snd_ether_frame + MAC_LEN, src_mac, MAC_LEN);

  // EtherType (16 bits): ETH_P_IPV6
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IPV6 / 256;
  snd_ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is Ethernet frame data (IPv6 header + ICMPv6 header + ICMPv6 data).

  // IPv6 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN);

  // ICMPv6 header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &icmphdr, ICMP_HDRLEN);

  // ICMPv6 data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN + ICMP_HDRLEN, data, datalen);

  // ICMPv6 checksum
  icmphdr.icmp6_cksum = icmp6_checksum (iphdr, snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN, ICMP_HDRLEN + datalen);
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &icmphdr, ICMP_HDRLEN);

  return (EXIT_SUCCESS);
}

// Create a UDP Ethernet frame.
int
create_udp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                  uint16_t udp_sport, uint16_t udp_dport, int hop_limit, uint8_t *data, int datalen) {

  int status;
  struct ip6_hdr iphdr = {0};
  struct udphdr udphdr = {0};

  // IPv6 header

  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
  iphdr.ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);

  // Payload length (16 bits): UDP header + UDP data
  iphdr.ip6_plen = htons (UDP_HDRLEN + datalen);

  // Next Header (8 bits): UDP
  iphdr.ip6_nxt = IPPROTO_UDP;

  // Hop Limit (8 bits)
  iphdr.ip6_hops = hop_limit;

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

  // UDP header

  // Source port number (16 bits)
  udphdr.uh_sport = udp_sport;

  // Destination port number (16 bits)
  udphdr.uh_dport = udp_dport;

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.uh_ulen = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits): Set to 0 for checksum calculation.
  udphdr.uh_sum = 0;
  udphdr.uh_sum = udp6_checksum (iphdr, udphdr, data, datalen);

  // Fill out Ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, MAC_LEN);
  memcpy (snd_ether_frame + MAC_LEN, src_mac, MAC_LEN);

  // EtherType (16 bits): ETH_P_IPV6.
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IPV6 / 256;
  snd_ether_frame[13] = ETH_P_IPV6 % 256;

  // Next is Ethernet frame data (IPv6 header + UDP header + UDP data).

  // IPv6 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN);

  // UDP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN, &udphdr, UDP_HDRLEN);

  // UDP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP6_HDRLEN + UDP_HDRLEN, data, datalen);

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
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's complement of sum. Return it in network byte order
  // so it can be copied directly into the packet header.
  answer = ~sum;

  return (htons (answer));
}

// Calculate ICMPv6 checksum.
// Computes the checksum over the complete ICMPv6 message:
//
//   ICMPv6 header + ICMPv6 data
//
// The IPv6 pseudo-header is built from the supplied IPv6 header.
uint16_t
icmp6_checksum (struct ip6_hdr iphdr, uint8_t *icmp_msg, int icmp_len) {

  int chksumlen = 0;
  uint8_t *buf, *ptr, cvalue;
  uint16_t answer = 0;
  uint32_t lvalue;

  if (icmp_len < 4) {
    fprintf (stderr, "ERROR: icmp_len must be at least 4 bytes in icmp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if (icmp_msg == NULL) {
    fprintf (stderr, "ERROR: icmp_msg is NULL in icmp6_checksum().\n");
    exit (EXIT_FAILURE);
  }

  cvalue = IPPROTO_ICMPV6;

  // Allocate memory for buffer.
  buf = allocate_ustrmem (40 + icmp_len + 1);  // Add 1 for possible padding.
  ptr = &buf[0];

  // Copy source IP address into buf (128 bits).
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits).
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy ICMPv6 length to buf (32 bits).
  lvalue = htonl (icmp_len);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits).
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy ICMPv6 message to buf after zeroing checksum field.
  memcpy (ptr, icmp_msg, icmp_len);
  ptr[2] = 0;
  ptr[3] = 0;
  ptr += icmp_len;
  chksumlen += icmp_len;

  // Pad to the next 16-bit boundary. The padding byte is used only for
  // checksum calculation and is not part of the ICMPv6 message length.
  if ((icmp_len % 2) != 0) {
    *ptr = 0;
    chksumlen++;
  }

  answer = checksum (buf, chksumlen);
  free (buf);

  return (answer);
}

// Build IPv6 TCP pseudo-header and call checksum function.
// This version supports any combination of TCP options and TCP data:
//   options == NULL and opt_len == 0        : no TCP options
//   tcp_data == NULL and tcp_datalen == 0   : no TCP data
//   options + tcp_data                      : TCP options followed by TCP data
//
// The caller must set tcphdr.th_off before calling this function. th_off is
// the TCP header length in 32-bit words, so it must include any TCP options.
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
  ptr = &buf[0];

  // Copy source IP address into buf (128 bits).
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits).
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits).
  lvalue = htonl (tcp_segment_len);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits).
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP source port to buf (16 bits).
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits).
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits).
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits).
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and copy reserved bits to buf (4 bits).
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits).
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits).
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits): zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits).
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  // Copy TCP options to buf, if any.
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

  answer = checksum (buf, chksumlen);
  free (buf);

  return (answer);
}

// Build IPv6 UDP pseudo-header and call checksum function.
uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *udp_data, int udp_datalen) {

  int udp_datagram_len, chksumlen = 0;
  uint8_t *buf, *ptr, cvalue;
  uint16_t answer = 0;
  uint32_t lvalue;

  if (udp_datalen < 0) {
    fprintf (stderr, "ERROR: udp_datalen must not be negative in udp6_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((udp_datalen > 0) && (udp_data == NULL)) {
    fprintf (stderr, "ERROR: udp_data is NULL but udp_datalen > 0 in udp6_checksum().\n");
    exit (EXIT_FAILURE);
  }

  cvalue = IPPROTO_UDP;
  udp_datagram_len = UDP_HDRLEN + udp_datalen;

  // Allocate memory for buffer.
  buf = allocate_ustrmem (40 + udp_datagram_len + 1);  // Add 1 for possible padding.
  ptr = &buf[0];

  // Copy source IP address into buf (128 bits).
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits).
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy UDP length to buf (32 bits).
  lvalue = htonl (udp_datagram_len);
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits).
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy UDP source port to buf (16 bits).
  memcpy (ptr, &udphdr.uh_sport, sizeof (udphdr.uh_sport));
  ptr += sizeof (udphdr.uh_sport);
  chksumlen += sizeof (udphdr.uh_sport);

  // Copy UDP destination port to buf (16 bits).
  memcpy (ptr, &udphdr.uh_dport, sizeof (udphdr.uh_dport));
  ptr += sizeof (udphdr.uh_dport);
  chksumlen += sizeof (udphdr.uh_dport);

  // Copy UDP length again to buf (16 bits).
  memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
  ptr += sizeof (udphdr.uh_ulen);
  chksumlen += sizeof (udphdr.uh_ulen);

  // Copy UDP checksum to buf (16 bits): zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy UDP data to buf, if any.
  if (udp_datalen > 0) {
    memcpy (ptr, udp_data, udp_datalen);
    ptr += udp_datalen;
    chksumlen += udp_datalen;
  }

  // Pad to the next 16-bit boundary. The padding byte is used only for
  // checksum calculation and is not part of the UDP datagram length.
  if ((udp_datagram_len % 2) != 0) {
    *ptr = 0;
    chksumlen++;
  }

  answer = checksum (buf, chksumlen);
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
