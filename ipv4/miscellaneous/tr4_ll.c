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

// Perform a traceroute by sending IPv4 TCP, UDP, or ICMP packets via
// raw socket at the link layer (ethernet frame).
// Need to have destination MAC address.
// TCP set for SYN, UDP for port unreachable, ICMP for echo request (ping).

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#define __FAVOR_BSD           // Use BSD-style networking structures. e.g., struct tcphdr
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_TCP, IPPROTO_ICMP, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>  // struct icmp and ICMP_TIME_EXCEEDED
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>      // struct udphdr
#include <fcntl.h>            // fcntl()
#include <poll.h>             // poll()
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_IP, ETH_P_ALL
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <limits.h>           // HOST_NAME_MAX
#include <time.h>             // time(), clock_gettime(), CLOCK_MONOTONIC

#include <errno.h>            // errno, perror()

// Define some constants.
#define ETH_HDRLEN ETH_HLEN   // Ethernet header length
#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define UDP_HDRLEN 8          // UDP header length, excludes data
#define ICMP_HDRLEN 8         // ICMP header length for echo request, excludes data
#define TIMEOUT 2             // Time for receive socket to wait for a reply (s)
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int, uint8_t *, int);
uint16_t udp4_checksum (struct ip, struct udphdr, uint8_t *, int);
int create_tcp_frame (uint8_t *, char *, char *, uint8_t *, uint8_t *, uint16_t, int, uint8_t *, int);
int create_icmp_frame (uint8_t *, char *, char *, uint8_t *, uint8_t *, uint16_t, uint16_t, int, uint8_t *, int);
int create_udp_frame (uint8_t *, char *, char *, uint8_t *, uint8_t *, uint16_t, uint16_t, int, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, frame_length, sd, sendsd, recsd, flags, node, trylim, trycount, timeout_ms;
  int packet_type, iphlen, inner_iphlen, done, datalen, resolve, maxhops, probes, num_probes, probe_index;
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip, *rec_ip, *tcp_dat, *icmp_dat, *udp_dat;
  char hostname[HOST_NAME_MAX];
  struct ip *iphdr;
  struct tcphdr *tcphdr;
  struct icmp *icmphdr;
  uint8_t *src_mac;
  uint8_t *snd_ether_frame, *rec_ether_frame;
  uint8_t *data;
  uint16_t tcp_sport, icmpid, icmpseq, udp_sport, udp_dport;
  struct addrinfo hints, *res;
  struct sockaddr_in *dst, sa;
  struct sockaddr_ll device, from;
  struct ifreq ifr;
  struct ip *inner_ip;
  struct tcphdr *inner_tcp;
  struct icmp *inner_icmp;
  struct udphdr *inner_udp;
  socklen_t fromlen;
  struct timespec t1, t2;
  struct pollfd pfd;
  double elapsed, remaining;
  void *tmp;

  // Choose whether to resolve IPs to hostnames: 0 = do not resolve, 1 = resolve
  resolve = 0;

  // Number of probes per node.
  num_probes = 3;

  // Choose type of packet to send: 1 = TCP, 2 = ICMP, 3 = UDP
  packet_type = 1;

  // Maximum number of hops allowed.
  maxhops = 30;

  // Random number seed
  srand ((unsigned) time (NULL));

  // ICMP Identifier (16 bits): Usually pid of sending process; you can choose.
  icmpid = htons (1000);

  // UDP source port (16 bits each); you can choose.
  udp_sport = htons (4950);

  // Allocate memory for various arrays.
  tcp_dat = allocate_strmem (IP_MAXPACKET);
  icmp_dat = allocate_strmem (IP_MAXPACKET);
  udp_dat = allocate_strmem (IP_MAXPACKET);
  data = allocate_ustrmem (IP_MAXPACKET);
  rec_ip = allocate_strmem (INET_ADDRSTRLEN);
  src_mac = allocate_ustrmem (6);
  snd_ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  rec_ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Payloads for TCP, UDP, and ICMP packets.
  memset (tcp_dat, 0, IP_MAXPACKET);  // No TCP data
  snprintf (icmp_dat, IP_MAXPACKET, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");  // Seems to be commonly used, but unnecessary I think
  snprintf (udp_dat, IP_MAXPACKET, "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_");  // Seems to be commonly used, but unnecessary I think

  // Check for acceptable payload lengths.
  if (strlen (tcp_dat) > (IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN)) {
    fprintf (stderr, "Maximum TCP data length exceeded. Maximum length is %d\n", IP_MAXPACKET - IP4_HDRLEN - TCP_HDRLEN);
    exit (EXIT_FAILURE);
  }
  if (strlen (icmp_dat) > (IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN)) {
    fprintf (stderr, "Maximum ICMP data length exceeded. Maximum length is %d\n", IP_MAXPACKET - IP4_HDRLEN - ICMP_HDRLEN);
    exit (EXIT_FAILURE);
  }
  if (strlen (udp_dat) > (IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN)) {
    fprintf (stderr, "Maximum UDP data length exceeded. Maximum length is %d\n", IP_MAXPACKET - IP4_HDRLEN - UDP_HDRLEN);
    exit (EXIT_FAILURE);
  }

  // Interface to send packet through.
  // You need to put your network interface name here.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Submit request for a socket descriptor to lookup interface.
  if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor for using ioctl().\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to lookup interface and get MAC address.
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
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

  // Report source MAC address to stdout.
  fprintf (stdout, "MAC address for interface %s is ", interface);
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", src_mac[i], (i < 5) ? ":" : "\n");
  }

  // Destination Ethernet MAC address: You need to fill these out.
  // For off-link destinations, this is normally the next-hop router's MAC address.
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Destination hostname or IPv4 address: you need to fill this out
  snprintf (target, HOSTNAME_LEN, "%s", "www.google.com");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  dst = (struct sockaddr_in *) res->ai_addr;
  tmp = &(dst->sin_addr);
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

  // Show target of traceroute.
  switch (packet_type) {

    case 1:  // TCP
      fprintf (stdout, "\nTCP traceroute to %s (%s)\n", target, dst_ip);
      fprintf (stdout, "Using TCP source ports in the high ephemeral range.\n");
      break;

    case 2:  // ICMP
      fprintf (stdout, "\nICMP traceroute to %s (%s)\n", target, dst_ip);
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
  // Use ETH_P_IP in order to only look at IP packets; could use ETH_P_ALL but likely slower on a busy network.
  if ((recsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP))) < 0) {
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
    fprintf (stderr, "fcntl() failed to set non-blcoking flag on receive socket.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set maximum number of tries for a host before incrementing TTL and moving on.
  trylim = 3;

  // Start at Time-to-Live (TTL) = 1. i.e., one hop
  node = 1;

  // LOOP: incrementing TTL each cycle, exiting when we get our target IP address.
  done = 0;
  trycount = 0;
  probes = 0;

  for (;;) {

  // Create probe packet.
  probe_index = ((node - 1) * num_probes) + probes;
  tcp_sport = htons (49152 + probe_index % 16384);  // Some random, high ephemeral port number; Some firewalls dislike packets claiming to originate from Port 80.
  icmpseq = htons (probe_index);  // ICMP sequence number (16 bits)
  udp_dport = htons (33434 + probe_index);  // UDP destination port (16 bits)
  memset (snd_ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);
  switch (packet_type) {

    case 1:  // TCP
      datalen = strlen (tcp_dat);
      memcpy (data, tcp_dat, datalen);
      create_tcp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, tcp_sport, node, data, datalen);
      frame_length = ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN + datalen;
      break;

    case 2:  // ICMP
      datalen = strlen (icmp_dat);
      memcpy (data, icmp_dat, datalen);
      create_icmp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, icmpid, icmpseq, node, data, datalen);
      frame_length = ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;
      break;

    case 3:  // UDP
      datalen = strlen (udp_dat);
      memcpy (data, udp_dat, datalen);
      create_udp_frame (snd_ether_frame, src_ip, dst_ip, src_mac, dst_mac, udp_sport, udp_dport, node, data, datalen);
      frame_length = ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN + datalen;
      break;

    default:
      fprintf (stderr, "Unknown packet type: %d\n", packet_type);
      exit (EXIT_FAILURE);

  }  // End swtich

  // SEND

    // Send ethernet frame to socket.
    bytes = sendto (sendsd, snd_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
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

    // Increment probe count.
    probes++;

    // Start timer.
    if (clock_gettime (CLOCK_MONOTONIC, &t1) < 0) {
      status = errno;
      fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
      exit (EXIT_FAILURE);
    }

    // Listen for incoming ethernet frame from socket recsd.
    // 
    // If we haven't reached the destination (because TTL reached 0), we expect an ICMP ethernet frame of the form:
    //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes) +
    //     Outer IP header + ICMP header + inner IP header + TCP*/ICMP/UDP header
    //     *Note: Many routers only provide the first 8 bytes of TCP header in reply. Payload almost certainly won't be included.
    // If we have reached our destination (i.e., we did not receive an ICMP_TIME_EXCEEDED (reached destination before TTL reached 0)), we expect:
    //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes) + one of:
    //     IP header + TCP (SYN-ACK or RST)
    //     IP header + ICMP (echo reply) + payload
    //     Outer IP header + Inner IP header + ICMP (port unreachable) + payload

    // RECEIVE LOOP
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

      timeout_ms = (int) (remaining * 1000.0);  // milliseconds
      if (timeout_ms < 1) timeout_ms = 1;

      // Wait for data to be available on our receive socket, or until we time-out.
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

      // Receive socket timed-out.
      if (status == 0) {
        fprintf (stdout, "%2d  No reply within %d seconds.\n", node, TIMEOUT);
        trycount++;
        break;  // Break out of Receive loop.
      }

      // Check for socket error conditions reported by poll().
      if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        fprintf (stderr, "poll() reported socket error: revents = 0x%x.\n", pfd.revents);
        exit (EXIT_FAILURE);
      }

      // If pfd has POLLIN set in revents, then recvsd (i.e., pfd.fd) is ready for reading.
      if (pfd.revents & POLLIN) {

        // Read available data from recsd.
        bytes = recvfrom (recsd, rec_ether_frame, ETH_HDRLEN + IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen);

        // Deal with error conditions first.
        if (bytes < 0) {
          status = errno;
          if ((status == EINTR) || (status == EAGAIN) || (status == EWOULDBLOCK)) {  // EINTR = 4
            continue;  // System call interrupted by a signal before completion. Retry.
          } else {
            fprintf (stderr, "recvfrom() failed. Error message: %s\n", strerror (status));
            exit (EXIT_FAILURE);
          }
        }

        // Check for sufficient bytes to parse ethernet header.
        if ((bytes >= 0) && (bytes < ETH_HDRLEN)) continue;

      // poll() returned, but no readable data was available; keep listening.
      } else {
        continue;
      }

      // Check for an IP ethernet frame. If not, ignore and keep listening.
      if (((rec_ether_frame[12] << 8) + rec_ether_frame[13]) == ETH_P_IP) {

        // Check for sufficient bytes to parse IP header.
        iphdr = (struct ip *) (rec_ether_frame + ETH_HDRLEN);
        if (iphdr->ip_v != 4) continue;
        if (iphdr->ip_hl < 5) continue;
        iphlen = iphdr->ip_hl * 4;  // Convert to bytes; IPv4 header length is expressed in 32-bit words.
        if ((bytes < (ETH_HDRLEN + iphlen)) || (bytes < (ETH_HDRLEN + (int) sizeof (struct ip)))) continue;
        if ((iphdr->ip_p == IPPROTO_ICMP) && (bytes < ETH_HDRLEN + iphlen + ICMP_HDRLEN)) continue;
        if ((iphdr->ip_p == IPPROTO_TCP) && (bytes < ETH_HDRLEN + iphlen + TCP_HDRLEN)) continue;

        // Determine offsets to headers.
        iphdr = (struct ip *) (rec_ether_frame + ETH_HDRLEN);
        icmphdr = (struct icmp *) (rec_ether_frame + ETH_HDRLEN + iphlen);
        tcphdr = (struct tcphdr *) (rec_ether_frame + ETH_HDRLEN + iphlen);

        // Did we get an ICMP_TIME_EXCEEDED?
        // i.e., TTL reached 0 before packet reached destination.
        if ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == ICMP_TIME_EXCEEDED)) {

          // Check for malformed packet.
          inner_ip = (struct ip *) (rec_ether_frame + ETH_HDRLEN + iphlen + ICMP_HDRLEN);
          if (((uint8_t *) inner_ip + sizeof (struct ip)) > rec_ether_frame + bytes) continue;
          if (inner_ip->ip_hl < 5) continue;
          inner_iphlen = inner_ip->ip_hl * 4;  // Convert to bytes; IPv4 header length is expressed in 32-bit words.
          if (((uint8_t *) inner_ip + inner_iphlen) > rec_ether_frame + bytes) continue;

          // Ensure embedded packet belongs to our probe.
          switch (packet_type) {

            case 1:  // TCP; Note: Many routers only provide first 8 bytes of TCP header in this reply.
              if (((uint8_t *) inner_ip + inner_iphlen + 8) > rec_ether_frame + bytes) continue;
              inner_tcp = (struct tcphdr *) ((uint8_t *) inner_ip + inner_iphlen);
              if (inner_ip->ip_p != IPPROTO_TCP) continue;
              if (inner_tcp->th_sport != tcp_sport) continue;
              if (inner_tcp->th_dport != htons (80)) continue;
              break;

            case 2:  // ICMP
              if (((uint8_t *) inner_ip + inner_iphlen + ICMP_HDRLEN) > rec_ether_frame + bytes) continue;
              inner_icmp = (struct icmp *) ((uint8_t *) inner_ip + inner_iphlen);
              if (inner_ip->ip_p != IPPROTO_ICMP) continue;
              if (inner_icmp->icmp_id != icmpid) continue;
              if (inner_icmp->icmp_seq != icmpseq) continue;
              break;

            case 3:  // UDP
              if (((uint8_t *) inner_ip + inner_iphlen + UDP_HDRLEN) > rec_ether_frame + bytes) continue;
              inner_udp = (struct udphdr *) ((uint8_t *) inner_ip + inner_iphlen);
              if (inner_ip->ip_p != IPPROTO_UDP) continue;
              if (inner_udp->uh_sport != udp_sport) continue;
              if (inner_udp->uh_dport != udp_dport) continue;
              break;

          } // End switch

          // Initialize count of tries.
          trycount = 0;

          // Stop timer and calculate how long it took to get a reply.
          if (clock_gettime (CLOCK_MONOTONIC, &t2) < 0) {
            status = errno;
            fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
            exit (EXIT_FAILURE);
          }
          elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;
          remaining = TIMEOUT - elapsed;
          if (remaining < 0) remaining = 0;

          // Extract source IP address from received ethernet frame.
          if (inet_ntop (AF_INET, &(iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
            fprintf (stderr, "inet_ntop() failed for received source address.\nError message: %s", strerror (errno));
            exit (EXIT_FAILURE);
          }

          // Report source IP address and time for reply.
          if (resolve == 0) {
            fprintf (stdout, "%2d  %s  %g ms (%zd bytes received)", node, rec_ip, elapsed * 1000.0, bytes);
          } else {
            memset (&sa, 0, sizeof (sa));
            sa.sin_family = AF_INET;
            if ((status = inet_pton (AF_INET, rec_ip, &sa.sin_addr)) != 1) {
              if (status == 0) {
                fprintf (stderr, "inet_pton() failed for received source address.\nError message: Invalid address");
              } else if (status < 0) {
                fprintf (stderr, "inet_pton() failed for received source address.\nError message: %s", strerror (errno));
              }
              exit (EXIT_FAILURE);
            }
            if ((status = getnameinfo ((struct sockaddr*)&sa, sizeof (sa), hostname, sizeof (hostname), NULL, 0, 0)) != 0) {
              fprintf (stderr, "getnameinfo() failed for received source address.\nError message: %s", gai_strerror (status));
              exit (EXIT_FAILURE);
            }
            fprintf (stdout, "%2d  %s (%s)  %g ms (%zd bytes received)", node, rec_ip, hostname, elapsed * 1000.0, bytes);
          }
          if (probes < num_probes) {
            fprintf (stdout, " : ");
            break;  // Break out of Receive loop and probe next node in route.
          } else {
            fprintf (stdout, "\n");
            node++;  // Increment TTL.
            probes = 0;
            break;  // Break out of Receive loop and probe next node in route.
          }
        }  // End of ICMP_TIME_EXCEEDED conditional.

        // Did we reach our destination? i.e., we did not receive an ICMP_TIME_EXCEEDED (reached destination before TTL reached 0).
        // TCP SYN-ACK or RST means TCP SYN packet reached destination node.
        // ICMP echo reply means ICMP echo request packet reached destination node.
        // ICMP port unreachable means UDP packet reached destination node.
        if (((iphdr->ip_p == IPPROTO_TCP) && (((tcphdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) || (tcphdr->th_flags & TH_RST))) ||
            ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == 0) && (icmphdr->icmp_code == 0)) ||  // ECHO REPLY
            ((iphdr->ip_p == IPPROTO_ICMP) && (icmphdr->icmp_type == 3) && (icmphdr->icmp_code == 3))) {  // PORT UNREACHABLE

          // Stop timer and calculate how long in ms it took to get a reply.
          if (clock_gettime (CLOCK_MONOTONIC, &t2) < 0) {
            status = errno;
            fprintf (stderr, "clock_gettime() failed. Error message: %s\n", strerror (status));
            exit (EXIT_FAILURE);
          }
          elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;
          remaining = TIMEOUT - elapsed;
          if (remaining < 0) remaining = 0;

          // Ensure received packet is not malformed and a reply to our probe and not other network traffic.
          switch (packet_type) {

            case 1:  // TCP
              if (iphdr->ip_p != IPPROTO_TCP) continue;
              if (bytes < (ETH_HDRLEN + iphlen + TCP_HDRLEN)) continue;
              if (tcphdr->th_sport != htons (80)) continue;
              if (tcphdr->th_dport != tcp_sport) continue;
              break;

            case 2:  // ICMP
              if (iphdr->ip_p != IPPROTO_ICMP) continue;
              if (icmphdr->icmp_type != 0) continue;
              if (icmphdr->icmp_code != 0) continue;
              if (bytes < (ETH_HDRLEN + iphlen + ICMP_HDRLEN)) continue;
              if (icmphdr->icmp_id != icmpid) continue;
              if (icmphdr->icmp_seq != icmpseq) continue;
              break;

            case 3:  // UDP
              if (iphdr->ip_p != IPPROTO_ICMP) continue;
              if (icmphdr->icmp_type != 3) continue;
              if (icmphdr->icmp_code != 3) continue;
              inner_ip = (struct ip *) (rec_ether_frame + ETH_HDRLEN + iphlen + ICMP_HDRLEN);
              if (((uint8_t *) inner_ip + sizeof (struct ip)) > rec_ether_frame + bytes) continue;
              if (inner_ip->ip_hl < 5) continue;
              inner_iphlen = inner_ip->ip_hl * 4;  // Convert to bytes; IPv4 header length is expressed in 32-bit words.
              if (((uint8_t *) inner_ip + inner_iphlen + UDP_HDRLEN) > rec_ether_frame + bytes) continue;
              inner_udp = (struct udphdr *) ((uint8_t *) inner_ip + inner_iphlen);
              if (inner_ip->ip_p != IPPROTO_UDP) continue;
              if (inner_udp->uh_sport != udp_sport) continue;
              if (inner_udp->uh_dport != udp_dport) continue;

          }  // End switch

          // Extract source IP address from received ethernet frame.
          if (inet_ntop (AF_INET, &(iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
            status = errno;
            fprintf (stderr, "inet_ntop() failed for received source address.\nError message: %s", strerror (status));
            exit (EXIT_FAILURE);
          }

          // Report source IP address and time for reply.
          fprintf (stdout, "%2d  %s  %g ms", node, rec_ip, elapsed * 1000.0);
          if (probes < num_probes) {
            fprintf (stdout, " : ");
            break;  // Break out of Receive loop and probe this node again.
          } else {
            fprintf (stdout, "\n");
            done = 1;
            break;  // Break out of Receive loop and finish.
          }
        }  // End of Reached Destination conditional.
      }  // End of Was IP Frame conditional.
    }  // End of Receive loop.

    // Reached destination node.
    if (done == 1) {
      fprintf (stdout, "Traceroute complete.\n\n");
      break;  // Break out of Send loop.

    // Reached maxhops.
    } else if (node > maxhops) {
      fprintf (stdout, "Reached maximum number of hops. Maximum is set to %d hops.", maxhops);
      break;  // Break out of Send loop.
    }

    // We ran out of tries, let's move on to next node unless we reached maxhops limit.
    if (trycount == trylim) {
      fprintf (stdout, "%2d  Node won't respond after %d probes.\n", node, trylim);
      node++;  // Increment TTL.
      probes = 0;
      trycount = 0;
      continue;
    }

  }  // End of Send loop.

  // Close socket descriptors.
  close (sendsd);
  close (recsd);

  // Free allocated memory.
  free (tcp_dat);
  free (icmp_dat);
  free (udp_dat);
  free (data);
  free (src_mac);
  free (snd_ether_frame);
  free (rec_ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (rec_ip);

  return (EXIT_SUCCESS);
}

// Create a TCP ethernet frame.
int
create_tcp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                  uint16_t tcp_sport, int ttl, uint8_t *data, int datalen) {

  int status;
  uint32_t seq;
  struct ip iphdr = {0};
  struct tcphdr tcphdr = {0};

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + TCP header + data
  iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + datalen);

  // IPv4 Identification field (16 bits)
  iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
  iphdr.ip_off = htons (0);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = ttl;

  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

  // TCP header

  // Source port number (16 bits)
  tcphdr.th_sport = tcp_sport;

  // Destination port number (16 bits)
  tcphdr.th_dport = htons (80);

  // Sequence number (32 bits): random initial sequence number (ISN)
  seq = ((uint32_t) rand () << 16) | ((uint32_t) rand () & 0xffff);
  tcphdr.th_seq = htonl (seq);

  // Acknowledgement number (32 bits): not used in initial SYN packet.
  tcphdr.th_ack = htonl (0);

  // Reserved (4 bits): should be 0
  tcphdr.th_x2 = 0;

  // Data offset (4 bits): size of TCP header in 32-bit words
  tcphdr.th_off = TCP_HDRLEN / 4;

  // Flags (8 bits)

  // SYN flag (1 bit): set to 1
  tcphdr.th_flags = TH_SYN;

  // Window size (16 bits)
  tcphdr.th_win = htons (65535);

  // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
  tcphdr.th_urp = htons (0);

  // TCP checksum (16 bits)
  tcphdr.th_sum = 0;
  tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, NULL, 0, data, datalen);

  // Fill out ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, 6);
  memcpy (snd_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IP / 256;
  snd_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + TCP header).

  // IPv4 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN);

  // TCP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);

  // TCP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + TCP_HDRLEN, data, datalen);

  return (EXIT_SUCCESS);
}

// Create a ICMP ethernet frame.
int
create_icmp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                   uint16_t icmpid, uint16_t icmpseq, int ttl, uint8_t *data, int datalen) {

  int status;
  struct ip iphdr = {0};
  struct icmp icmphdr = {0};

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // IPv4 Identification field (16 bits)
  iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
  iphdr.ip_off = htons (0);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = ttl;

  // Transport layer protocol (8 bits): 1 for ICMP
  iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): echo request
  icmphdr.icmp_code = 0;

  // Identifier (16 bits)
  icmphdr.icmp_id = icmpid;

  // Sequence Number (16 bits): starts at 0
  icmphdr.icmp_seq = icmpseq;

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  icmphdr.icmp_cksum = 0;

  // Fill out ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, 6);
  memcpy (snd_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IP / 256;
  snd_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

  // IPv4 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  // Already set to 0 above.
  icmphdr.icmp_cksum = checksum ((uint8_t *) (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN), ICMP_HDRLEN + datalen);
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);

  return (EXIT_SUCCESS);
}

// Create a UDP ethernet frame.
int
create_udp_frame (uint8_t *snd_ether_frame, char *src_ip, char *dst_ip, uint8_t *src_mac, uint8_t *dst_mac,
                  uint16_t udp_sport, uint16_t udp_dport, int ttl, uint8_t *data, int datalen) {

  int status;
  struct ip iphdr = {0};
  struct udphdr udphdr = {0};

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + UDP header + datalen
  iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

  // IPv4 Identification field (16 bits)
  iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
  iphdr.ip_off = htons (0);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = ttl;

  // Transport layer protocol (8 bits): 17 for UDP
  iphdr.ip_p = IPPROTO_UDP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  iphdr.ip_sum = 0;
  iphdr.ip_sum = checksum ((uint8_t *) &iphdr, IP4_HDRLEN);

  // UDP header

  // Source port number (16 bits)
  udphdr.uh_sport = udp_sport;

  // Destination port number (16 bits)
  udphdr.uh_dport = udp_dport;

  // Length of UDP datagram (16 bits): UDP header + UDP data
  udphdr.uh_ulen = htons (UDP_HDRLEN + datalen);

  // UDP checksum (16 bits)
  udphdr.uh_sum = 0;
  udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);

  // Fill out ethernet frame header.

  // Destination and Source MAC addresses
  memcpy (snd_ether_frame, dst_mac, 6);
  memcpy (snd_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  snd_ether_frame[12] = ETH_P_IP / 256;
  snd_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + UDP header + UDP data).
  // IPv4 header
  memcpy (snd_ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN);

  // UDP header
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &udphdr, UDP_HDRLEN);

  // UDP data
  memcpy (snd_ether_frame + ETH_HDRLEN + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

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

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t
udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *udp_data, int udp_datalen) {

  int udp_segment_len, chksumlen = 0;
  uint8_t *buf, *ptr;
  uint16_t answer = 0;

  if (udp_datalen < 0) {
    fprintf (stderr, "ERROR: udp_datalen must not be negative in udp4_checksum().\n");
    exit (EXIT_FAILURE);
  }
  if ((udp_datalen > 0) && (udp_data == NULL)) {
    fprintf (stderr, "ERROR: udp_data is NULL but udp_datalen > 0 in udp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  udp_segment_len = UDP_HDRLEN + udp_datalen;

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

  // Copy UDP data to buf, if any.
  if (udp_datalen > 0) {
    memcpy (ptr, udp_data, udp_datalen);
    ptr += udp_datalen;
    chksumlen += udp_datalen;
  }

  // Pad to the next 16-bit boundary
  if (udp_datalen % 2) {
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
