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

// Send an IPv4 ICMP echo request packet via raw socket at the link layer (ethernet frame),
// and receive echo reply packet (i.e., ping). Includes some ICMP data.
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
#include <poll.h>             // poll()
#include <time.h>             // clock_gettime()

#include <errno.h>            // errno, perror()

// Define some constants.
#define ETH_HDRLEN ETH_HLEN  // Ethernet header length
#define IP4_HDRLEN 20        // IPv4 header length
#define ICMP_HDRLEN 8        // ICMP header length for echo request, excludes data
#define TIMEOUT 2            // Time for receive socket to wait for a reply (s)
#define TEXT_STRINGLEN 80    // Maximum number of characters in a string

// Function prototypes
uint16_t checksum (uint8_t *, int);
uint16_t icmp4_checksum (struct icmp, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, datalen, sd, sendsd, recvsd, ip_flags[4] = {0}, frame_length, done;
  int iphlen, timeout_ms, trylim, trycount;
  ssize_t bytes;
  char *interface, *target, *src_ip, *dst_ip, *rec_ip;
  struct ip send_iphdr, *recv_iphdr;
  struct icmp send_icmphdr, *recv_icmphdr;
  uint8_t *data, *src_mac, *send_ether_frame, *recv_ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device, from;
  struct ifreq ifr;
  socklen_t fromlen;
  struct timespec t1, t2;
  struct pollfd pfd;
  double elapsed, remaining;
  void *tmp;

  memset (&send_iphdr, 0, sizeof (send_iphdr));
  memset (&send_icmphdr, 0, sizeof (send_icmphdr));

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  send_ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  recv_ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (TEXT_STRINGLEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  rec_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Random number seed
  srand ((unsigned) time (NULL));

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get socket descriptor for using ioctl() and sending packets.\nError message: %s\n", strerror (status));
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
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

  // Report source MAC address to stdout.
  fprintf (stdout, "MAC address for interface %s is ", interface);
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", src_mac[i], (i < 5) ? ":" : "\n");
  }

  // Set destination MAC address: you need to fill these out
  uint8_t dst_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Destination URL or IPv4 address: you need to fill this out
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

  // ICMP data
  datalen = 4;
  data[0] = 'T';
  data[1] = 'e';
  data[2] = 's';
  data[3] = 't';

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  send_iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  send_iphdr.ip_v = 4;

  // Type of service (8 bits)
  send_iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
  send_iphdr.ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + datalen);

  // IPv4 Identification field (16 bits)
  send_iphdr.ip_id = htons ((uint16_t) (rand () & 0xffff));

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  send_iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  send_iphdr.ip_ttl = 255;

  // Transport layer protocol (8 bits): 1 for ICMP
  send_iphdr.ip_p = IPPROTO_ICMP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(send_iphdr.ip_src))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(send_iphdr.ip_dst))) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for destination address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
  send_iphdr.ip_sum = 0;
  send_iphdr.ip_sum = checksum ((uint8_t *) &send_iphdr, IP4_HDRLEN);

  // ICMP header

  // Message Type (8 bits): echo request
  send_icmphdr.icmp_type = ICMP_ECHO;

  // Message Code (8 bits): 0 for echo request
  send_icmphdr.icmp_code = 0;

  // Identifier (16 bits): usually pid of sending process - pick a number
  send_icmphdr.icmp_id = htons (1000);

  // Sequence Number (16 bits): starts at 0
  send_icmphdr.icmp_seq = htons (0);

  // ICMP header checksum (16 bits): set to 0 when calculating checksum
  send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + ICMP header + ICMP data)
  frame_length = ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN + datalen;

  // Destination and Source MAC addresses
  memcpy (send_ether_frame, dst_mac, 6);
  memcpy (send_ether_frame + 6, src_mac, 6);

  // Next is ethernet type code (ETH_P_IP for IPv4).
  // http://www.iana.org/assignments/ethernet-numbers
  send_ether_frame[12] = ETH_P_IP / 256;
  send_ether_frame[13] = ETH_P_IP % 256;

  // Next is ethernet frame data (IPv4 header + ICMP header + ICMP data).

  // IPv4 header
  memcpy (send_ether_frame + ETH_HDRLEN, &send_iphdr, IP4_HDRLEN);

  // ICMP header
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

  // ICMP data
  memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, datalen);

  // Submit request for a raw socket descriptor to send packets.
  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get send socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Submit request for a raw socket descriptor to receive packets.
  // Use ETH_P_IP in order to only look at IP packets; could use ETH_P_ALL but likely slower on a busy network.
  if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get receive socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Set maximum number of tries to ping remote host before giving up.
  trylim = 3;
  trycount = 0;

  done = 0;
  for (;;) {

    // SEND

    // Set sequence number for this attempt and recompute ICMP checksum.
    // This prevents a delayed reply from an earlier attempt from matching a later attempt.
    send_icmphdr.icmp_seq = htons (trycount);
    send_icmphdr.icmp_cksum = 0;
    send_icmphdr.icmp_cksum = icmp4_checksum (send_icmphdr, data, datalen);

    // Copy updated ICMP header into ethernet frame.
    memcpy (send_ether_frame + ETH_HDRLEN + IP4_HDRLEN, &send_icmphdr, ICMP_HDRLEN);

    // Send ethernet frame to socket.
    bytes = sendto (sendsd, send_ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
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

    // Start timer.
    (void) clock_gettime (CLOCK_MONOTONIC, &t1);

    // Listen for incoming ethernet frame from socket recvsd.
    // We expect an ICMP ethernet frame of the form:
    //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
    //     + ethernet data (IPv4 header + ICMP header)
    // Keep at it for 'timeout' seconds, or until we get an ICMP reply.

    // RECEIVE LOOP
    for (;;) {

      memset (recv_ether_frame, 0, (ETH_HDRLEN + IP_MAXPACKET) * sizeof (uint8_t));
      memset (&from, 0, sizeof (from));
      fromlen = sizeof (from);

      // Set up pollfd structure for poll().
      memset (&pfd, 0, sizeof (pfd));
      pfd.fd = recvsd;
      pfd.events = POLLIN;

      // Calculate elapsed and remaining times.
      clock_gettime (CLOCK_MONOTONIC, &t2);
      elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;
      remaining = TIMEOUT - elapsed;

      if (remaining <= 0.0) {
        fprintf (stdout, "No reply within %d seconds.\n", TIMEOUT);
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
        fprintf (stdout, "No reply within %d seconds.\n", TIMEOUT);
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

        // Read available data from recvsd.
        bytes = recvfrom (recvsd, recv_ether_frame, ETH_HDRLEN + IP_MAXPACKET, 0, (struct sockaddr *) &from, &fromlen);

        // Deal with error conditions first.
        if (bytes < 0) {
          status = errno;
          if ((status == EINTR) || (status == EAGAIN) || (status == EWOULDBLOCK)) {  // EINTR = 4
            continue;  // Something weird happened, but let's keep listening.
          } else {
            fprintf (stderr, "recvfrom() failed.\nError message: %s\n", strerror (status));
            exit (EXIT_FAILURE);
          }
        }

        // Ignore packets received on other interfaces.
        if (from.sll_ifindex != device.sll_ifindex) continue;

        // Check for malformed packet; insufficient bytes to parse ethernet header.
        if ((bytes >= 0) && (bytes < ETH_HDRLEN)) continue;

      // poll() returned, but no readable data was available; keep listening.
      } else {
        continue;
      }

      // Check for sufficient bytes to parse IP header.
      recv_iphdr = (struct ip *) (recv_ether_frame + ETH_HDRLEN);
      if (recv_iphdr->ip_v != 4) continue;
      if (recv_iphdr->ip_hl < 5) continue;
      iphlen = recv_iphdr->ip_hl * 4;  // Convert to bytes; IPv4 header length is expressed in 32-bit words.
      if ((bytes < (ETH_HDRLEN + iphlen)) || (bytes < (ETH_HDRLEN + (int) sizeof (struct ip)))) continue;
      if ((recv_iphdr->ip_p == IPPROTO_ICMP) && (bytes < ETH_HDRLEN + iphlen + ICMP_HDRLEN)) continue;

      // Determine offsets to ICMP header.
      recv_icmphdr = (struct icmp *) (recv_ether_frame + ETH_HDRLEN + iphlen);


      // Check for an IP ethernet frame, carrying ICMP echo reply. If not, ignore and keep listening.
      // Make sure it's an ICMP ECHOREPLY with code 0, and match ID, Sequence #, source and destination addresses.
      if ((((recv_ether_frame[12] << 8) + recv_ether_frame[13]) == ETH_P_IP) &&
            (recv_iphdr->ip_p == IPPROTO_ICMP) &&
            (recv_icmphdr->icmp_type == ICMP_ECHOREPLY) &&
            (recv_icmphdr->icmp_code == 0) &&
            (recv_icmphdr->icmp_id == send_icmphdr.icmp_id) &&
            (recv_icmphdr->icmp_seq == send_icmphdr.icmp_seq) &&
            (recv_iphdr->ip_src.s_addr == send_iphdr.ip_dst.s_addr) &&
            (recv_iphdr->ip_dst.s_addr == send_iphdr.ip_src.s_addr)) {

        // Stop timer and calculate how long it took to get a reply.
        (void) clock_gettime (CLOCK_MONOTONIC, &t2);
        elapsed = (double) (t2.tv_sec - t1.tv_sec) + (double) (t2.tv_nsec - t1.tv_nsec) / 1000000000.0;
        remaining = TIMEOUT - elapsed;
        if (remaining < 0) remaining = 0;

        // Extract source IP address from received ethernet frame.
        if (inet_ntop (AF_INET, &(recv_iphdr->ip_src.s_addr), rec_ip, INET_ADDRSTRLEN) == NULL) {
          status = errno;
          fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
          exit (EXIT_FAILURE);
        }

        // Report source IPv4 address and time for reply.
        fprintf (stdout, "%s  %g ms (%zd bytes received)\n", rec_ip, elapsed * 1000.0, bytes);
        done = 1;
        break;  // Break out of Receive loop.
      }  // End if IP ethernet frame carrying ICMP_ECHOREPLY
    }  // End of Receive loop.

    // The 'done' flag was set because an echo reply was received; break out of send loop.
    if (done == 1) {
      break;  // Break out of Send loop.
    }

    // We ran out of tries, so let's give up.
    if (trycount == trylim) {
      fprintf (stdout, "Recognized no echo replies from remote host after %d tries.\n", trylim);
      break;
    }

  }  // End of Send loop.

  // Close socket descriptors.
  close (sendsd);
  close (recvsd);

  // Free allocated memory.
  free (src_mac);
  free (data);
  free (send_ether_frame);
  free (recv_ether_frame);
  free (interface);
  free (target);
  free (src_ip);
  free (dst_ip);
  free (rec_ip);

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

// Build ICMP message and calculate ICMP checksum.
uint16_t
icmp4_checksum (struct icmp icmphdr, uint8_t *icmpdata, int icmp_datalen) {

  int icmp_segment_len, chksumlen = 0;
  uint8_t *buf, *ptr;
  uint16_t answer = 0;

  if (icmp_datalen < 0) {
    fprintf (stderr, "ERROR: icmp_datalen must not be negative in icmp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  if ((icmp_datalen > 0) && (icmpdata == NULL)) {
    fprintf (stderr, "ERROR: icmpdata is NULL but icmp_datalen > 0 in icmp4_checksum().\n");
    exit (EXIT_FAILURE);
  }

  icmp_segment_len = ICMP_HDRLEN + icmp_datalen;

  // Allocate memory for buffer.
  buf = allocate_ustrmem (icmp_segment_len + 1);  // Add 1 for possible padding.
  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy Message Type to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
  ptr += sizeof (icmphdr.icmp_type);
  chksumlen += sizeof (icmphdr.icmp_type);

  // Copy Message Code to buf (8 bits)
  memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
  ptr += sizeof (icmphdr.icmp_code);
  chksumlen += sizeof (icmphdr.icmp_code);

  // Copy ICMP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy Identifier to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
  ptr += sizeof (icmphdr.icmp_id);
  chksumlen += sizeof (icmphdr.icmp_id);

  // Copy Sequence Number to buf (16 bits)
  memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
  ptr += sizeof (icmphdr.icmp_seq);
  chksumlen += sizeof (icmphdr.icmp_seq);

  // Copy ICMP data to buf, if any.
  if (icmp_datalen > 0) {
    memcpy (ptr, icmpdata, icmp_datalen);
    ptr += icmp_datalen;
    chksumlen += icmp_datalen;
  }

  // Pad to the next 16-bit boundary
  if (icmp_datalen % 2) {
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
