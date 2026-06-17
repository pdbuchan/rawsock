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

// Send an IPv4 ARP packet via raw socket at the link layer (ethernet frame) and
// receive ARP reply.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), and memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // needed for socket()
#include <poll.h>             // poll()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_ARP
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)

#include <errno.h>            // errno, perror()

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

// Define some constants.
#define ETH_HDRLEN ETH_HLEN  // Ethernet header length
#define IP4_HDRLEN 20        // IPv4 header length
#define ARP_ETH_IPV4_LEN 28  // Complete Ethernet/IPv4 ARP packet
#define ARPOP_REQUEST 1      // Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2        // Taken from <linux/if_arp.h>
#define TEXT_STRINGLEN 80    // Maximum number of characters in a string

// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, frame_length, sd, sendsd, recvsd, timeout;
  ssize_t bytes;
  char *interface, *target, *src_ip;
  arp_hdr send_arphdr, *recv_arphdr;
  uint8_t *src_mac, *dst_mac, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device, recv_device;
  struct ifreq ifr;
  struct pollfd pfd;

  memset (&send_arphdr, 0, sizeof (send_arphdr));

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (TEXT_STRINGLEN);
  target = allocate_strmem (TEXT_STRINGLEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "%s", "enp7s0");

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
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
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

  // Set destination MAC address: broadcast address
  memset (dst_mac, 0xff, 6 * sizeof (uint8_t));

  // Source IPv4 address: you need to fill this out
  snprintf (src_ip, INET_ADDRSTRLEN, "%s", "192.168.0.9");

  // Destination hostname or IPv4 address (must be a link-local node): you need to fill this out
  strncpy (target, "192.168.0.63", TEXT_STRINGLEN);

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Source IP address
  if ((status = inet_pton (AF_INET, src_ip, &send_arphdr.sender_ip)) != 1) {
    if (status == 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: Invalid address\n");
    } else if (status < 0) {
      fprintf (stderr, "inet_pton() failed for source address.\nError message: %s\n", strerror (errno));
    }
    exit (EXIT_FAILURE);
  }

  // Resolve target using getaddrinfo().
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed for target.\nError message: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }
  ipv4 = (struct sockaddr_in *) res->ai_addr;
  memcpy (&send_arphdr.target_ip, &ipv4->sin_addr, 4 * sizeof (uint8_t));
  freeaddrinfo (res);

  // Fill out device's sockaddr_ll struct.
  memset (&device, 0, sizeof (device));
  device.sll_family = AF_PACKET;
  device.sll_protocol = htons (ETH_P_ARP);
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    status = errno;
    fprintf (stderr, "if_nametoindex(\"%s\") failed to obtain interface index.\nError message: %s\n", interface, strerror (status));
    exit (EXIT_FAILURE);
  }
  fprintf (stdout, "Index for interface %s is %d\n", interface, device.sll_ifindex);
  memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
  device.sll_halen = 6;

  // ARP header

  // Hardware type (16 bits): 1 for ethernet
  send_arphdr.htype = htons (1);

  // Protocol type (16 bits): 2048 for IP
  send_arphdr.ptype = htons (ETH_P_IP);

  // Hardware address length (8 bits): 6 bytes for MAC address
  send_arphdr.hlen = 6;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  send_arphdr.plen = 4;

  // OpCode: 1 for ARP request
  send_arphdr.opcode = htons (ARPOP_REQUEST);

  // Sender hardware address (48 bits): MAC address
  memcpy (&send_arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

  // Sender protocol address (32 bits)
  // See getaddrinfo() resolution of src_ip.

  // Target hardware address (48 bits): zero, since we don't know it yet.
  memset (&send_arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  // Target protocol address (32 bits)
  // See getaddrinfo() resolution of target.

  // Fill out ethernet frame header.

  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
  frame_length = ETH_HDRLEN + ARP_ETH_IPV4_LEN;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;

  // Next is ethernet frame data (ARP header).

  // ARP header
  memcpy (ether_frame + ETH_HDRLEN, &send_arphdr, ARP_ETH_IPV4_LEN * sizeof (uint8_t));

  // Submit request for a raw socket descriptor.
  if ((recvsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ARP))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get receive socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Bind receive socket to interface.
  memset (&recv_device, 0, sizeof (recv_device));
  recv_device.sll_family = AF_PACKET;
  recv_device.sll_protocol = htons (ETH_P_ARP);
  recv_device.sll_ifindex = device.sll_ifindex;
  if (bind (recvsd, (struct sockaddr *) &recv_device, sizeof (recv_device)) < 0) {
    status = errno;
    fprintf (stderr, "bind() failed.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Submit request for a raw socket descriptor.
  if ((sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ARP))) < 0) {
    status = errno;
    fprintf (stderr, "socket() failed to get send socket descriptor.\nError message: %s\n", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Send ethernet frame to socket.
  bytes = sendto (sendsd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
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

  // Print out contents of send ethernet frame.
  fprintf (stdout, "\nSENT ETHERNET FRAME\n");
  fprintf (stdout, "  Ethernet header:\n");
  fprintf (stdout, "    Destination MAC (broadcast) address: ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", dst_mac[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Source MAC address (this node): ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", src_mac[i], (i < 5) ? ":" : "\n");
  }
  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  fprintf (stdout, "    Ethernet type code (2054 = ARP): %u\n\n", ((ether_frame[12]) << 8) + ether_frame[13]);

  fprintf (stdout, "  ARP header:\n");
  fprintf (stdout, "    Hardware type (1 = ethernet (10 Mb)): %u\n", ntohs (send_arphdr.htype));
  fprintf (stdout, "    Protocol type (2048 for IPv4 addresses): %u\n", ntohs (send_arphdr.ptype));
  fprintf (stdout, "    Hardware (MAC) address length (bytes): %u\n", send_arphdr.hlen);
  fprintf (stdout, "    Protocol (IPv4) address length (bytes): %u\n", send_arphdr.plen);
  fprintf (stdout, "    Opcode (1 = ARP request): %u\n", ntohs (send_arphdr.opcode));
  fprintf (stdout, "    Sender MAC address (this node): ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", send_arphdr.sender_mac[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Sender IPv4 address: %u.%u.%u.%u\n",
    send_arphdr.sender_ip[0], send_arphdr.sender_ip[1], send_arphdr.sender_ip[2], send_arphdr.sender_ip[3]);
  fprintf (stdout, "    Target MAC address: ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", send_arphdr.target_mac[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Target IPv4 address: %u.%u.%u.%u\n",
    send_arphdr.target_ip[0], send_arphdr.target_ip[1], send_arphdr.target_ip[2], send_arphdr.target_ip[3]);

  // Listen for incoming ethernet frame from socket recvsd.
  // We expect an ARP ethernet frame of the form:
  //     MAC (6 bytes) + MAC (6 bytes) + ethernet type (2 bytes)
  //     + ethernet data (ARP header) (28 bytes)
  // Keep at it until we get an ARP reply.
  timeout = 2000;  // Milliseconds
  pfd.fd = recvsd;
  pfd.events = POLLIN;
  memset (ether_frame, 0, (ETH_HDRLEN + IP_MAXPACKET) * sizeof (uint8_t));
  recv_arphdr = (arp_hdr *) (ether_frame + ETH_HDRLEN);
  for (;;) {
    status = poll (&pfd, 1, timeout);
    if (status < 0) {
      if (errno == EINTR) {
        continue;  // Something weird happened, but let's try again.
      } else {
        fprintf (stderr, "poll() failed.\nError message: %s\n", strerror (errno));
        exit (EXIT_FAILURE);
      }
    } else if (status == 0) {
      fprintf (stderr, "No ARP reply within %d milliseconds.\n", timeout);
      exit (EXIT_FAILURE);
    }

    // If pfd has POLLIN set in revents, then recvsd (i.e., pfd.fd) is ready for reading.
    if (pfd.revents & POLLIN) {
      memset (ether_frame, 0, (ETH_HDRLEN + IP_MAXPACKET) * sizeof (uint8_t));
      if ((bytes = recv (recvsd, ether_frame, ETH_HDRLEN + ARP_ETH_IPV4_LEN, 0)) < 0) {
        if (errno == EINTR) {
          continue;  // Something weird happened, but let's try again.
        } else {
          fprintf (stderr, "recv() failed.\nError message: %s\n", strerror (errno));
          exit (EXIT_FAILURE);
        }
      }

      // Check for sufficient bytes to parse ethernet and ARP headers.
      if (bytes < (ETH_HDRLEN + ARP_ETH_IPV4_LEN)) {
        continue;
      }

      // Ensure we have an ARP reply with correct source and destination IP addresses, and 
      // this node's MAC address.
      recv_arphdr = (arp_hdr *) (ether_frame + ETH_HDRLEN);
      if (((((ether_frame[12]) << 8) + ether_frame[13]) == ETH_P_ARP) &&
        (ntohs (recv_arphdr->htype) == 1) &&
        (ntohs (recv_arphdr->ptype) == ETH_P_IP) &&
        (recv_arphdr->hlen == 6) &&
        (recv_arphdr->plen == 4) &&
        (ntohs (recv_arphdr->opcode) == ARPOP_REPLY) &&
        (memcmp (recv_arphdr->sender_ip, send_arphdr.target_ip, 4 * sizeof (uint8_t)) == 0) &&
        (memcmp (recv_arphdr->target_ip, send_arphdr.sender_ip, 4 * sizeof (uint8_t)) == 0) &&
        (memcmp (recv_arphdr->target_mac, src_mac, 6 * sizeof (uint8_t)) == 0)) {
        break;
      }
    }
  }

  // Print out contents of received ethernet frame.
  fprintf (stdout, "\nRECEIVED ETHERNET FRAME\n");
  fprintf (stdout, "  Ethernet header:\n");
  fprintf (stdout, "    Destination MAC address (this node): ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", ether_frame[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Source MAC address: ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", ether_frame[i + 6], (i < 5) ? ":" : "\n");
  }
  // Next is ethernet type code (ETH_P_ARP for ARP).
  // http://www.iana.org/assignments/ethernet-numbers
  fprintf (stdout, "    Ethernet type code (2054 = ARP): %u\n\n", ((ether_frame[12]) << 8) + ether_frame[13]);

  fprintf (stdout, "  ARP header:\n");
  fprintf (stdout, "    Hardware type (1 = ethernet (10 Mb)): %u\n", ntohs (recv_arphdr->htype));
  fprintf (stdout, "    Protocol type (2048 for IPv4 addresses): %u\n", ntohs (recv_arphdr->ptype));
  fprintf (stdout, "    Hardware (MAC) address length (bytes): %u\n", recv_arphdr->hlen);
  fprintf (stdout, "    Protocol (IPv4) address length (bytes): %u\n", recv_arphdr->plen);
  fprintf (stdout, "    Opcode (2 = ARP reply): %u\n", ntohs (recv_arphdr->opcode));
  fprintf (stdout, "    Sender MAC address: ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", recv_arphdr->sender_mac[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Sender IPv4 address: %u.%u.%u.%u\n",
    recv_arphdr->sender_ip[0], recv_arphdr->sender_ip[1], recv_arphdr->sender_ip[2], recv_arphdr->sender_ip[3]);
  fprintf (stdout, "    Target MAC address (this node): ");
  for (i = 0; i < 6; i++) {
    fprintf (stdout, "%02x%s", recv_arphdr->target_mac[i], (i < 5) ? ":" : "\n");
  }
  fprintf (stdout, "    Target IPv4 address (this node): %u.%u.%u.%u\n\n",
    recv_arphdr->target_ip[0], recv_arphdr->target_ip[1], recv_arphdr->target_ip[2], recv_arphdr->target_ip[3]);

  // Close socket descriptors.
  close (sendsd);
  close (recvsd);

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (ether_frame);
  free (interface);
  free (target);
  free (src_ip);

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
