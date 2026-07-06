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

// Send an IPv4 ARP packet via raw socket at the link layer (Ethernet frame) and
// receive ARP reply.

#define _GNU_SOURCE           // Sometimes required for GNU/Linux-specific interfaces. e.g., SO_BINDTODEVICE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // memset(), memcpy()
#include <stdint.h>           // uint8_t, uint16_t, uint32_t

#include <netdb.h>            // struct addrinfo
#include <sys/socket.h>       // socket()
#include <poll.h>             // poll()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton(), inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_HLEN, ETH_P_ARP
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)

#include <errno.h>            // errno

// Define some constants.
#define ETH_HDRLEN ETH_HLEN   // Ethernet header length
#define MAC_LEN 6             // Length of a hardware (MAC) address
#define ARP_ETH_IPV4_LEN 28   // Complete Ethernet/IPv4 ARP packet
#define ARPOP_REQUEST 1       // Taken from <linux/if_arp.h>
#define ARPOP_REPLY 2         // Taken from <linux/if_arp.h>
#define HOSTNAME_LEN 255      // Maximum FQDN length including terminating null byte

// Define a struct for ARP header
typedef struct {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen; 
  uint16_t opcode;
  uint8_t sender_mac[MAC_LEN];
  uint8_t sender_ip[4];
  uint8_t target_mac[MAC_LEN];
  uint8_t target_ip[4];
} ARP_HDR;

// Function prototypes
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);

int
main (void) {

  int i, n, status, frame_length, sd, sendsd, recvsd, timeout;
  ssize_t bytes;
  char *interface, *target, *src_ip;
  ARP_HDR send_arphdr, *recv_arphdr;
  uint8_t src_mac[MAC_LEN] = {0}, dst_mac[MAC_LEN] = {0}, *ether_frame;
  struct addrinfo hints, *res;
  struct sockaddr_in dst;
  struct sockaddr_ll device, recv_device;
  struct ifreq ifr;
  struct pollfd pfd;

  memset (&send_arphdr, 0, sizeof (send_arphdr));

  // Allocate memory for various arrays.
  ether_frame = allocate_ustrmem (ETH_HDRLEN + IP_MAXPACKET);
  interface = allocate_strmem (sizeof (ifr.ifr_name));
  target = allocate_strmem (HOSTNAME_LEN);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);

  // Interface to send packet through.
  snprintf (interface, sizeof (ifr.ifr_name), "enp7s0");

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
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, sizeof (src_mac));

  // Set destination MAC address to the broadcast address.
  memset (dst_mac, 0xff, sizeof (dst_mac));

  // Source IPv4 address: You need to fill this out.
  snprintf (src_ip, INET_ADDRSTRLEN, "192.168.0.9");

  // Destination hostname or IPv4 address (must be directly reachable on the local network).
  // You need to fill this out.
  snprintf (target, HOSTNAME_LEN, "192.168.0.63");

  // Fill out hints for getaddrinfo().
  memset (&hints, 0, sizeof (hints));
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
  memset (&dst, 0, sizeof (dst));
  memcpy (&dst, res->ai_addr, res->ai_addrlen);
  memcpy (send_arphdr.target_ip, &dst.sin_addr, sizeof (send_arphdr.target_ip));
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
  memcpy (device.sll_addr, dst_mac, sizeof (dst_mac));
  device.sll_halen = sizeof (dst_mac);

  // ARP header

  // Hardware type (16 bits): 1 for Ethernet
  send_arphdr.htype = htons (1);

  // Protocol type (16 bits): Ethernet type ETH_P_IP (0x0800) for IPv4.
  send_arphdr.ptype = htons (ETH_P_IP);

  // Hardware address length (8 bits): 6 bytes for MAC address
  send_arphdr.hlen = MAC_LEN;

  // Protocol address length (8 bits): 4 bytes for IPv4 address
  send_arphdr.plen = 4;

  // OpCode: 1 for ARP request
  send_arphdr.opcode = htons (ARPOP_REQUEST);

  // Sender hardware address (48 bits): MAC address
  memcpy (send_arphdr.sender_mac, src_mac, sizeof (send_arphdr.sender_mac));

  // Sender protocol address (32 bits)
  // See inet_pton() conversion of src_ip.

  // Target hardware address (48 bits): Zero, since we don't know it yet.
  memset (send_arphdr.target_mac, 0, sizeof (send_arphdr.target_mac));

  // Target protocol address (32 bits)
  // See getaddrinfo() resolution of target.

  // Fill out Ethernet frame header.

  // Ethernet frame length = Ethernet header (MAC + MAC + Ethernet type) + Ethernet data (ARP header)
  frame_length = ETH_HDRLEN + ARP_ETH_IPV4_LEN;

  // Destination and Source MAC addresses
  memcpy (ether_frame, dst_mac, sizeof (dst_mac));
  memcpy (ether_frame + sizeof (dst_mac), src_mac, sizeof (src_mac));

  // EtherType (16 bits): ETH_P_ARP
  // http://www.iana.org/assignments/ethernet-numbers
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;

  // Next is Ethernet frame data (ARP header).

  // ARP header
  memcpy (ether_frame + ETH_HDRLEN, &send_arphdr, ARP_ETH_IPV4_LEN);

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

  // Send Ethernet frame to socket.
  bytes = sendto (sendsd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device));
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

  // Print out contents of send Ethernet frame.
  fprintf (stdout, "\nSENT ETHERNET FRAME\n");
  fprintf (stdout, "  Ethernet header:\n");
  fprintf (stdout, "    Destination MAC (broadcast) address: ");
  for (i = 0; i < (int) sizeof (dst_mac); i++) {
    fprintf (stdout, "%02x%s", dst_mac[i], (i < (int) sizeof (dst_mac) - 1) ? ":" : "\n");
  }
  fprintf (stdout, "    Source MAC address (this node): ");
  for (i = 0; i < (int) sizeof (src_mac); i++) {
    fprintf (stdout, "%02x%s", src_mac[i], (i < (int) sizeof (src_mac) - 1) ? ":" : "\n");
  }
  // EtherType (16 bits): ETH_P_ARP
  // http://www.iana.org/assignments/ethernet-numbers
  fprintf (stdout, "    Ethernet type code (2054 = ARP): %u\n\n", ((ether_frame[12]) << 8) + ether_frame[13]);

  fprintf (stdout, "  ARP header:\n");
  fprintf (stdout, "    Hardware type (1 = Ethernet (10 Mb)): %u\n", ntohs (send_arphdr.htype));
  fprintf (stdout, "    Protocol type (ETH_P_IP (0x0800) for IPv4): %u\n", ntohs (send_arphdr.ptype));
  fprintf (stdout, "    Hardware (MAC) address length (bytes): %u\n", send_arphdr.hlen);
  fprintf (stdout, "    Protocol (IPv4) address length (bytes): %u\n", send_arphdr.plen);
  fprintf (stdout, "    Opcode (1 = ARP request): %u\n", ntohs (send_arphdr.opcode));
  fprintf (stdout, "    Sender MAC address (this node): ");
  for (i = 0; i < (int) sizeof (send_arphdr.sender_mac); i++) {
    fprintf (stdout, "%02x%s", send_arphdr.sender_mac[i], (i < (int) sizeof (send_arphdr.sender_mac) - 1) ? ":" : "\n");
  }
  fprintf (stdout, "    Sender IPv4 address: %u.%u.%u.%u\n",
    send_arphdr.sender_ip[0], send_arphdr.sender_ip[1], send_arphdr.sender_ip[2], send_arphdr.sender_ip[3]);
  fprintf (stdout, "    Target MAC address: ");
  for (i = 0; i < (int) sizeof (send_arphdr.target_mac); i++) {
    fprintf (stdout, "%02x%s", send_arphdr.target_mac[i], (i < (int) sizeof (send_arphdr.target_mac) - 1) ? ":" : "\n");
  }
  fprintf (stdout, "    Target IPv4 address: %u.%u.%u.%u\n",
    send_arphdr.target_ip[0], send_arphdr.target_ip[1], send_arphdr.target_ip[2], send_arphdr.target_ip[3]);

  // Listen for incoming Ethernet frame from socket recvsd.
  // We expect an ARP Ethernet frame of the form:
  //     MAC (6 bytes) + MAC (6 bytes) + Ethernet type (2 bytes)
  //     + Ethernet data (ARP header) (28 bytes)
  // Keep at it until we get an ARP reply.
  timeout = 2000;  // Milliseconds
  pfd.fd = recvsd;
  pfd.events = POLLIN;
  memset (ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);
  recv_arphdr = (ARP_HDR *) (ether_frame + ETH_HDRLEN);
  for (;;) {
    status = poll (&pfd, 1, timeout);
    if (status < 0) {
      if (errno == EINTR) {
        continue;  // System call interrupted by a signal before completion. Retry.
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
      memset (ether_frame, 0, ETH_HDRLEN + IP_MAXPACKET);
      if ((bytes = recv (recvsd, ether_frame, ETH_HDRLEN + ARP_ETH_IPV4_LEN, 0)) < 0) {
        if (errno == EINTR) {
          continue;  // System call interrupted by a signal before completion. Retry.
        } else {
          fprintf (stderr, "recv() failed.\nError message: %s\n", strerror (errno));
          exit (EXIT_FAILURE);
        }
      }

      // Check for sufficient bytes to parse Ethernet and ARP headers.
      if (bytes < (ETH_HDRLEN + ARP_ETH_IPV4_LEN)) {
        continue;
      }

      // Ensure we have an ARP reply with correct source and destination IP addresses, and 
      // this node's MAC address.
      recv_arphdr = (ARP_HDR *) (ether_frame + ETH_HDRLEN);
      if (((((ether_frame[12]) << 8) + ether_frame[13]) == ETH_P_ARP) &&
        (ntohs (recv_arphdr->htype) == 1) &&
        (ntohs (recv_arphdr->ptype) == ETH_P_IP) &&
        (recv_arphdr->hlen == MAC_LEN) &&
        (recv_arphdr->plen == 4) &&
        (ntohs (recv_arphdr->opcode) == ARPOP_REPLY) &&
        (memcmp (recv_arphdr->sender_ip, send_arphdr.target_ip, 4) == 0) &&
        (memcmp (recv_arphdr->target_ip, send_arphdr.sender_ip, 4) == 0) &&
        (memcmp (recv_arphdr->target_mac, src_mac, sizeof (src_mac)) == 0)) {
        break;
      }
    }
  }

  // Print out contents of received Ethernet frame.
  fprintf (stdout, "\nRECEIVED ETHERNET FRAME\n");
  fprintf (stdout, "  Ethernet header:\n");
  fprintf (stdout, "    Destination MAC address (this node): ");
  for (i = 0; i < (int) recv_arphdr->hlen; i++) {
    fprintf (stdout, "%02x%s", ether_frame[i], (i < (int) recv_arphdr->hlen - 1) ? ":" : "\n");
  }
  fprintf (stdout, "    Source MAC address: ");
  for (i = 0; i < (int) recv_arphdr->hlen; i++) {
    fprintf (stdout, "%02x%s", ether_frame[i + (int) recv_arphdr->hlen], (i < (int) recv_arphdr->hlen - 1) ? ":" : "\n");
  }
  // EtherType (16 bits): ETH_P_ARP
  // http://www.iana.org/assignments/ethernet-numbers
  fprintf (stdout, "    Ethernet type code (2054 = ARP): %u\n\n", ((ether_frame[12]) << 8) + ether_frame[13]);

  fprintf (stdout, "  ARP header:\n");
  fprintf (stdout, "    Hardware type (1 = Ethernet (10 Mb)): %u\n", ntohs (recv_arphdr->htype));
  fprintf (stdout, "    Protocol type (ETH_P_IP (0x0800) for IPv4): %u\n", ntohs (recv_arphdr->ptype));
  fprintf (stdout, "    Hardware (MAC) address length (bytes): %u\n", recv_arphdr->hlen);
  fprintf (stdout, "    Protocol (IPv4) address length (bytes): %u\n", recv_arphdr->plen);
  fprintf (stdout, "    Opcode (2 = ARP reply): %u\n", ntohs (recv_arphdr->opcode));
  fprintf (stdout, "    Sender MAC address: ");
  for (i = 0; i < (int) recv_arphdr->hlen; i++) {
    fprintf (stdout, "%02x%s", recv_arphdr->sender_mac[i], (i < (int) recv_arphdr->hlen - 1) ? ":" : "\n");
  }
  fprintf (stdout, "    Sender IPv4 address: %u.%u.%u.%u\n",
    recv_arphdr->sender_ip[0], recv_arphdr->sender_ip[1], recv_arphdr->sender_ip[2], recv_arphdr->sender_ip[3]);
  fprintf (stdout, "    Target MAC address (this node): ");
  for (i = 0; i < (int) recv_arphdr->hlen; i++) {
    fprintf (stdout, "%02x%s", recv_arphdr->target_mac[i], (i < (int) recv_arphdr->hlen - 1) ? ":" : "\n");
  }
  fprintf (stdout, "    Target IPv4 address (this node): %u.%u.%u.%u\n\n",
    recv_arphdr->target_ip[0], recv_arphdr->target_ip[1], recv_arphdr->target_ip[2], recv_arphdr->target_ip[3]);

  // Close socket descriptors.
  close (sendsd);
  close (recvsd);

  // Free allocated memory.
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
