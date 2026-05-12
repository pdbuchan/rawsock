# IPv6 Raw Sockets

## IPv6 introduces the need for Neighbor Discovery

In IPv6, we have less options at our disposal for modifying packet values (see [RFC 3542](https://datatracker.ietf.org/doc/html/rfc3542) and [RFC 3493](https://datatracker.ietf.org/doc/html/rfc3493)). In particular, IPv6 has no equivalent to using `setsockopt()` with the `IP_HDRINCL` flag (see ipv4/hdrincl examples). Without doing something special (using neighbor discovery), we can only change the hop limit and traffic class to arbitrary values. Neighbor discovery is the IPv6 replacement for ARP in IPv4.

If we wish to have the ability to change any parameter in the IPv6 header, we need to have the source and destination MAC addresses available (Note 1). Before trying neighbor discovery, you can take a quick look at a couple of examples where we don't use neighbor discovery, and thus can only change the hop limit and traffic class values in the IPv6 header.

You can use either the ancillary data method, or a call to `setsockopt()` with option level `IPPROTO_IPV6` and option names `IPV6_TCLASS`, `IPV6_UNICAST_HOPS`, or `IPV6_MULTICAST_HOPS`. Note that changes made to the properties of the socket with `setsockopt()` will remain in effect for all packets sent through the socket, whereas ancillary data is associated with a particular packet.

## IPv6 introduces Extension Headers

The IP header in IPv6 does not have provision for IP options embedded within the IP header itself like in IPv4. Instead, extension headers are used. Extension headers are optional headers that are positioned after the IPv6 header but before the TCP, ICMP, or UDP header. You can use multiple extension headers simultaneously by linking them to each other in a chain, one after another. If multiple extension headers are used, they must appear in a specific order (see `header_linking_and_fragmentation.c` of my [Simple Packet Sender (SPS) project](https://github.com/pdbuchan/sps/tree/main).

In IPv6, packet fragmentation requires the introduction of a fragment extension header. 

### Note 1

First I recommend checking out the [OSI model](https://en.wikipedia.org/wiki/OSI_model).

MAC addresses are link-local addresses and are only used to route packets on a LAN, that is, amongst interfaces (wireless cards, ethernet cards, etc.) that are on the same local network.

For ethernet, this means all the ethernet cards attached to the same cable (and via switches).

IP addresses are for traversing outside a LAN to a node located within some other LAN.

What this means is, the destination MAC address in an ethernet frame is the MAC address of the interface of the *next hop*, not the final destination.

If I send a packet to google.com, the packet I send will have the destination MAC address as my home router's interface and the destination IP address of google.com.

With IPv4, we find the MAC address of another node's interface on our LAN using ARP. With IPv6, we use the neighbor discovery process.
