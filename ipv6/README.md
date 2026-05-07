# IPv6 introduces the need for Neighbor Discovery

In IPv6, we have less options at our disposal for modifying packet values (see [RFC 3542](https://datatracker.ietf.org/doc/html/rfc3542) and [RFC 3493](https://datatracker.ietf.org/doc/html/rfc3493)). In particular, IPv6 has no equivalent to using setsockopt() with the IP_HDRINCL flag (see /hdrincl examples). Without doing something special (using neighbor discovery), we can only change the hop limit and traffic class to arbitrary values. Neighbor discovery is the IPv6 replacement for ARP in IPv4.

If we wish to have the ability to change any parameter in the IPv6 header, we need to have the source and destination MAC addresses available*. Before trying neighbor discovery, you can take a quick look at a couple of examples where we don't use neighbor discovery, and thus can only change the hop limit and traffic class values in the IPv6 header.

You can use either the ancillary data method, or a call to setsockopt() with option level IPPROTO_IPV6 and option names IPV6_TCLASS, IPV6_UNICAST_HOPS, or IPV6_MULTICAST_HOPS. Note that changes made to the properties of the socket with setsockopt() will remain in effect for all packets sent through the socket, whereas ancillary data is associated with a particular packet.

*Based on questions received, some explanation is in order...

First I recommend checking out the [OSI model](https://en.wikipedia.org/wiki/OSI_model).

The super short version of the story is this:

MAC addresses are link-local addresses and are only used to route packets on a LAN, that is, amongst interfaces (wireless cards, ethernet cards, etc.) that are on the same local network.

For ethernet, this means all the ethernet cards attached to the same cable (and via switches).

IP addresses are for traversing outside a LAN to a node located within some other LAN.

What this means is, the destination MAC address in an ethernet frame is the MAC address of the interface of the NEXT HOP, not the final destination.

If I send a packet to google.com, the packet I send will have the destination MAC address as my home router's interface and the destination IP address of google.com.

With IPv4, we find the MAC address of another node's interface on our LAN using ARP. With IPv6, we use the neighbor discovery process.

# Authentication Header (AH) and Encapsulating Security Payload (ESP) Header

Examples are given which use the authentication extension header (AH) and the encapsulating security payload (ESP) extension header.

The AH provides data origin and integrity authentication. The ESP header provides confidentiality, data origin and integrity authentication, an anti-replay service, and limited traffic flow confidentiality.

The main difference between the AH and ESP headers is the extent of coverage. Specifically, ESP does not protect any IP header fields unless those fields are encapsulated by ESP (tunnel mode).

The respective RFCs (given below) explain the encryption requirements; no encryption is done here in the examples.

For more details on how to use AH and ESP in various network environments, see the security architecture document [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301).

The IP security (IPsec) protocols (AH and ESP) can be used in either transport mode or tunnel mode. Section 5.1.2.2 of [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301) states that in tunnel mode, the inner extension headers, if any, are not copied to become outer extension headers, although new outer extension headers can be created as desired.
