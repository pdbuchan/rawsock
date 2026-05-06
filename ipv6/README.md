In IPv6, we have less options at our disposal for modifying packet values (see [RFC 3542](https://datatracker.ietf.org/doc/html/rfc3542) and [RFC 3493](https://datatracker.ietf.org/doc/html/rfc3493)). In particular, IPv6 has no equivalent to using setsockopt() with the IP_HDRINCL flag (see /hdrincl examples). Without doing something special (using neighbor discovery), we can only change the hop limit and traffic class to arbitrary values. Neighbor discovery is the IPv6 replacement for ARP in IPv4.<br/><br/>

**Ancillary Data Method**<br/><br/>
Before we try some neighbor discovery, let's take a quick look at a couple of examples where we don't use neighbor discovery, and thus can only change the hop limit and traffic class values in the IPv6 header.<br/><br/>

You can use either the ancillary data method, or a call to setsockopt() with option level IPPROTO_IPV6 and option names IPV6_TCLASS, IPV6_UNICAST_HOPS, or IPV6_MULTICAST_HOPS. Note that changes made to the properties of the socket with setsockopt() will remain in effect for all packets sent through the socket, whereas ancillary data is associated with a particular packet.<br/><br/>

**Authentication Header (AH) and Encapsulating Security Payload (ESP) Header**<br/><br/>

The following few tables give examples of the authentication extension header (AH) and the encapsulating security payload (ESP) extension header.<br/><br/>

The AH provides data origin and integrity authentication. The ESP header provides confidentiality, data origin and integrity authentication, an anti-replay service, and limited traffic flow confidentiality.<br/><br/>

The main difference between the AH and ESP headers is the extent of coverage. Specifically, ESP does not protect any IP header fields unless those fields are encapsulated by ESP (tunnel mode).<br/><br/>

The respective RFCs (given below) explain the encryption requirements; no encryption is done here in the examples.<br/><br/>

For more details on how to use AH and ESP in various network environments, see the security architecture document [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301).<br/><br/>

The IP security (IPsec) protocols (AH and ESP) can be used in either transport mode or tunnel mode. Section 5.1.2.2 of [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301) states that in tunnel mode, the inner extension headers, if any, are not copied to become outer extension headers, although new outer extension headers can be created as desired.
