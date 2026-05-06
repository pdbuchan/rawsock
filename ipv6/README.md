In IPv6, we have less options at our disposal for modifying packet values (see RFC 3542 and RFC 3493). In particular, IPv6 has no equivalent to using setsockopt() with the IP_HDRINCL flag (see /hdrincl examples). Without doing something special (using neighbor discovery), we can only change the hop limit and traffic class to arbitrary values. Neighbor discovery is the IPv6 replacement for ARP in IPv4.<br/><br/>

**Ancillary Data Method**<br/><br/>
Before we try some neighbor discovery, let's take a quick look at a couple of examples where we don't use neighbor discovery, and thus can only change the hop limit and traffic class values in the IPv6 header.<br/><br/>

You can use either the ancillary data method, or a call to setsockopt() with option level IPPROTO_IPV6 and option names IPV6_TCLASS, IPV6_UNICAST_HOPS, or IPV6_MULTICAST_HOPS. Note that changes made to the properties of the socket with setsockopt() will remain in effect for all packets sent through the socket, whereas ancillary data is associated with a particular packet.<br/><br/>
