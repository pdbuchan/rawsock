Fragmentation - Section 4.5 of [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200) and [RFC 7739](https://datatracker.ietf.org/doc/html/rfc7739)<br/><br/>

In IPv6, packet fragmentation requires the introduction of a fragment extension header. The first file, called "data", contains a list of numbers, and the following routines use it as data for the upper layer protocols. Feel free to provide to the routines your own data in any manner you prefer.<br/><br/>

    data                12390-byte file to use as upper layer protocol data
    tcp6_frag.c         Send TCP packet with enough data to require fragmentation.
    icmp6_frag.c        Send ICMP packet with enough data to require fragmentation.
    udp6_frag.c         Send UDP packet with enough data to require fragmentation.
    tcp6_6to4_frag.c    Send IPv6 TCP packet through IPv4 tunnel with enough data to require fragmentation.
    icmp6_6to4_frag.c   Send IPv6 ICMP packet through IPv4 tunnel with enough data to require fragmentation.
    udp6_6to4_frag.c    Send IPv6 UDP packet through IPv4 tunnel with enough data to require fragmentation.
