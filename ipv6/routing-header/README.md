Routing Extension Header (Type 3) - [RFC 6554](https://datatracker.ietf.org/doc/html/rfc6554)

There are several possible types of routing header, specified in the Routing Type field of the header itself. Types 0 and 1 routing headers have been deprecated (IANA Parameters List).

Here we use a type 3 routing header, which is a Source Routing Header for the routing protocol for low-power and lossy networks (RPL).

| File | Description |
| :--- | :--- |
| data | 12390-byte file to use as upper layer protocol data |
| tcp6_hop_route3_frag.c | Send TCP packet with a hop-by-hop extension header, type 3 routing extension header, and enough data to require fragmentation. |
