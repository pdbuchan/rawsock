## Destination Extension Header (last) - [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200)

Here I provide an example of sending a TCP packet with a hop-by-hop extension header with a router alert option, destination extension header (last) with an Identifier-Locator Network Protocol (ILNP) nonce option, and enough TCP data to require fragmentation. Here, "last" means a destination header that is to be processed only by the final destination node. This is relevent in terms of where in the packet the destination header is placed. A destination header can also be placed such that it is processed by devices specified within a routing header.

If multiple extension headers are used, they must appear in a specific order (see `header_linking_and_fragmentation.c` of my [Simple Packet Sender (SPS) project](https://github.com/pdbuchan/sps).

| File | Description |
| :--- | :--- |
| data | 12390-byte file to use as upper layer protocol data |
| tcp6_hop_dst_frag.c | Send TCP packet with a hop-by-hop extension header, destination extension header (last), and enough data to require fragmentation. |
