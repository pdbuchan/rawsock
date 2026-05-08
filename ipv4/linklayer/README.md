## Link Layer - We provide everything

In these examples, we fill out all values, including the layer 2 (data link) information (source and next-hop MAC addresses). To do this, we must know the MAC address of the router/host the frames will be routed to next (more explanation), as well as the MAC address of the network interface ("network card") we're sending the packet from.

    sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

We provide layer 2 (data link) information. i.e., we specify ethernet frame header with MAC addresses.

| File | Description |
| :--- | :--- |
| tcp4_ll.c | Send SYN packet (an example with no TCP data). |
| get4_ll.c | Send HTTP GET (an example with TCP data) (Note 1). |
| icmp4_ll.c | Send ICMP Echo Request with data. |
| ping4_ll.c | Send ICMP Echo Request with data and receive reply. i.e., ping |
| udp4_ll.c | Send UDP packet with data. |

### Note 1

This HTTP GET packet will not actually get anything because we haven't gone through the [SYN, SYN-ACK, ACK process](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment).
