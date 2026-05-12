## Cooked Packets

As in the IPv4 cooked packet examples, here we fill out all values, but only including the destination (i.e., next hop) Layer 2 (data link) information and not the source MAC address. Similar to IPv4, this is called a "cooked packet." We must know the MAC address of the router/host the frames will be routed to next (Note 1).

| File | Description |
| :--- | :--- |
| tcp6_cooked.c | Send SYN packet (an example with no TCP data). |
| get6_cooked.c | Send HTTP GET (an example with TCP data) (Note 2). |
| icmp6_cooked.c | Send ICMP Echo Request with data. |
| udp6_cooked.c | Send UDP packet with data. |

### Note 1

First I recommend checking out the [OSI model](https://en.wikipedia.org/wiki/OSI_model).

MAC addresses are link-local addresses and are only used to route packets on a LAN, that is, amongst interfaces (wireless cards, ethernet cards, etc.) that are on the same local network.
For ethernet, this means all the ethernet cards attached to the same cable (and via switches).

IP addresses are for traversing outside a LAN to a node located within some other LAN.

What this means is, the destination MAC address in an ethernet frame is the MAC address of the interface of the *next hop*, not the final destination.

If I send a packet to google.com, the packet I send will have the destination MAC address as my home router's interface and the destination IP address of google.com.

With IPv4, we find the MAC address of another node's interface on our LAN using ARP. With IPv6, we use the neighbor discovery process.

### Note 2

This HTTP GET packet will not actually get anything because we haven't gone through the [SYN, SYN-ACK, ACK process](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment).
