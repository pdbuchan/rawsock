    sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

If we have used neighbor discovery to determine the MAC address of a link-local router or host, we can go ahead and modify all parameters within the ethernet frame.

| File | Description |
| :--- | :--- |
| tcp6_ll.c | Send SYN packet (an example with no TCP data). |
| get6_ll.c | Send HTTP GET (an example with TCP data)*. |
| icmp6_ll.c | Send ICMP Echo Request with data. |
| ping6_ll.c | Send ICMP Echo Request with data and receive reply. i.e., ping |
| udp6_ll.c | Send UDP packet with data. |

*This HTTP GET packet will not actually get anything because we haven't gone through the [SYN, SYN-ACK, ACK process](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment).
