## Miscellaneous - Some other useful functions

To learn the next-hop's MAC address for use in the /linklayer and /cooked examples, you must use the Address Resolution Protocol (ARP). I have included an example which sends an ARP request ethernet frame as well as an example that receives an ARP reply ethernet frame.

Additionally, I have included some router solicitation and advertisement routines.

| File | Description |
| :--- | :--- |
| arp.c | Send an ARP request and receive an ARP replay via ethernet frame. `sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ARP));` |
| rs4.c | Send a router solicitation. `sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);` |
| ra4.c | Send a router advertisement. `sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);` |
| receive_ra4.c | Receive a router advertisement. `sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP));` |
| tr4_ll.c | TCP/ICMP/UDP traceroute. `sendsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));`, `recsd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_IP));` |
