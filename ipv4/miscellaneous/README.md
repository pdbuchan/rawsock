To learn the next-hop's MAC address for use in the /fullraw and /cooked examples, you must use the Address Resolution Protocol (ARP). I have included an example which sends an ARP request ethernet frame as well as an example that receives an ARP reply ethernet frame. Additionally, I have included some router solicitation and advertisement routines.

| File | Description |
| arp.c | Send an ARP request ethernet frame. |
| receive_arp.c | Receive an ARP reply ethernet frame. |
| rs4.c | Send a router solicitation. |
| ra4.c | Send a router advertisement. |
| receive_ra4.c | Receive a router advertisement. |
| tr4_ll.c | TCP/ICMP/UDP traceroute |
