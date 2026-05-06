sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));

We provide layer 2 (data link) information. i.e., we specify ethernet frame header with MAC addresses.

tcp4_ll.c 	Send SYN packet (an example with no TCP data).
get4_ll.c 	Send HTTP GET (an example with TCP data).
icmp4_ll.c 	Send ICMP Echo Request with data.
ping4_ll.c 	Send ICMP Echo Request with data and receive reply. i.e., ping
udp4_ll.c 	Send UDP packet with data.
