In these examples, we fill out all values, but only including the destination (i.e., next-hop) layer 2 (data link) information (not source MAC address). This is called a "cooked packet." To do this, we must know the MAC address of the router/host the frames will be routed to next (more explanation).<br/><br/>

    sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL));
	  We provide a "cooked" packet with destination MAC address in struct sockaddr_ll.

    tcp4_cooked.c 	Send SYN packet (an example with no TCP data).
    get4_cooked.c 	Send HTTP GET (an example with TCP data) (note).
    icmp4_cooked.c 	Send ICMP Echo Request with data.
    udp4_cooked.c 	Send UDP packet with data.
