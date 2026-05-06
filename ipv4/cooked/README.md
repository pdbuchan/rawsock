In these examples, we fill out all values, but only including the destination (i.e., next-hop) layer 2 (data link) information (not source MAC address). This is called a "cooked packet." To do this, we must know the MAC address of the router/host the frames will be routed to next*.<br/><br/>

    sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL));
	We provide a "cooked" packet with destination MAC address in struct sockaddr_ll.

    tcp4_cooked.c 	Send SYN packet (an example with no TCP data).
    get4_cooked.c 	Send HTTP GET (an example with TCP data) (note).
    icmp4_cooked.c 	Send ICMP Echo Request with data.
    udp4_cooked.c 	Send UDP packet with data.

*Based on questions received, some explanation is in order.<br/><br/>

First I recommend checking out the OSI model.<br/><br/>

The super short version of the story is this:<br/>
MAC addresses are link-local addresses and are only used to route packets on a LAN, that is, amongst interfaces (wireless cards, ethernet cards, etc.) that are on the same local network. For ethernet, this means all the ethernet cards attached to the same cable (and via switches).<br/>
IP addresses are for traversing outside a LAN to a node located within some other LAN.<br/>
What this means is, the destination MAC address in an ethernet frame is the MAC address of the interface of the NEXT HOP, not the final destination.<br/>
If I send a packet to google.com, the packet I send will have the destination MAC address as my home router's interface and the destination IP address of google.com.<br/>
With IPv4, we find the MAC address of another node's interface on our LAN using ARP.<br/>
With IPv6, we use the neighbor discovery process.<br/>
