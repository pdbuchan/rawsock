sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));<br/<br/>

If we have used neighbor discovery to determine the MAC address of a link-local router or host, we can go ahead and modify all parameters within the ethernet frame.<br/><br/>

    tcp6_ll.c 	Send SYN packet (an example with no TCP data).
    get6_ll.c 	Send HTTP GET (an example with TCP data) (note).
    icmp6_ll.c 	Send ICMP Echo Request with data.
    ping6_ll.c 	Send ICMP Echo Request with data and receive reply. i.e., ping
    udp6_ll.c 	Send UDP packet with data.
