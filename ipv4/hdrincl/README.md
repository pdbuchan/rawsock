In the examples below, we tell the kernal the IP header is included (by us) by using setsockopt() and the IP_HDRINCL flag, and we can modify all values within the packet but the kernal fills out the layer 2 (data link) information (source and next-hop MAC addresses) for us.<br/><br/>

    tcp4.c    Send SYN packet (an example with no TCP data).
    get4.c    Send HTTP GET (an example with TCP data) (note).
    icmp4.c   Send ICMP Echo Request with data.
    udp4.c    Send UDP packet with data.
