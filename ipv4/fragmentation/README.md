These are examples of packet fragmentation. The first file, called "data", contains a list of numbers. The following three routines use it as data for the upper layer protocols. Feel free to provide to the routines your own data in any manner you prefer.<br/><br/>

    data          12390-byte file to use as upper layer protocol data
    tcp4_frag.c   Send TCP packet with enough data to require fragmentation.
    icmp4_frag.c  Send ICMP packet with enough data to require fragmentation.
    udp4_frag.c   Send UDP packet with enough data to require fragmentation.
