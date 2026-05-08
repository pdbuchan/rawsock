## hdrincl - We include the IP header

In these examples, we tell the kernal the IP header is included (by us) by using `setsockopt()` and the `IP_HDRINCL` flag, and we can modify all values within the packet but the kernal fills out the layer 2 (data link) information (source and next-hop MAC addresses) for us.

    sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

The kernel fills out layer 2 (data link) information (MAC addresses) for us.

| File | Description |
| :--- | :--- |
| tcp4.c | Send SYN packet (an example with no TCP data). |
| get4.c | Send HTTP GET (an example with TCP data)*. |
| icmp4.c | Send ICMP Echo Request with data. |
| udp4.c | Send UDP packet with data. |
