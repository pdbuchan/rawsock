Tunneling IPv6 over IPv4 (6to4) - [RFC 4213](https://datatracker.ietf.org/doc/html/rfc4213)<br/><br/>

For the transition from IPv4 to IPv6, a mechanism of tunneling IPv6 over IPv4 (6to4) has been established. Note that Section 3.5 of [RFC 4213](https://datatracker.ietf.org/doc/html/rfc4213) states that IP options are not permitted in the IPv4 header.<br/><br/>

    tcp6_6to4.c 	Send SYN packet (an example with no TCP data).
    get6_6to4.c 	Send HTTP GET (an example with TCP data) (note).
    icmp6_6to4.c 	Send ICMP Echo Request with data.
    ping6_6to4.c 	Send ICMP Echo Request with data and receive reply. i.e., ping
    udp6_6to4.c 	Send UDP packet with data.
