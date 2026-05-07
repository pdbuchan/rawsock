## Tunneling IPv6 over IPv4 (6to4) - [RFC 4213](https://datatracker.ietf.org/doc/html/rfc4213)

For the transition from IPv4 to IPv6, a mechanism of tunneling IPv6 over IPv4 (6to4) has been established. Note that Section 3.5 of [RFC 4213](https://datatracker.ietf.org/doc/html/rfc4213) states that IP options are not permitted in the IPv4 header.

| File | Description |
| :--- | :--- |
| tcp6_6to4.c | Send SYN packet (an example with no TCP data). |
| get6_6to4.c | Send HTTP GET (an example with TCP data)*. |
| icmp6_6to4.c | Send ICMP Echo Request with data. |
| ping6_6to4.c | Send ICMP Echo Request with data and receive reply. i.e., ping |
| udp6_6to4.c | Send UDP packet with data. |

*This HTTP GET packet will not actually get anything because we haven't gone through the [SYN, SYN-ACK, ACK process](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment).
