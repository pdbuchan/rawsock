Hop-by-Hop Extension Header - Section 4.3 of [RFC 8200](https://datatracker.ietf.org/doc/html/rfc8200)<br/><br/>

This is an example of sending a TCP packet with a hop-by-hop extension header and enough TCP data to require fragmentation. The hop-by-hop header contains two options: a router alert, and a PadN padding option which is required to pad to the appropriate boundary. For demonstration purposes here, the router alert option provides a value which is currently unassigned by [IANA](https://www.iana.org/) (see Section 2.1 of [RFC 2711](https://datatracker.ietf.org/doc/html/rfc2711)).
