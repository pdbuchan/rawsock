## Authentication Extension Header - [RFC 4302](https://datatracker.ietf.org/doc/html/rfc4302) and [RFC 4305](https://datatracker.ietf.org/doc/html/rfc4305)

The Authentication Header provides data origin and integrity authentication (Note 1).

Here we send a TCP packet with a hop-by-hop extension header, authentication extension header, and enough TCP data to require fragmentation. The hop-by-hop header contains two options: a router alert, and a PadN padding option which is required to pad to the appropriate boundary. For demonstration purposes here, the router alert option provides a value which is currently unassigned by [IANA](https://www.iana.org/) (see Section 2.1 of [RFC 2711](https://datatracker.ietf.org/doc/html/rfc2711)). Here, the authentication header carries a random bogus integrity check value (ICV) for demonstration; normally, this is computed as per [RFC 4302](https://datatracker.ietf.org/doc/html/rfc4302) and [RFC 4305](https://datatracker.ietf.org/doc/html/rfc4305). Since the authentication header can be used in transport or tunnel mode, an example is given of each.

| File | Description |
| :--- | :--- |
| data | 12390-byte file to use as upper layer protocol data |
| tcp6_hop_auth-tr_frag.c | Send TCP packet with a hop-by-hop extension header with router alert option, authentication extension header (in transport mode), and enough data to require fragmentation. |
| tcp6_hop_auth-tun_frag.c | Send TCP packet with a hop-by-hop extension header with router alert option, authentication extension header (in tunnel mode), and enough data to require fragmentation. |

### Note 1

The main difference between the AH and ESP headers is the extent of coverage. Specifically, ESP does not protect any IP header fields unless those fields are encapsulated by ESP (tunnel mode). The ESP header provides confidentiality, data origin and integrity authentication, an anti-replay service, and limited traffic flow confidentiality.

The respective RFCs (given below) explain the encryption requirements; no encryption is done here in the examples.

For more details on how to use AH and ESP in various network environments, see the security architecture document [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301).

The IP security (IPsec) protocols (AH and ESP) can be used in either transport mode or tunnel mode. Section 5.1.2.2 of [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301) states that in tunnel mode, the inner extension headers, if any, are not copied to become outer extension headers, although new outer extension headers can be created as desired.
