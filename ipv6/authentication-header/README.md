Authentication Extension Header - [RFC 4302](https://datatracker.ietf.org/doc/html/rfc4302) and [RFC 4305](https://datatracker.ietf.org/doc/html/rfc4305)<br/><br/>

Here we send a TCP packet with a hop-by-hop extension header, authentication extension header, and enough TCP data to require fragmentation. The hop-by-hop header contains two options: a router alert, and a PadN padding option which is required to pad to the appropriate boundary. For demonstration purposes here, the router alert option provides a value which is currently unassigned by [IANA](https://www.iana.org/) (see Section 2.1 of [RFC 2711](https://datatracker.ietf.org/doc/html/rfc2711)). Here, the authentication header carries a random bogus integrity check value (ICV) for demonstration; normally, this is computed as per [RFC 4302](https://datatracker.ietf.org/doc/html/rfc4302) and [RFC 4305](https://datatracker.ietf.org/doc/html/rfc4305). Since the authentication header can be used in transport or tunnel mode, an example is given of each.

| File | Description |
| :--- | :--- |
| `data` | 12390-byte file to use as upper layer protocol data |
| <nobr>`tcp6_hop_auth-tr_frag.c`</nobr> | Send TCP packet with a hop-by-hop extension header with router alert option, authentication extension header (in transport mode), and enough data to require fragmentation. |
| <nobr>`tcp6_hop_auth-tun_frag.c`</nobr> | Send TCP packet with a hop-by-hop extension header with router alert option, authentication extension header (in tunnel mode), and enough data to require fragmentation. |


<table>
<tr>
  <th>File</th>
  <th>Description</th>
</tr>
<tr>
  <td nowrap><code>very_long_filename_example.c</code></td>
  <td>blah blah</td>
</tr>
</table>
