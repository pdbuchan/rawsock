## Ancillary Data Method Examples

For these example, we send ICMP Echo Request Without Using Neighbor Discovery (ND).

Examples `icmp6_ancillary1.c` and `icmp6_ancillary2.c` use the `bind()` function to bind the socket to the source IP address. Example `icmp6_ancillary3.c` sets the source IP address using ancillary data. In either case, the supplied source address must actually be assigned to the interface or else the `sendto()` call will fail and the packet won't be sent.

| File | Description |
| :--- | :--- |
| icmp6_ancillary1.c | Change hop limit using ancillary data. Source IP address set using bind(). |
| icmp6_ancillary2.c | Change hop limit and specify source interface using ancillary data. Source IP address set using bind(). |
| icmp6_ancillary3.c | Change hop limit, specify source interface, and source IP address using ancillary data. |
