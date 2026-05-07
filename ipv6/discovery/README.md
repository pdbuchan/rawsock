Neighbor Discovery and Router Discovery

The neighbor discovery process is used to obtain the MAC address of a link-local node's interface card (could be the MAC address of a link-local router or host's interface the frames will be routed through). First we send a neighbor solicitation with our MAC address to the target node, and then it replies with a neighbor advertisement that contains its MAC address. The neighbor solicitation is sent to the target node's solicited-node multicast address.

Some router discovery routines are also included. Router solicitations are issued by a host looking for local routers, and router advertisements are issued by routers announcing their presence on the LAN.

| File | Description |
| :--- | :--- |
| ns.c | Send a neighbor solicitation. |
| na.c | Send a neighbor advertisement (this example doesn't detect and respond to a solicitation). |
| receive_na.c | Receive a neighbor advertisement and extract lots of info including MAC address. |
| rs6.c | Send a router solicitation. |
| ra6.c | Send a router advertisement (this example doesn't detect and respond to a solicitation). |
| receive_ra6.c | Receive a router advertisement and extract lots of info including MAC address. |
