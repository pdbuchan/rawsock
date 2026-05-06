As in the IPv4 cooked packet examples, here we fill out all values, but only including the destination (i.e., next hop) layer 2 (data link) information and not the source MAC address. Similar to IPv4, this is called a "cooked packet." We must know the MAC address of the router/host the frames will be routed to next*.<br/<br/>

*Based on questions received, some explanation is in order...

First I recommend checking out the [OSI model](https://en.wikipedia.org/wiki/OSI_model).

    The super short version of the story is this:
      MAC addresses are link-local addresses and are only used to route packets on a LAN, that is,
	  amongst interfaces (wireless cards, ethernet cards, etc.) that are on the same local network.
	  For ethernet, this means all the ethernet cards attached to the same cable (and via switches).

      IP addresses are for traversing outside a LAN to a node located within some other LAN.

      What this means is, the destination MAC address in an ethernet frame is the MAC address of the
	  interface of the NEXT HOP, not the final destination.

      If I send a packet to google.com, the packet I send will have the destination MAC address as
	  my home router's interface and the destination IP address of google.com.

      With IPv4, we find the MAC address of another node's interface on our LAN using ARP.
      With IPv6, we use the neighbor discovery process.
