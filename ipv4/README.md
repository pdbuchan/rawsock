# IPv4 Raw Sockets

Three combinations of the *Domain*, *Type*, and *Protocol* arguments are shown here. There are other possible combinations you could try. The packet parameters that can be modified are determined by which combination you choose.

A socket descriptor is obtained with a call to `socket()`:

`int sd = socket (Domain, Type, Protocol);`

## Combination 1: hdrincl
`sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);`<br/>
The kernel fills out layer 2 (data link) information (MAC addresses) for us.

## Combination 2: linklayer
`sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));`<br/>
We provide layer 2 (data link) information. i.e., we specify ethernet frame header with MAC addresses.

## Combination 3: cooked
`sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL));`<br/>
We provide a "cooked" packet with destination MAC address in struct sockaddr_ll.
