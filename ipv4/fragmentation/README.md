## Fragmentation

If the size of payload exceeds what a single packet can carry, multiple packets will be needed. This process is called packet fragmentation. The first file, called "data", contains a list of numbers, and its size exceeds the capacity of one packet. The following three routines use it as data for the upper layer protocols. Feel free to provide to the routines your own data in any manner you prefer.

| File | Description |
| :--- | :--- |
| data | 12390-byte file to use as upper layer protocol data |
| tcp4_frag.c | Send TCP packet with enough data to require fragmentation. |
| icmp4_frag.c | Send ICMP packet with enough data to require fragmentation. |
| udp4_frag.c | Send UDP packet with enough data to require fragmentation. |
