## TCP Options - Section 3.1 of [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293)

Here are two examples which include options in the TCP header.

| File | Description |
| :--- | :--- |
| tcp6_maxseg.c | Send TCP packet with a TCP option which sets maximum segment size. |
| tcp6_maxseg_tsopt.c | Send TCP packet with two TCP options: set maximum segment size, and provide time stamp. |
