## IP and TCP Options

These examples include various combinations of IP and TCP options.

    `sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));`

| File | Description |
| :--- | :--- |
| tcp4_maxseg.c | Send TCP packet with a TCP option which sets maximum segment size. |
| tcp4_maxseg_tsopt.c | Send TCP packet with two TCP options: set maximum segment size, and provide time stamp. |
| tcp4_maxseg-timestamp.c | Send TCP packet with IP option to send time stamp, and TCP option to set maximum segment size. |
| tcp4_maxseg-security.c | Send TCP packet with security IP option and TCP option to set maximum segment size. |
| tcp4_2ip-opts_2tcp_opts.c | Send TCP packet with two IP options and two TCP options. |
