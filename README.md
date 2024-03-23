# Exploring a Linux Kernel sk_buff UAF Vulnerability: A Personal Journey to a Linux Kernel 0-day Vulnerability
In the vast and intricate world of the Linux kernel, sk_buff stands out as a fundamental structure tasked with the critical role of packet management. This backbone of network data flow caught my attention when I stumbled upon a rather intriguing use-after-free (UAF) vulnerability, revealed through a detailed KASAN (Kernel Address SANitizer) report. My journey into this vulnerability started with a simple Proof of Concept (PoC) but quickly evolved into a deep dive into the kernel's inner workings.

The UAF error manifests in the networking code, particularly within the IPv4 IP output path. The anomaly triggers when an sk_buff is prematurely freed and subsequently accessed, a scenario not too far-fetched in complex packet manipulation situations, like those involving crafted messages sent via raw sockets.

Diving into the KASAN report, it became evident that the slab-use-after-free errors were scattered across several functions integral to packet processing in the Linux kernel. Functions such as skb_dst, dst_output, ip_local_out, ip_send_skb, and ip_push_pending_frames were highlighted. These functions, which facilitate the sending of IP packets, were accessing sk_buff (skb) structures post their release, leading to potential kernel crashes or, worse, exploitable conditions for executing arbitrary code.

The trail of breadcrumbs left by the call trace pointed to the raw_sendmsg function as the initiation point of the vulnerability, aligning with my PoC's objective to demonstrate a critical null pointer dereference or UAF vulnerability. The process that triggered this issue involved allocating an sk_buff, dispatching it, and observing a use-after-free occurrence when the network stack attempted to reference the already freed sk_buff.

My venture into further understanding the intricacies of this vulnerability required a deep dive into several source code files, as mentioned in the KASAN report:

include/linux/skbuff.h
include/net/dst.h
net/ipv4/ip_output.c
net/ipv4/raw.c
The exploration revealed that the UAF vulnerability within the IP output path, especially during IP packet handling, was not merely a coding oversight but a critical flaw needing immediate attention.

Key Discoveries and Insights
Affected Code Paths: Functions such as ip_local_out, ip_send_skb, and ip_push_pending_frames, primarily within net/ipv4/ip_output.c, play pivotal roles in prepping and dispatching IP packets from the kernel. These were the hotspots for the vulnerability.

Triggering Conditions: The root of the vulnerability lies in the freeing and subsequent access of an sk_buff. This precarious situation arises in scenarios where packets undergo manipulation, including instances where crafted messages traverse raw sockets.

Consequences and Exploit Scenarios: The repercussions of accessing freed memory vary from data corruption and system crashes to potential arbitrary code execution. The crafted network traffic or interactions, as demonstrated by my PoC, spotlight how the kernel's mismanagement of an sk_buff can lead to exploiting this UAF vulnerability.

A significant part of my research also veered into the specifics of handling network packets, particularly through socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP). The exploration of nfnetlink.c and nf_tables_api.c sources, integral to Linux's Netfilter and nftables frameworks, opened up potential vulnerability paths. These paths hinted at the vulnerability being possibly incited by certain Netfilter configurations or by processing crafted packets with nftables rules.Z

https://elixir.bootlin.com/linux/v4.4/source/net/ipv4/ip_output.c#L1602.

https://elixir.bootlin.com/linux/latest/source/net/netfilter/nfnetlink.c#L371

https://elixir.bootlin.com/linux/latest/source/net/netfilter/nf_tables_api.c#L3796
