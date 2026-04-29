# Real Trigger Additional rtable allocs

```
#0  rt_dst_alloc (dev=0xffff888004982000, flags=2147483648, type=2, nopolicy=false, noxfrm=noxfrm@entry=false) at /src/net/ipv4/route.c:1656
#1  0xffffffff81d67e93 in ip_route_input_slow (skb=0xffff888008a37d00, daddr=<optimized out>, saddr=<optimized out>, tos=<optimized out>, dev=<optimized out>, res=res@entry=0xffffc90000063b28) at /src/net/ipv4/route.c:2263
#2  0xffffffff81d6859b in ip_route_input_rcu (res=0xffffc90000063b28, dev=0xffff88800673b000, tos=<optimized out>, saddr=<optimized out>, daddr=<optimized out>, skb=0xffff888008a37d00) at /src/net/ipv4/route.c:2393
#3  ip_route_input_noref (skb=skb@entry=0xffff888008a37d00, daddr=<optimized out>, saddr=<optimized out>, tos=<optimized out>, dev=dev@entry=0xffff88800673b000) at /src/net/ipv4/route.c:2338
#4  0xffffffff81d6ac3a in ip_rcv_finish_core (net=net@entry=0xffffffff836a70c0 <init_net>, skb=skb@entry=0xffff888008a37d00, dev=dev@entry=0xffff88800673b000, hint=hint@entry=0x0 <fixed_percpu_data>, sk=0x0 <fixed_percpu_data>) at /src/net/ipv4/ip_input.c:353
#5  0xffffffff81d6b4a2 in ip_list_rcv_finish (sk=0x0 <fixed_percpu_data>, head=0xffffc90000063c28, net=0xffffffff836a70c0 <init_net>) at /src/net/ipv4/ip_input.c:582
#6  ip_sublist_rcv (head=head@entry=0xffffc90000063c28, dev=dev@entry=0xffff88800673b000, net=net@entry=0xffffffff836a70c0 <init_net>) at /src/net/ipv4/ip_input.c:608
#7  0xffffffff81d6bc05 in ip_list_rcv (head=0xffffc90000063ca0, pt=<optimized out>, orig_dev=<optimized out>) at /src/net/ipv4/ip_input.c:643
#8  0xffffffff81c01e39 in __netif_receive_skb_list_ptype (orig_dev=0xffff88800673b000, pt_prev=0xffffffff83744fe0 <ip_packet_type>, head=0xffffc90000063ca0) at /src/net/core/dev.c:5399
#9  __netif_receive_skb_list_core (head=head@entry=0xffff888006734908, pfmemalloc=pfmemalloc@entry=false) at /src/net/core/dev.c:5447
#10 0xffffffff81c0203e in __netif_receive_skb_list (head=0xffff888006734908) at /src/net/core/dev.c:5499
#11 netif_receive_skb_list_internal (head=head@entry=0xffff888006734908) at /src/net/core/dev.c:5609
#12 0xffffffff81c0301f in gro_normal_list (napi=0xffff888006734808) at /src/net/core/dev.c:5763
#13 gro_normal_list (napi=0xffff888006734808) at /src/net/core/dev.c:5759
#14 napi_complete_done (n=n@entry=0xffff888006734808, work_done=work_done@entry=1) at /src/net/core/dev.c:6511
#15 0xffffffff81a1b520 in virtqueue_napi_complete (processed=1, vq=0xffff88800672f700, napi=0xffff888006734808) at /src/drivers/net/virtio_net.c:337
#16 virtnet_poll (napi=0xffff888006734808, budget=64) at /src/drivers/net/virtio_net.c:1503
#17 0xffffffff81c0323c in napi_poll (repoll=0xffffc90000063e48, n=0xffff888006734808) at /src/net/core/dev.c:6827
#18 net_rx_action (h=<optimized out>) at /src/net/core/dev.c:6897
#19 0xffffffff822000d2 in __do_softirq () at /src/kernel/softirq.c:298
#20 0xffffffff8116a696 in run_ksoftirqd (cpu=<optimized out>) at /src/kernel/softirq.c:653
#21 run_ksoftirqd (cpu=<optimized out>) at /src/kernel/softirq.c:645
#22 0xffffffff8118f405 in smpboot_thread_fn (data=0xffff888004a83c00) at /src/kernel/smpboot.c:164
#23 0xffffffff81188a4b in kthread (_create=0xffff888004a83a00) at /src/kernel/kthread.c:313
#24 0xffffffff81004492 in ret_from_fork () at /src/arch/x86/entry/entry_64.S:296
#25 0x0000000000000000 in ?? ()
```

```
#0  rt_dst_alloc (dev=dev@entry=0xffff88800673b000, flags=flags@entry=0, type=1, nopolicy=false, noxfrm=false) at /src/net/ipv4/route.c:1656
#1  0xffffffff81d688e1 in __mkroute_output (flags=<optimized out>, dev_out=0xffff88800673b000, orig_oif=0, fl4=0xffffc90000063a20, res=0xffffc900000639b0) at /src/net/ipv4/route.c:2487
#2  ip_route_output_key_hash_rcu (net=net@entry=0xffffffff836a70c0 <init_net>, fl4=fl4@entry=0xffffc90000063a20, res=res@entry=0xffffc900000639b0, skb=skb@entry=0x0 <fixed_percpu_data>) at /src/net/ipv4/route.c:2714
#3  0xffffffff81d69d49 in ip_route_output_key_hash (skb=0x0 <fixed_percpu_data>, fl4=<optimized out>, net=0xffffffff836a70c0 <init_net>) at /src/net/ipv4/route.c:2542
#4  __ip_route_output_key (flp=<optimized out>, net=0xffffffff836a70c0 <init_net>) at /src/include/net/route.h:126
#5  ip_route_output_flow (net=0xffffffff836a70c0 <init_net>, flp4=0xffffc90000063a20, sk=0xffff88800d9bdf80) at /src/net/ipv4/route.c:2774
#6  0xffffffff81d6a034 in ipv4_sk_update_pmtu (skb=skb@entry=0xffff888008a37d00, sk=sk@entry=0xffff88800d9bdf80, mtu=mtu@entry=1200) at /src/include/net/net_namespace.h:337
#7  0xffffffff81da82d5 in __udp4_lib_err (skb=0xffff888008a37d00, info=1200, udptable=0xffffffff83744ed0 <udp_table>) at /src/net/ipv4/udp.c:741
#8  0xffffffff81dad6f6 in icmp_unreach (skb=0xffff888008a37d00) at /src/net/ipv4/icmp.c:950
#9  0xffffffff81dae5b5 in icmp_rcv (skb=0xffff888008a37d00) at /src/net/ipv4/icmp.c:1132
#10 0xffffffff81d6b876 in ip_protocol_deliver_rcu (net=0xffffffff836a70c0 <init_net>, skb=0xffff888008a37d00, protocol=<optimized out>) at /src/net/ipv4/ip_input.c:204
#11 0xffffffff81d6b8c4 in ip_local_deliver_finish (net=<optimized out>, sk=<optimized out>, skb=<optimized out>) at /src/net/ipv4/ip_input.c:231
#12 0xffffffff81d6b0d7 in dst_input (skb=<optimized out>) at /src/include/net/dst.h:449
#13 ip_sublist_rcv_finish (head=head@entry=0xffffc90000063ba8) at /src/net/ipv4/ip_input.c:550
#14 0xffffffff81d6b589 in ip_list_rcv_finish (sk=0x0 <fixed_percpu_data>, head=0xffffc90000063c28, net=0xffffffff836a70c0 <init_net>) at /src/net/ipv4/ip_input.c:600
#15 ip_sublist_rcv (head=head@entry=0xffffc90000063c28, dev=dev@entry=0xffff88800673b000, net=net@entry=0xffffffff836a70c0 <init_net>) at /src/net/ipv4/ip_input.c:608
#16 0xffffffff81d6bc05 in ip_list_rcv (head=0xffffc90000063ca0, pt=<optimized out>, orig_dev=<optimized out>) at /src/net/ipv4/ip_input.c:643
#17 0xffffffff81c01e39 in __netif_receive_skb_list_ptype (orig_dev=0xffff88800673b000, pt_prev=0xffffffff83744fe0 <ip_packet_type>, head=0xffffc90000063ca0) at /src/net/core/dev.c:5399
#18 __netif_receive_skb_list_core (head=head@entry=0xffff888006734908, pfmemalloc=pfmemalloc@entry=false) at /src/net/core/dev.c:5447
#19 0xffffffff81c0203e in __netif_receive_skb_list (head=0xffff888006734908) at /src/net/core/dev.c:5499
#20 netif_receive_skb_list_internal (head=head@entry=0xffff888006734908) at /src/net/core/dev.c:5609
#21 0xffffffff81c0301f in gro_normal_list (napi=0xffff888006734808) at /src/net/core/dev.c:5763
#22 gro_normal_list (napi=0xffff888006734808) at /src/net/core/dev.c:5759
#23 napi_complete_done (n=n@entry=0xffff888006734808, work_done=work_done@entry=1) at /src/net/core/dev.c:6511
#24 0xffffffff81a1b520 in virtqueue_napi_complete (processed=1, vq=0xffff88800672f700, napi=0xffff888006734808) at /src/drivers/net/virtio_net.c:337
#25 virtnet_poll (napi=0xffff888006734808, budget=64) at /src/drivers/net/virtio_net.c:1503
#26 0xffffffff81c0323c in napi_poll (repoll=0xffffc90000063e48, n=0xffff888006734808) at /src/net/core/dev.c:6827
#27 net_rx_action (h=<optimized out>) at /src/net/core/dev.c:6897
#28 0xffffffff822000d2 in __do_softirq () at /src/kernel/softirq.c:298
#29 0xffffffff8116a696 in run_ksoftirqd (cpu=<optimized out>) at /src/kernel/softirq.c:653
#30 run_ksoftirqd (cpu=<optimized out>) at /src/kernel/softirq.c:645
#31 0xffffffff8118f405 in smpboot_thread_fn (data=0xffff888004a83c00) at /src/kernel/smpboot.c:164
#32 0xffffffff81188a4b in kthread (_create=0xffff888004a83a00) at /src/kernel/kthread.c:313
#33 0xffffffff81004492 in ret_from_fork () at /src/arch/x86/entry/entry_64.S:296
#34 0x0000000000000000 in ?? ()
```
