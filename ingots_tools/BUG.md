Can you determine a pathway to use the following bug to obtain root? Do not write the code, just write a summary in a file.

net: fix __dst_negative_advice() race
commit 92f1655aa2b2294d0b49925f3b875a634bd3b59e upstream.

__dst_negative_advice() does not enforce proper RCU rules when
sk->dst_cache must be cleared, leading to possible UAF.

RCU rules are that we must first clear sk->sk_dst_cache,
then call dst_release(old_dst).

Note that sk_dst_reset(sk) is implementing this protocol correctly,
while __dst_negative_advice() uses the wrong order.

Given that ip6_negative_advice() has special logic
against RTF_CACHE, this means each of the three ->negative_advice()
existing methods must perform the sk_dst_reset() themselves.

Note the check against NULL dst is centralized in
__dst_negative_advice(), there is no need to duplicate
it in various callbacks.

Many thanks to Clement Lecigne for tracking this issue.

This old bug became visible after the blamed commit, using UDP sockets.

Fixes: a87cb3e48ee8 ("net: Facility to report route quality of connected sockets")
Reported-by: Clement Lecigne <clecigne@google.com>
Diagnosed-by: Clement Lecigne <clecigne@google.com>
Signed-off-by: Eric Dumazet <edumazet@google.com>
Cc: Tom Herbert <tom@herbertland.com>
Reviewed-by: David Ahern <dsahern@kernel.org>
Link: https://lore.kernel.org/r/20240528114353.1794151-1-edumazet@google.com
Signed-off-by: Jakub Kicinski <kuba@kernel.org>
[Lee: Stable backport]
Signed-off-by: Lee Jones <lee@kernel.org>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Diffstat
-rw-r--r--	include/net/dst_ops.h	2	
		
-rw-r--r--	include/net/sock.h	13	
		
-rw-r--r--	net/ipv4/route.c	22	
		
-rw-r--r--	net/ipv6/route.c	29	
		
-rw-r--r--	net/xfrm/xfrm_policy.c	11	
		
5 files changed, 30 insertions, 47 deletions
diff --git a/include/net/dst_ops.h b/include/net/dst_ops.h
index 632086b2f644a9..3ae2fda2950738 100644
--- a/include/net/dst_ops.h
+++ b/include/net/dst_ops.h
@@ -24,7 +24,7 @@ struct dst_ops {
 	void			(*destroy)(struct dst_entry *);
 	void			(*ifdown)(struct dst_entry *,
 					  struct net_device *dev, int how);
-	struct dst_entry *	(*negative_advice)(struct dst_entry *);
+	void			(*negative_advice)(struct sock *sk, struct dst_entry *);
 	void			(*link_failure)(struct sk_buff *);
 	void			(*update_pmtu)(struct dst_entry *dst, struct sock *sk,
 					       struct sk_buff *skb, u32 mtu,
diff --git a/include/net/sock.h b/include/net/sock.h
index b5a929a4bc74de..6304e287087ffa 100644
--- a/include/net/sock.h
+++ b/include/net/sock.h
@@ -1915,19 +1915,12 @@ sk_dst_get(struct sock *sk)
 
 static inline void dst_negative_advice(struct sock *sk)
 {
-	struct dst_entry *ndst, *dst = __sk_dst_get(sk);
+	struct dst_entry *dst = __sk_dst_get(sk);
 
 	sk_rethink_txhash(sk);
 
-	if (dst && dst->ops->negative_advice) {
-		ndst = dst->ops->negative_advice(dst);
-
-		if (ndst != dst) {
-			rcu_assign_pointer(sk->sk_dst_cache, ndst);
-			sk_tx_queue_clear(sk);
-			WRITE_ONCE(sk->sk_dst_pending_confirm, 0);
-		}
-	}
+	if (dst && dst->ops->negative_advice)
+		dst->ops->negative_advice(sk, dst);
 }
 
 static inline void
diff --git a/net/ipv4/route.c b/net/ipv4/route.c
index 3014605105350a..3c5401dafdeed9 100644
--- a/net/ipv4/route.c
+++ b/net/ipv4/route.c
@@ -140,7 +140,8 @@ static int ip_rt_gc_timeout __read_mostly	= RT_GC_TIMEOUT;
 static struct dst_entry *ipv4_dst_check(struct dst_entry *dst, u32 cookie);
 static unsigned int	 ipv4_default_advmss(const struct dst_entry *dst);
 static unsigned int	 ipv4_mtu(const struct dst_entry *dst);
-static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst);
+static void		ipv4_negative_advice(struct sock *sk,
+					     struct dst_entry *dst);
 static void		 ipv4_link_failure(struct sk_buff *skb);
 static void		 ip_rt_update_pmtu(struct dst_entry *dst, struct sock *sk,
 					   struct sk_buff *skb, u32 mtu,
@@ -848,22 +849,15 @@ static void ip_do_redirect(struct dst_entry *dst, struct sock *sk, struct sk_buf
 	__ip_do_redirect(rt, skb, &fl4, true);
 }
 
-static struct dst_entry *ipv4_negative_advice(struct dst_entry *dst)
+static void ipv4_negative_advice(struct sock *sk,
+				 struct dst_entry *dst)
 {
 	struct rtable *rt = (struct rtable *)dst;
-	struct dst_entry *ret = dst;
 
-	if (rt) {
-		if (dst->obsolete > 0) {
-			ip_rt_put(rt);
-			ret = NULL;
-		} else if ((rt->rt_flags & RTCF_REDIRECTED) ||
-			   rt->dst.expires) {
-			ip_rt_put(rt);
-			ret = NULL;
-		}
-	}
-	return ret;
+	if ((dst->obsolete > 0) ||
+	    (rt->rt_flags & RTCF_REDIRECTED) ||
+	    rt->dst.expires)
+		sk_dst_reset(sk);
 }
 
 /*
diff --git a/net/ipv6/route.c b/net/ipv6/route.c
index b4d9acb1bc1019..db349679b11273 100644
--- a/net/ipv6/route.c
+++ b/net/ipv6/route.c
@@ -88,7 +88,8 @@ enum rt6_nud_state {
 static struct dst_entry	*ip6_dst_check(struct dst_entry *dst, u32 cookie);
 static unsigned int	 ip6_default_advmss(const struct dst_entry *dst);
 static unsigned int	 ip6_mtu(const struct dst_entry *dst);
-static struct dst_entry *ip6_negative_advice(struct dst_entry *);
+static void		ip6_negative_advice(struct sock *sk,
+					    struct dst_entry *dst);
 static void		ip6_dst_destroy(struct dst_entry *);
 static void		ip6_dst_ifdown(struct dst_entry *,
 				       struct net_device *dev, int how);
@@ -2281,24 +2282,24 @@ static struct dst_entry *ip6_dst_check(struct dst_entry *dst, u32 cookie)
 	return dst_ret;
 }
 
-static struct dst_entry *ip6_negative_advice(struct dst_entry *dst)
+static void ip6_negative_advice(struct sock *sk,
+				struct dst_entry *dst)
 {
 	struct rt6_info *rt = (struct rt6_info *) dst;
 
-	if (rt) {
-		if (rt->rt6i_flags & RTF_CACHE) {
-			rcu_read_lock();
-			if (rt6_check_expired(rt)) {
-				rt6_remove_exception_rt(rt);
-				dst = NULL;
-			}
-			rcu_read_unlock();
-		} else {
-			dst_release(dst);
-			dst = NULL;
+	if (rt->rt6i_flags & RTF_CACHE) {
+		rcu_read_lock();
+		if (rt6_check_expired(rt)) {
+			/* counteract the dst_release() in sk_dst_reset() */
+			dst_hold(dst);
+			sk_dst_reset(sk);
+
+			rt6_remove_exception_rt(rt);
 		}
+		rcu_read_unlock();
+		return;
 	}
-	return dst;
+	sk_dst_reset(sk);
 }
 
 static void ip6_link_failure(struct sk_buff *skb)
diff --git a/net/xfrm/xfrm_policy.c b/net/xfrm/xfrm_policy.c
index c8a7a573942505..fb76a2ee8873a1 100644
--- a/net/xfrm/xfrm_policy.c
+++ b/net/xfrm/xfrm_policy.c
@@ -2556,15 +2556,10 @@ static void xfrm_link_failure(struct sk_buff *skb)
 	/* Impossible. Such dst must be popped before reaches point of failure. */
 }
 
-static struct dst_entry *xfrm_negative_advice(struct dst_entry *dst)
+static void xfrm_negative_advice(struct sock *sk, struct dst_entry *dst)
 {
-	if (dst) {
-		if (dst->obsolete) {
-			dst_release(dst);
-			dst = NULL;
-		}
-	}
-	return dst;
+	if (dst->obsolete)
+		sk_dst_reset(sk);
 }
 
 static void xfrm_init_pmtu(struct xfrm_dst **bundle, int nr)


 # Current Notes

 patch / description of bug: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=051c0bde9f0450a2ec3d62a86d2a0d2fad117f13
# Exploit Plan

### Triggering Bug
- setup UDP ipv6 socket, and connect
- spam `setsockopt(fd, SOL_SOCKET, SO_CNX_ADVICE, &one, sizeof(one))` calls
	- will free dst_cache if RTF_CACHE flag is not set, which is typically the case it seems
	- will free in a call_rcu callback
	- have to use a trick similar to [[Android CVE-2022-22057]] to preempt thread to stop after call_rcu but before set null pointer
- After spamming setsockopt calls, should win race eventually?

### sk_dst_cache field usage

- `include/net/sock.h`
	- `__sk_dst_get` and `sk_dst_get`  functions
	- vulnerable function
	- `__sk_dst_set` and `sk_dst_set`
		- both free old pointer after setting the field to a new pointer
- `net/core/dev.c`
	- `netdev_pick_tx` just checks if `sk_dst_cache` field is not null, then does some queue index set
- `net/core/sock.c`
	- `__sk_dst_check` only directly sets pointer to null, but operates on value returned by get, and frees it if some condition is met
	- `sk_clone_lock` initialized it to null
- `net/ipv4/af_inet.c`
	- `sk_dst_cache` is released, using usual rcu path
- Several other obsolete drivers use it

Possible leak values:
ipv6 getsockopt with `IPV6_MULTICAST_HOPS` just reads from some offset. reads signed 32 bit. Issue is if its negative, will return diff value.
get MTU options also return something related to dst, but they are using function pointer, may be more tempermantal

assuming vtable pointer and lwtunnel pointer still intact, mtu can leak some bytes, but is clamped to be less than a 2 byte value
possible arb read as well with ptr deref, but with 2 byte limit to read, a bit annoying to get working, also just tempermental in general

the metrics for an ipv6 socket may be private, and this struct is 18 u32 fields, plus int refcount, so (19 * 4) = 76 bytes
it is read out by earlier sock get opt functions

### Exploiting Bug
ipv4 and ipv6 are in their own cache (`ip_dst_cache` and `ip6_dst_cache`), exploitation a bit harder
even this xfrm thing has its own `xfrm_dst_cache`, these are the only 3 handlers patched in bug fix
`ip6_dst_cache` details:
- size: 0xf0 bytes
- flags: `SLAB_HWCACHE_ALIGN`: align objects on cache lines
- created with call: `kmem_cache_create_usercopy(s_ip6_dst_cache_ffffffc011f84f20,0xf0,0,0x2000,0,0,0)`

maybe cross cache attack to kmalloc-256 spray with sendmsg
- problem: don't know when race condition succeeds, double free very difficult
- also a mutex is held on the socket, non viable

main UAF path: UDP sendmsg fast path does not acquire lock, uses only RCU

# Codex Summary Of Bug:

## Summary

This `v5.10.107` source tree appears vulnerable to the bug described in `BUG.md`.

The core issue is that `__dst_negative_advice()` uses the wrong lifetime order for
`sk->sk_dst_cache`: it invokes the route-specific `negative_advice()` callback
first, and only updates `sk_dst_cache` afterward.

In this tree:

- `negative_advice` still returns a `struct dst_entry *` in
  `include/net/dst_ops.h`
- `__dst_negative_advice()` still does:
  1. `ndst = dst->ops->negative_advice(dst);`
  2. `rcu_assign_pointer(sk->sk_dst_cache, ndst);`

The safe pattern already exists elsewhere in the tree via `sk_dst_set()` /
`__sk_dst_set()`, which first replaces or clears the socket's cached dst and only
then calls `dst_release(old_dst)`.

## Vulnerable Code Paths

### Core bug

- `include/net/sock.h:1938`
  - `__dst_negative_advice()` reads `sk->sk_dst_cache`
  - calls `dst->ops->negative_advice(dst)`
  - only afterward updates `sk->sk_dst_cache`

- `include/net/sock.h:1960`
  - `__sk_dst_set()` shows the correct protocol:
  - clear/replace `sk->sk_dst_cache`
  - then `dst_release(old_dst)`

### Direct userspace trigger

- `net/core/sock.c:1194`
  - `setsockopt(..., SOL_SOCKET, SO_CNX_ADVICE, ...)`
  - `val == 1` calls `dst_negative_advice(sk)`

This is the most important syscall surface because it gives userspace a direct
way to ask the kernel to run the buggy logic.

### Route-specific callbacks

- `net/ipv6/route.c:2638`
  - `ip6_negative_advice()` drops non-`RTF_CACHE` routes unconditionally
  - this makes IPv6 particularly reachable

- `net/ipv4/route.c:859`
  - `ipv4_negative_advice()` only drops the route if it is obsolete,
    redirected, or expired
  - IPv4 is therefore narrower than IPv6

- `net/xfrm/xfrm_policy.c`
  - `xfrm_negative_advice()` also drops obsolete dst entries

### Non-setsockopt paths

- `net/ipv4/tcp_timer.c:241`
  - TCP retransmission timeout path calls `__dst_negative_advice(sk)`

- `net/dccp/timer.c:38`
  - DCCP timeout path calls `dst_negative_advice(sk)`

So even if `SO_CNX_ADVICE` is unavailable, TCP and DCCP can still reach the same
bug internally.

## Exploitability Assessment

## Overall judgment

The bug is plausibly exploitable as a local unprivileged kernel memory corruption
or kernel DoS issue. A reliable privilege-escalation exploit is not obvious from
static review alone, but it cannot be ruled out.

## Why it is reachable

- Connected sockets cache a route in `sk->sk_dst_cache`
- `SO_CNX_ADVICE` allows userspace to force `dst_negative_advice()`
- Concurrent users of the same socket can race with that path
- Upstream explicitly noted that the old bug became visible with UDP sockets

The most plausible local case is a connected IPv6 UDP socket shared by multiple
threads:

1. One thread repeatedly calls `setsockopt(SOL_SOCKET, SO_CNX_ADVICE, 1)`
2. Another thread concurrently uses the socket, such as `sendmsg()` /
   `sendmmsg()`

IPv6 is the most concerning protocol family in this tree because
`ip6_negative_advice()` drops non-`RTF_CACHE` routes directly.

## Why exploitation is not obviously trivial

- `dst_release()` frees via RCU in `net/core/dst.c:169`
  - that reduces the race to an RCU lifetime bug rather than an immediate free

- Route objects use dedicated slabs
  - IPv4: `ip_dst_cache` in `net/ipv4/route.c:3614`
  - IPv6: `ip6_dst_cache` in `net/ipv6/route.c:6515`
  - this limits attacker-controlled cross-cache heap shaping compared with a
    generic `kmalloc` UAF

These two properties make the bug harder to weaponize into a strong arbitrary
write or fully controlled object replacement. They do not make it safe.

## Likely impact

Most likely outcomes:

- kernel crash
- KASAN/UAF splat
- route-cache corruption
- potentially exploitable memory corruption under favorable heap conditions

## Practical Trigger Scenarios

### Most plausible local trigger

- `socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)`
- `connect()`
- two-thread race:
  - thread A: repeated `setsockopt(SOL_SOCKET, SO_CNX_ADVICE, 1)`
  - thread B: repeated `sendmsg()` / `sendmmsg()`

### Other plausible paths

- Connected TCP socket under retransmission timeout conditions
- DCCP timeout path if DCCP is enabled

### Less convincing from static review

- Pure remote trigger without local code execution

Remote influence may help make route state enter a releasable condition, but the
cleanest trigger in this tree is still local syscall access.

## Trigger Callpath

setsockopt() reaches the bug through this path:  
  
 1. User syscall entry  
  
 - SYSCALL_DEFINE5(setsockopt, ...) in net/socket.c:2131  
 - calls __sys_setsockopt(...)  
  
 2. Generic socket syscall handler  
  
 - __sys_setsockopt() in net/socket.c:2084  
 - resolves the struct socket *  
 - for level == SOL_SOCKET, calls sock_setsockopt(...)  
  
 3. SOL_SOCKET option dispatcher  
  
 - sock_setsockopt() in net/core/sock.c:831  
 - takes lock_sock(sk)  
 - in the switch, case SO_CNX_ADVICE: at net/core/sock.c:1194  
 - if val == 1, calls dst_negative_advice(sk)  
  
 4. Socket dst advice wrapper  
  
 - dst_negative_advice() in include/net/sock.h:1953  
 - does sk_rethink_txhash(sk)  
 - then calls __dst_negative_advice(sk)  
  
 5. Vulnerable function  
  
 - __dst_negative_advice() in include/net/sock.h:1938  
 - loads dst = __sk_dst_get(sk)  
 - calls ndst = dst->ops->negative_advice(dst)  
 - only afterward updates sk->sk_dst_cache  
  
 Why this is wrong:  
  
 - the route callback can drop the last reference to dst  
 - but sk->sk_dst_cache still points at that old dst until after the callback returns  
 - that violates the safe order used by sk_dst_set() in include/net/sock.h:1973, which swaps/clears the cached pointer first and only then calls dst_release(old_dst)  
  
 In short:  
  
 setsockopt syscall  
 -> __sys_setsockopt()  
 -> sock_setsockopt()  
 -> SO_CNX_ADVICE case  
 -> dst_negative_advice(sk)  
 -> __dst_negative_advice(sk)   <-- vulnerable  
 -> dst->ops->negative_advice(dst)

