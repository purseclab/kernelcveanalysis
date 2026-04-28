#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int16_t  s16;
typedef int32_t  s32;
typedef uint32_t __be32;
typedef uint64_t __be64;

#define RTAX_MAX 17

/* Opaque pointer targets: layout does not depend on their definitions. */
struct net_device;
struct dst_ops;
struct xfrm_state;
struct sk_buff;
struct net;
struct sock;
struct lwtunnel_state;
struct fib6_info;
struct inet6_dev;
struct uncached_list;

/* Minimal kernel-layout helpers */
typedef struct {
    int counter;
} atomic_t;

typedef struct {
    atomic_t refs;
} refcount_t;

struct rcu_head {
    struct rcu_head *next;
    void (*func)(struct rcu_head *head);
};

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

struct hlist_node {
    struct hlist_node *next;
    struct hlist_node **pprev;
};

struct hlist_head {
    struct hlist_node *first;
};

struct in6_addr {
    union {
        u8  u6_addr8[16];
        u16 u6_addr16[8];
        u32 u6_addr32[4];
    } in6_u;
};

struct dst_metrics {
    u32 metrics[RTAX_MAX];
    refcount_t refcnt;
};

/*
* This matches include/net/dst.h for:
*   CONFIG_64BIT=y
*   CONFIG_XFRM=y
*/
struct dst_entry {
    struct net_device *dev;
    struct dst_ops *ops;
    unsigned long _metrics;
    unsigned long expires;
    struct xfrm_state *xfrm;

    int (*input)(struct sk_buff *);
    int (*output)(struct net *net, struct sock *sk, struct sk_buff *skb);

    unsigned short flags;
    short obsolete;
    unsigned short header_len;
    unsigned short trailer_len;

    atomic_t __refcnt;   /* 64-bit builds place this here */
    int __use;
    unsigned long lastuse;
    struct lwtunnel_state *lwtstate;
    struct rcu_head rcu_head;
    short error;
    short __pad;
    u32 tclassid;
};

struct rt6key {
    struct in6_addr addr;
    int plen;
};

struct rt6_exception_bucket {
    struct hlist_head chain;
    int depth;
};

struct rt6_exception {
    struct hlist_node hlist;
    struct rt6_info *rt6i;
    unsigned long stamp;
    struct rcu_head rcu;
};

struct rt6_info {
    struct dst_entry dst;
    struct fib6_info *from;
    int sernum;

    struct rt6key rt6i_dst;
    struct rt6key rt6i_src;
    struct in6_addr rt6i_gateway;
    struct inet6_dev *rt6i_idev;
    u32 rt6i_flags;

    struct list_head rt6i_uncached;
    struct uncached_list *rt6i_uncached_list;

    unsigned short rt6i_nfheader_len;
};
