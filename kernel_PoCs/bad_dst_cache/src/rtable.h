#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int16_t  s16;
typedef int32_t  s32;
typedef uint32_t __be32;
// typedef uint64_t __be64;

#define CONFIG_IPV6

#define RTAX_MAX 17

struct net_device;
struct dst_ops;
struct xfrm_state;
struct sk_buff;
struct net;
struct sock;
struct lwtunnel_state;
struct neighbour;
struct uncached_list;
struct in_device;

/* Kernel-layout helper mirrors */
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

struct dst_metrics {
    u32 metrics[RTAX_MAX];
    refcount_t refcnt;
};

/*
* Matches include/net/dst.h for:
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

    atomic_t __refcnt;
    int __use;
    unsigned long lastuse;
    struct lwtunnel_state *lwtstate;
    struct rcu_head rcu_head;
    short error;
    short __pad;
    u32 tclassid;
};

/*
* Matches include/net/route.h for 5.10.y
*/
struct rtable {
    struct dst_entry dst;

    int rt_genid;
    unsigned int rt_flags;
    __u16 rt_type;
    __u8 rt_is_input;
    __u8 rt_uses_gateway;

    int rt_iif;

    u8 rt_gw_family;
    u8 rt_pmtu;
    u8 rt_mtu_locked;
    u8 rt_protocol;

    struct list_head rt_uncached;
    struct uncached_list *rt_uncached_list;

    struct in_device *idev;
    struct neighbour *rt_gw4_neigh;
    __be32 rt_gw4;

#ifdef CONFIG_IPV6
    struct neighbour *rt_gw6_neigh;
    struct in6_addr rt_gw6;
#endif
};

enum metadata_type {
    METADATA_IP_TUNNEL,
    METADATA_HW_PORT_MUX,
};

struct metadata_dst {
    struct dst_entry dst;
    // path to kfree checks this isn't METADATA_IP_TUNNEL
    enum metadata_type type;
};
