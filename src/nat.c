#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_eal.h>
#include <rte_errno.h> 

#include "nat.h"
#include "debug.h"

static inline int ip_in_net(uint32_t ip_be, uint32_t net_be, uint32_t mask_be)
{
    return (ip_be & mask_be) == (net_be & mask_be);
}

static uint16_t snat_next_port = SNAT_PORT_MIN;

static inline uint16_t nat_alloc_snat_port(void)
{
    uint16_t p = snat_next_port;

    snat_next_port++;
    if (snat_next_port > SNAT_PORT_MAX)
        snat_next_port = SNAT_PORT_MIN;

    return p;
}

static inline int nat_key_equal(const struct nat_entry_key *a,
                                const struct nat_entry_key *b)
{
    return a->src_ip    == b->src_ip   &&
           a->dst_ip    == b->dst_ip   &&
           a->src_port  == b->src_port &&
           a->dst_port  == b->dst_port &&
           a->proto     == b->proto    &&
           a->direction == b->direction;
}

void nat_table_init(struct nat_table *t)
{
    memset(t, 0, sizeof(*t));

    int socket_id = rte_socket_id();

    struct rte_hash_parameters fwd_params = {
        .name               = "nat_fwd",
        .entries            = NAT_HASH_ENTRIES,
        .reserved           = 0,
        .key_len            = sizeof(struct nat_entry_key),
        .hash_func          = rte_hash_crc,
        .hash_func_init_val = 0,
        .socket_id          = socket_id,
        .extra_flag         = 0
    };

    t->hash_fwd = rte_hash_create(&fwd_params);
    if (!t->hash_fwd) {
        int err = rte_errno;
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER3,
                "nat: rte_hash_create(fwd) failed: %d (%s)\n",
                err, rte_strerror(err));
        return -1;
    }

    struct rte_hash_parameters rev_params = fwd_params;
    rev_params.name = "nat_rev";

    t->hash_rev = rte_hash_create(&rev_params);
    if (!t->hash_rev) {
        rte_exit(EXIT_FAILURE, "[nat] failed to create hash_rev\n");
    }
}

void nat_table_destroy(struct nat_table *t)
{
    if (!t)
        return;

    if (t->hash_fwd) {
        rte_hash_free(t->hash_fwd);
        t->hash_fwd = NULL;
    }
    if (t->hash_rev) {
        rte_hash_free(t->hash_rev);
        t->hash_rev = NULL;
    }

    t->count = 0;
}

static struct nat_entry *nat_lookup(struct nat_table *t,
                                    const struct nat_entry_key *key)
{
    if (!t)
        return NULL;

    void *data = NULL;
    int ret;

    if (key->direction == 0) {
        if (!t->hash_fwd)
            return NULL;
        ret = rte_hash_lookup_data(t->hash_fwd, key, &data);
    } else {
        if (!t->hash_rev)
            return NULL;
        ret = rte_hash_lookup_data(t->hash_rev, key, &data);
    }

    if (ret < 0)
        return NULL;

    return (struct nat_entry *)data;
}

static struct nat_entry *nat_insert(struct nat_table *t,
                                    const struct nat_entry_key *orig,
                                    const struct nat_entry_key *reply,
                                    int hairpin)
{
    if (t->count >= NAT_TABLE_SIZE)
        return NULL;

    struct nat_entry *e = &t->entries[t->count++];

    e->orig      = *orig;
    e->reply     = *reply;
    e->hairpin   = hairpin ? 1 : 0;
    e->last_seen = time(NULL);

    int ret = rte_hash_add_key_data(t->hash_fwd, &e->orig, e);
    if (ret < 0) {
        DBG("[nat] rte_hash_add_key_data(fwd) failed: %d\n", ret);
        t->count--;
        return NULL;
    }

    ret = rte_hash_add_key_data(t->hash_rev, &e->reply, e);
    if (ret < 0) {
        DBG("[nat] rte_hash_add_key_data(rev) failed: %d\n", ret);
        rte_hash_del_key(t->hash_fwd, &e->orig);
        t->count--;
        return NULL;
    }

    DBG("[snat] Connection recorded\n");
    return e;
}

static const struct dnat_rule *
nat_find_dnat_rule(const struct nat_config *cfg,
                   uint32_t dst_ip_be,
                   uint16_t dst_port_be,
                   uint8_t proto)
{
    for (int i = 0; i < cfg->dnat_count; i++) {
        const struct dnat_rule *rule = &cfg->dnat[i];

        if (rule->ext_ip != dst_ip_be)
            continue;
        if (rule->ext_port && rule->ext_port != ntohs(dst_port_be))
            continue;
        if (rule->proto && rule->proto != proto)
            continue;

        return rule;
    }
    return NULL;
}

int nat_process_lan_outbound(const struct app_config *cfg,
                             struct nat_table *table,
                             struct rte_ipv4_hdr *ip,
                             struct rte_mbuf *m)
{
    struct l4_tuple l4;
    void *l4_hdr;
    int proto = parse_l4_tuple(ip, &l4, &l4_hdr);
    if (proto < 0)
        return 0;

    uint32_t src = ip->src_addr;
    uint32_t dst = ip->dst_addr;

    uint16_t src_port_be = l4.src_port;
    uint16_t dst_port_be = l4.dst_port;
    uint16_t src_port    = ntohs(src_port_be);
    uint16_t dst_port    = ntohs(dst_port_be);

    struct nat_entry_key key = {
        .src_ip    = src,
        .dst_ip    = dst,
        .src_port  = src_port,
        .dst_port  = dst_port,
        .proto     = proto,
        .direction = 0
    };
    struct nat_entry *e = nat_lookup(table, &key);
    if (e) {
        uint32_t new_src   = e->reply.dst_ip;
        uint32_t new_dst   = e->orig.dst_ip;
        uint16_t new_sport = e->reply.dst_port;
        uint16_t new_dport = e->orig.dst_port;

        ip->src_addr = new_src;
        ip->dst_addr = new_dst;

        if (proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            tcp->src_port = htons(new_sport);
            tcp->dst_port = htons(new_dport);
            tcp->cksum = 0;
        } else if (proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            udp->src_port    = htons(new_sport);
            udp->dst_port    = htons(new_dport);
            udp->dgram_cksum = 0;
        } else if (proto == IPPROTO_ICMP) {
            struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4_hdr;
            icmp->icmp_ident = htons(new_sport);
            icmp->icmp_cksum = 0;
        }

        m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
        if (proto == IPPROTO_UDP)
            m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        else if (proto == IPPROTO_TCP)
            m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = sizeof(struct rte_ipv4_hdr);

        return 1;
    }

    if (ip_in_net(dst, cfg->lan_net, cfg->lan_mask))
        return 0;

    const struct dnat_rule *dr =
        nat_find_dnat_rule(&cfg->nat, dst, dst_port_be, proto);

    int      hairpin = 0;
    uint32_t new_src, new_dst;
    uint16_t new_sport, new_dport;

    if (proto == IPPROTO_ICMP) {
        new_src   = cfg->wan.ip_addr;
        new_dst   = dst;
        new_sport = src_port;
        new_dport = dst_port;
    } else if (dr &&
               ip_in_net(dr->int_ip, cfg->lan_net, cfg->lan_mask) &&
               cfg->nat.hairpin)
    {
        hairpin   = 1;
        new_dst   = dr->int_ip;
        new_dport = dr->int_port ? dr->int_port : dst_port;

        new_src   = cfg->lan.ip_addr;
        new_sport = src_port;
    } else {
        new_dst   = dst;
        new_dport = dst_port;
        new_src   = cfg->wan.ip_addr;
        new_sport = nat_alloc_snat_port();
    }

    struct nat_entry_key orig = {
        .src_ip    = src,
        .dst_ip    = dst,
        .src_port  = src_port,
        .dst_port  = dst_port,
        .proto     = proto,
        .direction = 0
    };

    struct nat_entry_key reply2 = {
        .src_ip    = new_dst,
        .dst_ip    = new_src,
        .src_port  = new_dport,
        .dst_port  = new_sport,
        .proto     = proto,
        .direction = 1
    };

    struct nat_entry *e2 = nat_insert(table, &orig, &reply2, hairpin);
    if (!e2)
        return 0;

    ip->src_addr = new_src;
    ip->dst_addr = new_dst;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
        tcp->src_port = htons(new_sport);
        tcp->dst_port = htons(new_dport);
        tcp->cksum = 0;
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
        udp->src_port    = htons(new_sport);
        udp->dst_port    = htons(new_dport);
        udp->dgram_cksum = 0;
    }

    m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    if (proto == IPPROTO_UDP)
        m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
    else if (proto == IPPROTO_TCP)
        m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);

    return 1;
}

int nat_process_wan_inbound(const struct app_config *cfg,
                            struct nat_table *table,
                            struct rte_ipv4_hdr *ip,
                            struct rte_mbuf *m)
{
    struct l4_tuple l4;
    void *l4_hdr;
    int proto = parse_l4_tuple(ip, &l4, &l4_hdr);
    if (proto < 0)
        return 0;

    uint32_t src = ip->src_addr;
    uint32_t dst = ip->dst_addr;
    uint16_t src_port = ntohs(l4.src_port);
    uint16_t dst_port = ntohs(l4.dst_port);

    struct nat_entry_key k = {
        .src_ip    = src,
        .dst_ip    = dst,
        .src_port  = src_port,
        .dst_port  = dst_port,
        .proto     = proto,
        .direction = 1
    };

    struct nat_entry *e = nat_lookup(table, &k);
    if (e) {
        ip->dst_addr = e->orig.src_ip;

        if (proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            tcp->dst_port = htons(e->orig.src_port);
            tcp->cksum = 0;
        } else if (proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            udp->dst_port    = htons(e->orig.src_port);
            udp->dgram_cksum = 0;
        } else if (proto == IPPROTO_ICMP) {
            struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4_hdr;
            icmp->icmp_ident = htons(e->orig.src_port); 
            icmp->icmp_cksum = 0;
        }
        m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
        if (proto == IPPROTO_UDP)
            m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
        else if (proto == IPPROTO_TCP)
            m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

        m->l2_len = sizeof(struct rte_ether_hdr);
        m->l3_len = sizeof(struct rte_ipv4_hdr);
        return 1;
    }
    const struct dnat_rule *dr =
        nat_find_dnat_rule(&cfg->nat, dst, l4.dst_port, proto);
    if (!dr)
        return 0;

    uint32_t int_ip      = dr->int_ip;
    uint16_t int_port    = dr->int_port ? dr->int_port : dst_port;
    uint32_t client_ip   = src;
    uint16_t client_port = src_port;
    uint32_t vip_ip      = cfg->wan.ip_addr;
    uint16_t vip_port    = (uint16_t)dr->ext_port;

    struct nat_entry_key fwd = {
        .src_ip    = int_ip,
        .dst_ip    = client_ip,
        .src_port  = int_port,
        .dst_port  = client_port,
        .proto     = proto,
        .direction = 0
    };
    struct nat_entry_key rev = {
        .src_ip    = client_ip,
        .dst_ip    = vip_ip,
        .src_port  = client_port,
        .dst_port  = vip_port,
        .proto     = proto,
        .direction = 1
    };

    nat_insert(table, &fwd, &rev, 0);

    ip->dst_addr = int_ip;
    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
        tcp->dst_port = htons(int_port);
        tcp->cksum = 0;
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
        udp->dst_port    = htons(int_port);
        udp->dgram_cksum = 0;
    }
    m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
    if (proto == IPPROTO_UDP)
        m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
    else if (proto == IPPROTO_TCP)
        m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

    m->l2_len = sizeof(struct rte_ether_hdr);
    m->l3_len = sizeof(struct rte_ipv4_hdr);

    return 1;
}
