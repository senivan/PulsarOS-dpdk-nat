#include <string.h>
#include <time.h>


#include "nat.h"

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
           a->proto     == b->proto    ;
}

void nat_table_init(struct nat_table *t)
{
    memset(t, 0, sizeof(*t));
}

struct nat_entry *nat_lookup(struct nat_table *t,
                             const struct nat_entry_key *key)
{
    if (!t)
        return NULL;

    for (uint32_t i = 0; i < t->count; i++) {
        struct nat_entry *e = &t->entries[i];

        if (nat_key_equal(&e->orig, key))
            return e;

        if (nat_key_equal(&e->reply, key))
            return e;
    }
    return NULL;
}

struct nat_entry *nat_insert(struct nat_table *t,
                             const struct nat_entry_key *orig,
                             const struct nat_entry_key *reply,
                             int hairpin)
{
    if (t->count >= NAT_TABLE_SIZE)
        return NULL;

    struct nat_entry *e = &t->entries[t->count++];
    e->orig = *orig;
    e->reply = *reply;
    e->hairpin = hairpin ? 1 : 0;
    e->last_seen = time(NULL);
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
        .src_ip   = src,
        .dst_ip   = dst,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto    = proto,
        .direction = 0
    };

    struct nat_entry *e = nat_lookup(table, &key);
    if (e) {
        uint32_t new_src   = e->reply.src_ip;
        uint32_t new_dst   = e->reply.dst_ip;  
        uint16_t new_sport = e->reply.src_port;
        uint16_t new_dport = e->reply.dst_port;

        ip->src_addr = new_src;
        ip->dst_addr = new_dst;

        if (proto == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            tcp->src_port = htons(new_sport);
            tcp->dst_port = htons(new_dport);
            tcp->cksum = 0;
            tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
        } else if (proto == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            udp->src_port = htons(new_sport);
            udp->dst_port = htons(new_dport);
            udp->dgram_cksum = 0;
            udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
        }

        m->ol_flags = 0;
        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);

        return 1;
    }


    if (ip_in_net(dst, cfg->lan_net, cfg->lan_mask))
        return 0;

    const struct dnat_rule *dr =
        nat_find_dnat_rule(&cfg->nat, dst, dst_port_be, proto);

    int hairpin = 0;
    uint32_t new_src, new_dst;
    uint16_t new_sport, new_dport;

    if (dr && ip_in_net(dr->int_ip, cfg->lan_net, cfg->lan_mask) &&
        cfg->nat.hairpin)
    {
        hairpin  = 1;
        new_dst  = dr->int_ip;
        new_dport = dr->int_port ? dr->int_port : dst_port;

        new_src  = cfg->lan.ip_addr;
        new_sport = src_port;
    } else {
        new_dst   = dst;
        new_dport = dst_port;
        new_src   = cfg->wan.ip_addr;
        new_sport = nat_alloc_snat_port();
    }

    struct nat_entry_key orig = {
        .src_ip   = src,
        .dst_ip   = dst,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto    = proto,
        .direction = 0
    };

    struct nat_entry_key reply2 = {
        .src_ip   = new_dst,
        .dst_ip   = new_src,
        .src_port = new_dport,
        .dst_port = new_sport,
        .proto    = proto,
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
        tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
        udp->src_port = htons(new_sport);
        udp->dst_port = htons(new_dport);
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
    }

    m->ol_flags = 0;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

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
    if (proto < 0) return 0;

    uint32_t src = ip->src_addr;  
    uint32_t dst = ip->dst_addr; 

    uint16_t src_port_be = l4.src_port;
    uint16_t dst_port_be = l4.dst_port;
    uint16_t src_port    = ntohs(src_port_be);  
    uint16_t dst_port    = ntohs(dst_port_be);  

    struct in_addr a;
    char buf[16];
    a.s_addr = dst;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    printf("[nat] WAN inbound: dst=%s port=%u proto=%d\n",
           buf, (unsigned)dst_port, proto);

    const struct dnat_rule *dr =
        nat_find_dnat_rule(&cfg->nat, dst, dst_port_be, proto);

    if (!dr) {
        printf("[nat] no DNAT rule match\n");
        return 0;
    }

    uint32_t int_ip   = dr->int_ip;              
    uint16_t int_port = dr->int_port ? dr->int_port
                                     : dst_port;     
    uint32_t client_ip   = src;                      
    uint16_t client_port = src_port;
    uint32_t vip_ip      = cfg->wan.ip_addr;          
    uint16_t vip_port    = (uint16_t)dr->ext_port;   

    a.s_addr = int_ip;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    printf("[nat] DNAT match: %u -> int %s:%u\n",
           (unsigned)vip_port, buf, (unsigned)int_port);

    struct nat_entry_key orig = {
        .src_ip   = int_ip,         
        .dst_ip   = client_ip,     
        .src_port = int_port,
        .dst_port = client_port,
        .proto    = proto,
        .direction = 0
    };
    struct nat_entry_key reply = {
        .src_ip   = vip_ip,        
        .dst_ip   = client_ip,     
        .src_port = vip_port,     
        .dst_port = client_port,
        .proto    = proto,
        .direction = 1
    };

    nat_insert(table, &orig, &reply, 0);

    ip->dst_addr = int_ip;

    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
        tcp->dst_port = htons(int_port);
        tcp->cksum    = 0;
        tcp->cksum    = rte_ipv4_udptcp_cksum(ip, tcp);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
        udp->dst_port    = htons(int_port);
        udp->dgram_cksum = 0;
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
    }

    m->ol_flags      = 0;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    return 1;
}
