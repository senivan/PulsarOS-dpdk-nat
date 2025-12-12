#pragma once
#ifndef NAT_H
#define NAT_H

#include <stdint.h>
#include <time.h>
#include <string.h>

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_icmp.h>
#include <rte_mbuf.h>

#include "app.h"
#include "constants.h"

struct rte_hash;

struct l4_tuple {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t icmp_id;
};

#define NAT_HASH_ENTRIES   16384

struct nat_table {
    struct nat_entry entries[NAT_TABLE_SIZE];
    uint32_t count;

    struct rte_hash *hash_fwd;   
    struct rte_hash *hash_rev;   
};

void nat_table_init(struct nat_table *t);

void nat_table_destroy(struct nat_table *t);

static inline int parse_l4_tuple(struct rte_ipv4_hdr *ip,
                                 struct l4_tuple *out,
                                 void **l4_hdr_out)
{
    uint8_t  ihl_bytes = (ip->version_ihl & 0x0F) * 4;
    uint16_t ip_len    = rte_be_to_cpu_16(ip->total_length);

    if (ihl_bytes < sizeof(struct rte_ipv4_hdr) || ip_len < ihl_bytes)
        return -1;

    uint8_t *l4 = ((uint8_t *)ip) + ihl_bytes;
    *l4_hdr_out = l4;

    memset(out, 0, sizeof(*out));

    switch (ip->next_proto_id) {
    case IPPROTO_TCP: {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        if (ip_len < ihl_bytes + sizeof(*tcp))
            return -1;
        out->src_port = tcp->src_port;
        out->dst_port = tcp->dst_port;
        return IPPROTO_TCP;
    }
    case IPPROTO_UDP: {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        if (ip_len < ihl_bytes + sizeof(*udp))
            return -1;
        out->src_port = udp->src_port;
        out->dst_port = udp->dst_port;
        return IPPROTO_UDP;
    }
    case IPPROTO_ICMP: {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4;
        if (ip_len < ihl_bytes + sizeof(*icmp))
            return -1;
        out->icmp_id  = icmp->icmp_ident;
        out->src_port = icmp->icmp_ident;
        out->dst_port = icmp->icmp_ident;
        return IPPROTO_ICMP;
    }
    default:
        return -1;
    }
}

int nat_process_wan_inbound(const struct app_config *cfg,
                            struct nat_table *table,
                            struct rte_ipv4_hdr *ip,
                            struct rte_mbuf *m);

int nat_process_lan_outbound(const struct app_config *cfg,
                             struct nat_table *table,
                             struct rte_ipv4_hdr *ip,
                             struct rte_mbuf *m);

#endif 
