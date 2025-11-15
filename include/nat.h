#pragma once
#ifndef NAT_H
#define NAT_H

#include <stdint.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_icmp.h>

#include "constants.h"

struct dnat_rule {
    uint32_t ext_ip;
    uint32_t ext_port;
    uint32_t int_ip;
    uint32_t int_port;
    uint8_t proto; // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, 0=all
};

struct nat_entry_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t src_port;
    uint32_t dst_port;
    uint8_t proto;
    uint8_t direction; // 0 = original direction, 1 = reverse
};

struct nat_entry {
    struct nat_entry_key orig;
    struct nat_entry_key reply;
    uint8_t hairpin; // 1 if hairpin
    uint64_t last_seen;
};

struct nat_table {
    struct nat_entry entries[NAT_TABLE_SIZE];
    uint32_t count;
};

struct l4_tuple {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t icmp_id;
};

static inline int parse_l4_tuple(struct rte_ipv4_hdr *ip,
                                 struct l4_tuple *out,
                                 void **l4_hdr_out)
{
    uint8_t ihl_bytes = (ip->version_ihl & 0x0F) * 4;
    uint16_t ip_len   = rte_be_to_cpu_16(ip->total_length);
    if (ihl_bytes < sizeof(struct rte_ipv4_hdr) ||
        ip_len < ihl_bytes)
        return -1;

    uint8_t *l4 = ((uint8_t *)ip) + ihl_bytes;
    *l4_hdr_out = l4;

    memset(out, 0, sizeof(*out));

    switch (ip->next_proto_id) {
    case IPPROTO_TCP: {
        struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4;
        if (ip_len < ihl_bytes + sizeof(*tcp)) return -1;
        out->src_port = tcp->src_port;
        out->dst_port = tcp->dst_port;
        return IPPROTO_TCP;
    }
    case IPPROTO_UDP: {
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4;
        if (ip_len < ihl_bytes + sizeof(*udp)) return -1;
        out->src_port = udp->src_port;
        out->dst_port = udp->dst_port;
        return IPPROTO_UDP;
    }
    case IPPROTO_ICMP: {
        struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4;
        if (ip_len < ihl_bytes + sizeof(*icmp)) return -1;
        // treat echo id as "port"
        out->icmp_id = icmp->icmp_ident;
        out->src_port = icmp->icmp_ident;
        out->dst_port = icmp->icmp_ident;
        return IPPROTO_ICMP;
    }
    default:
        return -1;
    }
}

#endif