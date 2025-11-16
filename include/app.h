#pragma once
#ifndef APP_H
#define APP_H
#include <stdint.h>
#include "constants.h"

struct timeout_cfg {
    uint32_t tcp_established;
    uint32_t tcp_transitory;
    uint32_t udp;
    uint32_t icmp;
};

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

struct nat_config {
    uint8_t hairpin; // enable hairpin bool
    uint32_t dnat_count;
    struct dnat_rule dnat[NAT_MAX_DNAT_RULES];
};

struct interface {
    char name[IF_NAME_MAX_LEN];
    char pcie_addr[16];
    uint32_t ip_addr;
};

struct arp_config {
    size_t cache_size;
    size_t reachable_ms;
    size_t stale_ms;
    size_t request_interval_ms;
    size_t max_retries;
    size_t max_pending_per_neighbor;
    size_t gratuitous_on_start;
};

struct app_config {
    enum {
        PMD_TAP,
        PMD_AFPKT,
        PMD_PHYS
    } pmd;
    struct interface wan;
    struct interface lan;
    uint32_t lan_net, lan_mask;
    uint32_t wan_net, wan_mask;
    uint32_t public_ip;
    
    struct nat_config nat;

    struct arp_config arp;

    struct timeout_cfg to;
    int use_metrics;
    char metrics_addr[METRICS_ADDR_MAX_LEN];
    uint16_t metrics_port;

    uint64_t lcore_mask;
};

#endif