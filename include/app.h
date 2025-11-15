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

struct nat_rule_dnat {
    uint16_t ing_port;
    uint16_t egr_port;
    uint32_t internal_ip;
};

struct nat_rule_snat {
    uint32_t int_net;
    uint32_t int_mask;
    char out_if[OUT_IF_NAME_MAX_LEN];
    uint32_t ext_ip;
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
    // char lan_name[IF_NAME_MAX_LEN];
    // char wan_name[IF_NAME_MAX_LEN];
    struct interface wan;
    struct interface lan;
    uint32_t lan_net, lan_mask;
    uint32_t wan_net, wan_mask;
    uint32_t public_ip;

    int hairpin;
    struct nat_rule_snat snat[NAT_MAX_SNAT_RULES]; uint8_t snat_cnt;
    struct nat_rule_dnat dnat[NAT_MAX_DNAT_RULES]; uint8_t dnat_cnt;

    struct arp_config arp;

    struct timeout_cfg to;
    int use_metrics;
    char metrics_addr[METRICS_ADDR_MAX_LEN];
    uint16_t metrics_port;

    uint64_t lcore_mask;
};

#endif