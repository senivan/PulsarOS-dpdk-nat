#pragma once
#ifndef APP_H
#define APP_H
#include <stdint.h>

struct timeout_cfg {
    uint32_t tcp_established;
    uint32_t tcp_transitory;
    uint32_t udp;
    uint32_t icmp;
}

struct nat_rule_dnat {
    uint16_t ing_port;
    uint16_t egr_port;
    uint32_t internal_ip;
}

struct nat_rule_snat {
    uint32_t int_net;
    uint32_t int_mask;
    char out_if[16];
    uint32_t ext_ip;
}

struct app_config {
    enum {
        PMD_TAP,
        PMD_AFPKT,
        PMD_PHYS
    } pmd;
    char lan_name[64];
    char wan_name[64];
    uint32_t lan_net, lan_mask;
    uint32_t wan_net, wan_mask;
    uint32_t public_ip;

    int hairpin;
    struct nat_rule_snat snat[64]; uint8_t snat_cnt;
    struct nat_rule_snat dnat[64]; uint8_t dnat_cnt;

    struct timeout_cfg to;
    bool use_metrics;
    char metrics_addr[64];
    uint16_t metrics_port;

    uint64_t lcore_mask;
};

#endif