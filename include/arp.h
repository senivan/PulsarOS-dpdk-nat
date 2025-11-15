#pragma once
#ifndef ARP_H
#define ARP_H
#include <stdint.h>
#include <rte_mbuf.h>

#include "dpdk_port.h"

static inline void send_arp_reply(struct if_state *ifs, struct rte_mbuf *m);
static inline void send_gratuitous_arp(struct if_state *ifs);
static inline int is_arp_request_for_host(struct rte_mbuf *m, uint32_t host_ip_be);


#endif 