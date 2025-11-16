#pragma once
#ifndef ARP_H
#define ARP_H
#include <stdint.h>
#include <rte_mbuf.h>

#include "dpdk_port.h"

static inline void send_arp_reply(struct if_state *ifs, struct rte_mbuf *m);
void arp_send_gratuitous(struct if_state *ifs);
static inline int is_arp_request_for_us(struct rte_mbuf *m, uint32_t our_ip_be);
int arp_handle(struct if_state *ifs, struct rte_mbuf *m);


#endif 