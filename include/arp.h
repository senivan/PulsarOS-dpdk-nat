#pragma once
#ifndef ARP_H
#define ARP_H
#include <stdint.h>
#include <rte_mbuf.h>

#include "dpdk_port.h"


static inline int l2_skip_vlan(const struct rte_mbuf *m,
                               const struct rte_ether_hdr **eth_out,
                               uint16_t *etype_out,
                               uint16_t *off_out)
{
    const uint16_t max = rte_pktmbuf_pkt_len(m);
    uint16_t off = 0;

    if (max < sizeof(struct rte_ether_hdr)) return -1;
    const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
    uint16_t et = eth->ether_type;
    off = sizeof(*eth);

    while (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
           et == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
        if (max < off + 4) return -1;           
        et = *(const uint16_t *)((const char *)rte_pktmbuf_mtod(m, const char *) + off + 2);
        off += 4;
    }

    *eth_out  = eth;
    *etype_out = et;
    *off_out  = off;
    return 0;
}

static inline bool ip_is_local(uint32_t dst_be,
                               const struct if_state *lan,
                               const struct if_state *wan)
{
    return dst_be == lan->ip_be || dst_be == wan->ip_be;
}
static inline void send_arp_reply(struct if_state *ifs,
                                          struct rte_mbuf *m,
                                          uint16_t l2_off);
void arp_send_gratuitous(struct if_state *ifs);
static inline int is_arp_request_for_us(struct rte_mbuf *m, uint32_t our_ip_be);
int arp_handle(struct if_state *ifs, struct rte_mbuf *m);

#endif 