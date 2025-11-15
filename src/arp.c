#include <string.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include "arp.h"

static inline int is_arp_request_for_us(struct rte_mbuf *m, uint32_t our_ip_be) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) return 0;

    if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))
        return 0;

    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    if (arp->arp_opcode  != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) return 0;
    if (arp->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) return 0;
    if (arp->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER))  return 0;
    if (arp->arp_hlen != RTE_ETHER_ADDR_LEN || arp->arp_plen != 4) return 0;

    return arp->arp_data.arp_tip == our_ip_be;
}

static inline void send_arp_reply(struct if_state *ifs, struct rte_mbuf *m) {
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);

    struct rte_ether_addr req_sha = arp->arp_data.arp_sha;
    uint32_t              req_sip = arp->arp_data.arp_sip;

    rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
    rte_ether_addr_copy(&ifs->mac,    &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = 4;
    arp->arp_opcode  = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    rte_ether_addr_copy(&ifs->mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = ifs->ip_be;

    rte_ether_addr_copy(&req_sha,  &arp->arp_data.arp_tha);
    arp->arp_data.arp_tip = req_sip;

    const uint16_t plen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    m->l2_len   = sizeof(struct rte_ether_hdr);
    m->data_len = plen;
    m->pkt_len  = plen;

    uint16_t sent = rte_eth_tx_burst(ifs->port_id, ifs->txq, &m, 1);
    if (sent == 0) rte_pktmbuf_free(m);
}

int arp_handle(struct if_state *ifs, struct rte_mbuf *m) {
    if (!m) return 1;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) return 0;
    struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);
    neigh_learn(&ifs->table, arp->arp_data.arp_sip, &arp->arp_data.arp_sha);

    if (is_arp_request_for_us(m, ifs->ip_be)) {
        send_arp_reply(ifs, m);     
        return 1;
    }

    rte_pktmbuf_free(m);
    return 1;
}

void arp_send_gratuitous(struct if_state *ifs) {
    struct rte_mbuf *m = rte_pktmbuf_alloc(ifs->mbuf_pool);
    if (!m) return;

    const uint16_t plen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    if (!rte_pktmbuf_append(m, plen)) { rte_pktmbuf_free(m); return; }

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);

    struct rte_ether_addr bcast;
    // rte_eth_broadcast_addr(&bcast);
    memset(bcast.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);

    rte_ether_addr_copy(&bcast,   &eth->dst_addr);
    rte_ether_addr_copy(&ifs->mac,&eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = 4;
    arp->arp_opcode  = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

    rte_ether_addr_copy(&ifs->mac, &arp->arp_data.arp_sha);
    memset(&arp->arp_data.arp_tha, 0, sizeof(arp->arp_data.arp_tha));
    arp->arp_data.arp_sip = ifs->ip_be;  
    arp->arp_data.arp_tip = ifs->ip_be;

    m->l2_len   = sizeof(struct rte_ether_hdr);
    m->data_len = plen;
    m->pkt_len  = plen;

    uint16_t sent = rte_eth_tx_burst(ifs->port_id, ifs->txq, &m, 1);
    if (sent == 0) rte_pktmbuf_free(m);
}
