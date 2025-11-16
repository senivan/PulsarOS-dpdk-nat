#include <string.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include "arp.h"
#include "neigh_t.h"


static inline int ip_is_multicast(uint32_t be) {
    return (be & rte_cpu_to_be_32(0xF0000000)) == rte_cpu_to_be_32(0xE0000000);
}
static inline int ip_is_broadcast(uint32_t be) {
    return be == rte_cpu_to_be_32(0xFFFFFFFF);
}
static inline int ip_is_local_arp(uint32_t be, const struct if_state *ifs) {
    return be == ifs->ip_be;
}
static inline int is_ipv4_arp_request_for_us(const struct rte_mbuf *m,
                                             uint32_t our_ip_be,
                                             const struct rte_ether_hdr **eth_out,
                                             const struct rte_arp_hdr   **arp_out,
                                             uint16_t *l2_off_out)
{
    const struct rte_ether_hdr *eth;
    uint16_t et, off;

    if (l2_skip_vlan(m, &eth, &et, &off) < 0) return 0;
    if (et != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) return 0;

    if (rte_pktmbuf_pkt_len(m) < off + sizeof(struct rte_arp_hdr)) return 0;

    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)((const char *)rte_pktmbuf_mtod(m, const char *) + off);

    if (arp->arp_opcode  != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) return 0;
    if (arp->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) return 0;
    if (arp->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER))  return 0;
    if (arp->arp_hlen != RTE_ETHER_ADDR_LEN || arp->arp_plen != 4) return 0;

    if (arp->arp_data.arp_tip != our_ip_be) return 0;

    if (eth_out) *eth_out = eth;
    if (arp_out) *arp_out = arp;
    if (l2_off_out) *l2_off_out = off;
    return 1;
}

static inline int arp_is_reply(const struct rte_mbuf *m,
                               const struct rte_arp_hdr **arp_out)
{
    const struct rte_ether_hdr *eth; uint16_t et, off;
    if (l2_skip_vlan(m, &eth, &et, &off) < 0) return 0;
    if (et != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) return 0;
    if (rte_pktmbuf_pkt_len(m) < off + sizeof(struct rte_arp_hdr)) return 0;

    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)((const char *)rte_pktmbuf_mtod(m, const char *) + off);
    if (arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) return 0;
    if (arp_out) *arp_out = arp;
    return 1;
}

static inline void send_arp_reply(struct if_state *ifs,
                                          struct rte_mbuf *m,
                                          uint16_t l2_off)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)((uint8_t *)eth + l2_off);

    rte_ether_addr_copy(&arp->arp_data.arp_sha, &eth->dst_addr); 
    rte_ether_addr_copy(&ifs->mac,              &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP); 

    struct rte_ether_addr tha = arp->arp_data.arp_sha; 
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

    rte_ether_addr_copy(&ifs->mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = ifs->ip_be;
    rte_ether_addr_copy(&tha,      &arp->arp_data.arp_tha);


    struct rte_mbuf *txm = m;
    if (!rte_eth_tx_burst(ifs->port_id, ifs->txq, &txm, 1)) rte_pktmbuf_free(m);
}


int arp_handle(struct if_state *ifs, struct rte_mbuf *m)
{
    if (!m) return 1;

    const struct rte_arp_hdr *arp;
    if (arp_is_reply(m, &arp)) {
        if (arp->arp_data.arp_sip != 0 &&
            (arp->arp_data.arp_sha.addr_bytes[0] & 1) == 0)
            neigh_learn(&ifs->table, arp->arp_data.arp_sip, &arp->arp_data.arp_sha);

        rte_pktmbuf_free(m);
        return 1;
    }

    const struct rte_ether_hdr *eth;
    uint16_t l2off;
    if (is_ipv4_arp_request_for_us(m, ifs->ip_be, &eth, &arp, &l2off)) {
        if (!ip_is_broadcast(arp->arp_data.arp_sip) &&
            arp->arp_data.arp_sip != 0 &&
            !ip_is_multicast(arp->arp_data.arp_sip) &&
            !ip_is_local_arp(arp->arp_data.arp_sip, ifs) &&
            ((arp->arp_data.arp_sha.addr_bytes[0] & 1) == 0)) {
            neigh_learn(&ifs->table, arp->arp_data.arp_sip, &arp->arp_data.arp_sha);
        }

        send_arp_reply(ifs, m, l2off);
        return 1;
    }

    const struct rte_ether_hdr *e2; uint16_t et2, off2;
    if (l2_skip_vlan(m, &e2, &et2, &off2) == 0 && et2 == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        const struct rte_arp_hdr *a2 = (const struct rte_arp_hdr *)((const char *)rte_pktmbuf_mtod(m, const char *) + off2);
        if (!ip_is_broadcast(a2->arp_data.arp_sip) &&
            a2->arp_data.arp_sip != 0 &&
            !ip_is_multicast(a2->arp_data.arp_sip) &&
            !ip_is_local_arp(a2->arp_data.arp_sip, ifs) &&
            ((a2->arp_data.arp_sha.addr_bytes[0] & 1) == 0)) {
            neigh_learn(&ifs->table, a2->arp_data.arp_sip, &a2->arp_data.arp_sha);
        }

    }

    rte_pktmbuf_free(m);
    return 1;
}

void arp_send_gratuitous(struct if_state *ifs)
{
    {
        struct rte_mbuf *m = rte_pktmbuf_alloc(ifs->mbuf_pool);
        if (!m) return;
        const uint16_t plen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
        if (!rte_pktmbuf_append(m, plen)) { rte_pktmbuf_free(m); return; }

        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);

        struct rte_ether_addr bcast; memset(bcast.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
        rte_ether_addr_copy(&bcast,    &eth->dst_addr);
        rte_ether_addr_copy(&ifs->mac, &eth->src_addr);
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

        if (!rte_eth_tx_burst(ifs->port_id, ifs->txq, &m, 1)) rte_pktmbuf_free(m);
    }

    {
        struct rte_mbuf *m = rte_pktmbuf_alloc(ifs->mbuf_pool);
        if (!m) return;
        const uint16_t plen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
        if (!rte_pktmbuf_append(m, plen)) { rte_pktmbuf_free(m); return; }

        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        struct rte_arp_hdr   *arp = (struct rte_arp_hdr *)(eth + 1);

        struct rte_ether_addr bcast; memset(bcast.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
        rte_ether_addr_copy(&bcast,    &eth->dst_addr);
        rte_ether_addr_copy(&ifs->mac, &eth->src_addr);
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

        arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
        arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        arp->arp_hlen = RTE_ETHER_ADDR_LEN;
        arp->arp_plen = 4;
        arp->arp_opcode  = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

        rte_ether_addr_copy(&ifs->mac, &arp->arp_data.arp_sha);
        rte_ether_addr_copy(&bcast,    &arp->arp_data.arp_tha);
        arp->arp_data.arp_sip = ifs->ip_be;
        arp->arp_data.arp_tip = ifs->ip_be;

        m->l2_len   = sizeof(struct rte_ether_hdr);
        m->data_len = plen;
        m->pkt_len  = plen;

        if (!rte_eth_tx_burst(ifs->port_id, ifs->txq, &m, 1)) rte_pktmbuf_free(m);
    }
}
