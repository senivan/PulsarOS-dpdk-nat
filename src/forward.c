#include <stdio.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_byteorder.h>

#include "neigh_t.h"
#include "forward.h"


static inline struct if_state* if_by_port(struct if_state *lan, struct if_state *wan, uint16_t port){
    return (port == lan->port_id) ? lan : ((port == wan->port_id) ? wan : NULL);
}



int ipv4_forward_one(struct if_state *lan, struct if_state *wan,
                     const struct fib *fib, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) return 0;

    if (rte_pktmbuf_data_len(m) < sizeof(*eth) + sizeof(struct rte_ipv4_hdr)){
        rte_pktmbuf_free(m); return 1;
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    if ((ip->version_ihl >> 4) != 4) { rte_pktmbuf_free(m); return 1; }


    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    if (rte_pktmbuf_data_len(m) < sizeof(*eth) + ihl) { rte_pktmbuf_free(m); return 1; }

    if (ip->dst_addr == lan->ip_be || ip->dst_addr == wan->ip_be){
        rte_pktmbuf_free(m); return 1;
    }

    if (ip->time_to_live <= 1){
        rte_pktmbuf_free(m); return 1;
    }

    uint16_t egress_port = 0xffff;
    uint32_t next_hop_be = 0;
    if (!fib_lookup(fib, ip->dst_addr, &egress_port, &next_hop_be)){
        rte_pktmbuf_free(m); return 1;
    }
    struct if_state *eg = if_by_port(lan, wan, egress_port);
    if (!eg){ rte_pktmbuf_free(m); return 1; }

        struct rte_ether_addr nh_mac;
    if (!neigh_lookup(&eg->table, next_hop_be, &nh_mac)){
        rte_pktmbuf_free(m); return 1;
    }
        ip->time_to_live -= 1;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    rte_ether_addr_copy(&nh_mac,  &eth->dst_addr);
    rte_ether_addr_copy(&eg->mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    uint16_t sent = rte_eth_tx_burst(eg->port_id, eg->txq, &m, 1);
    if (sent == 0) rte_pktmbuf_free(m);
    return 1;

}