#include <stdio.h>
#include <rte_ether.h>
#include <rte_ethdev.h>    
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <netinet/in.h>
#include <rte_icmp.h>


#include "dpdk_port.h" 
#include "fib.h"     
#include "neigh_t.h"
#include "forward.h"

static inline struct if_state* if_by_port(struct if_state *lan, struct if_state *wan, uint16_t port){
    return (port == lan->port_id) ? lan : ((port == wan->port_id) ? wan : NULL);
}

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

int ipv4_handle_local_icmp(struct if_state *lan, struct if_state *wan,
                           struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth;
    struct rte_ipv4_hdr  *ip;
    struct rte_icmp_hdr  *icmp;

    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return 0;

    if (rte_pktmbuf_data_len(m) <
        sizeof(struct rte_ether_hdr) +
        sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_icmp_hdr))
        return 0;

    ip = (struct rte_ipv4_hdr *)(eth + 1);

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
    if (ip->next_proto_id != IPPROTO_ICMP)
        return 0;

    if (ip->dst_addr != lan->ip_be && ip->dst_addr != wan->ip_be)
        return 0;

    uint8_t ihl_bytes = (ip->version_ihl & 0x0F) * 4;
    if (ihl_bytes < sizeof(struct rte_ipv4_hdr) ||
        rte_pktmbuf_data_len(m) <
        sizeof(struct rte_ether_hdr) + ihl_bytes + sizeof(struct rte_icmp_hdr))
        return 0;

    icmp = (struct rte_icmp_hdr *)((uint8_t *)ip + ihl_bytes);

    if (icmp->icmp_type != ICMP_ECHO_REQUEST || icmp->icmp_code != 0)
        return 0;

    uint32_t src_ip = ip->src_addr;
    ip->src_addr = ip->dst_addr;
    ip->dst_addr = src_ip;

    struct rte_ether_addr src_mac;
    rte_ether_addr_copy(&eth->src_addr, &src_mac);
    rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
    rte_ether_addr_copy(&src_mac, &eth->dst_addr);

    icmp->icmp_type = ICMP_ECHO_REPLY;
    icmp->icmp_cksum = 0;

    uint16_t ip_len   = rte_be_to_cpu_16(ip->total_length);
    uint16_t icmp_len = ip_len - ihl_bytes;

    uint16_t cksum = rte_raw_cksum(icmp, icmp_len);
    cksum = ~cksum;
    icmp->icmp_cksum = cksum;

    ip->time_to_live = 64;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    uint16_t out_port = m->port;   
    uint16_t sent = rte_eth_tx_burst(out_port, 0, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
    }

    return 1;   /* handled */
}


int ipv4_forward_one(struct if_state *lan, struct if_state *wan,
                     const struct fi_table *fib, struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){printf("NOT IPV4 packet. Dismissed\n");return 0;};

    if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + sizeof(struct rte_ipv4_hdr)){
        rte_pktmbuf_free(m); 
        printf("Bad size\n");
        return 1;
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    if ((ip->version_ihl >> 4) != 4) { printf("IPv6 packet\n"); rte_pktmbuf_free(m); return 1; }
    neigh_learn(&lan->table, ip->src_addr, &eth->src_addr);


    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;
    if (rte_pktmbuf_pkt_len(m) < sizeof(*eth) + ihl) { printf("wrong packet length\n"); rte_pktmbuf_free(m); return 1; }
    // if (ip->dst_addr == lan->ip_be || ip->dst_addr == wan->ip_be){
    //     printf("Local forwarding not working yet\n");
    //     rte_pktmbuf_free(m); return 1;
    // }

    if (ip->time_to_live <= 1){
        printf("No ttl\n");
        rte_pktmbuf_free(m); return 1;
    }
    uint16_t egress_port = 0xffff;
    uint32_t next_hop_be = 0;
    if (!fib_lookup(fib, ip->dst_addr, &egress_port, &next_hop_be)){
        printf("No route\n");
        rte_pktmbuf_free(m); return 1;
    }
    struct if_state *eg = if_by_port(lan, wan, egress_port);
    if (!eg){ printf("No port\n"); rte_pktmbuf_free(m); return 1; }


    if (next_hop_be == 0) next_hop_be = ip->dst_addr;
    struct rte_ether_addr nh_mac;
    if (!neigh_lookup(&eg->table, next_hop_be, &nh_mac)){
        printf("No such neigh\n");
        rte_pktmbuf_free(m); return 1;
    }
    ip->time_to_live -= 1;
    ip->hdr_checksum = 0;
    ip->src_addr = wan->ip_be;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    rte_ether_addr_copy(&nh_mac,  &eth->dst_addr);
    rte_ether_addr_copy(&eg->mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    uint16_t sent = rte_eth_tx_burst(eg->port_id, eg->txq, &m, 1);
    if (sent == 0) {printf("Failed to send\n"); rte_pktmbuf_free(m);};
    printf("Sent packet\n");
    return 1;

}