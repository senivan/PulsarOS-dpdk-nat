#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include "constants.h"
#include "config.h"
#include "arp.h"
#include "dpdk_port.h"
#include "fib.h"
#include "forward.h"
#include "nat.h"
#include "debug.h"

#if DEBUG_OUTPUT
#  pragma message("DEBUG_OUTPUT = 1")
#else
#  pragma message("DEBUG_OUTPUT = 0")
#endif


static volatile int keep_running = 1;
static void on_sigint(int sig){ (void)sig; keep_running = 0; }

static void wait_link(uint16_t port){
    struct rte_eth_link link;
    for (int i=0;i<20;i++){ rte_eth_link_get_nowait(port,&link); if (link.link_status) break; rte_delay_us_sleep(50*1000); }
    rte_eth_link_get_nowait(port,&link);
    DBG("[port %u] link %s %u Mbps\n", port, link.link_status?"UP":"DOWN", link.link_speed);
}

static void rx_loop_main(
    struct app_config *cfg,
    struct if_state *lan, 
    struct if_state *wan, 
    const struct fi_table *fib,
    struct nat_table *nat
)
{
    const uint16_t BURST = 32;
    struct rte_mbuf *pkts[BURST];

    while (keep_running) {
        uint16_t n = rte_eth_rx_burst(lan->port_id, 0, pkts, BURST);
        for (uint16_t i=0; i<n; i++) {
            struct rte_mbuf *m = pkts[i];
            const struct rte_ether_hdr *eth; uint16_t et, l3off;
            if (l2_skip_vlan(m, &eth, &et, &l3off) < 0) { rte_pktmbuf_free(m); continue; }

            if (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                (void)arp_handle(lan, m);   
                continue;
            }
            if (et != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { rte_pktmbuf_free(m); continue; }

            struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr*, l3off);
            m->l2_len = l3off; m->l3_len = sizeof(*ip);  

            if (ip_is_local(ip->dst_addr, lan, wan)) {
                if (ipv4_handle_local_icmp(lan, wan, m)) continue;
                rte_pktmbuf_free(m);
                continue;
            }

            nat_process_lan_outbound(cfg, nat, ip, m);

            if (!ipv4_forward_one(lan, wan, fib, m)) rte_pktmbuf_free(m);
        }


        n = rte_eth_rx_burst(wan->port_id, 0, pkts, BURST);
        for (uint16_t i=0; i<n; i++) {
            struct rte_mbuf *m = pkts[i];
            const struct rte_ether_hdr *eth; uint16_t et, l3off;
            if (l2_skip_vlan(m, &eth, &et, &l3off) < 0) { rte_pktmbuf_free(m); continue; }

            if (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                (void)arp_handle(wan, m);  
                continue;
            }
            if (et != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { rte_pktmbuf_free(m); continue; }

            struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr*, l3off);
            m->l2_len = l3off; m->l3_len = sizeof(*ip);

            nat_process_wan_inbound(cfg, nat, ip, m);

            if (ip->dst_addr == wan->ip_be) {
                if (ipv4_handle_local_icmp(lan, wan, m)) continue;
                rte_pktmbuf_free(m);
                continue;
            }

            if (!ipv4_forward_one(lan, wan, fib, m)) rte_pktmbuf_free(m);
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], "--") != 0) { DBG( "usage: natdpdk -- -c <config.yaml>\n"); return 2; }
    const char *cfgpath = NULL;
    for (int i = 2; i < argc; i++) if (!strcmp(argv[i], "-c") && i+1 < argc) cfgpath = argv[++i];
    if (!cfgpath) { DBG( "config required\n"); return 2; }

    struct app_config cfg;
    struct nat_table nat;
    nat_table_init(&nat);
    if (cfg_load(cfgpath, &cfg) < 0 || cfg_validate(&cfg) < 0) return 1;
    struct if_state lan = {0}, wan = {0};
    neigh_init(&lan.table);
    neigh_init(&wan.table);
    lan.ip_be = cfg.lan.ip_addr;
    wan.ip_be = cfg.wan.ip_addr;
    lan.txq = 0; wan.txq = 0;
    struct fi_table fib = {0};
    init_fib(&fib);
    struct in_addr a;
    struct in_addr b;
    inet_pton(AF_INET, "192.168.10.0", &a);
    inet_pton(AF_INET, "255.255.255.0", &b);
    fib_add(&fib, a.s_addr, b.s_addr, 24, 0, 0);
    fib_add(&fib, cfg.wan_net, cfg.wan_mask, 24, 1,  0);





    if (vdev_create(argv[0], &cfg) < 0) return 1;
    if (ports_configure(&lan,&wan, DPDK_RX_DESC, DPDK_TX_DESC, DPDK_MBUF_COUNT, DPDK_MBUF_CACHE) < 0) return 1;

    wait_link(lan.port_id);
    wait_link(wan.port_id);

    signal(SIGINT, on_sigint);

    arp_send_gratuitous(&lan);
    arp_send_gratuitous(&wan);
    rte_delay_us_sleep(200*1000);
    arp_send_gratuitous(&lan);
    arp_send_gratuitous(&wan);

    rx_loop_main(&cfg, &lan, &wan, &fib, &nat);

    rte_eth_dev_stop(lan.port_id);
    rte_eth_dev_stop(wan.port_id);
    rte_eth_dev_close(lan.port_id);
    rte_eth_dev_close(wan.port_id);
    rte_eal_cleanup();
    return 0;
}
