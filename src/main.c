#include <stdio.h>
#include <signal.h>
#include <string.h>

#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_lcore.h>

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

static void on_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void wait_link(uint16_t port)
{
    struct rte_eth_link link;

    for (int i = 0; i < 20; i++) {
        rte_eth_link_get_nowait(port, &link);
        if (link.link_status)
            break;
        rte_delay_us_sleep(50 * 1000);
    }
    rte_eth_link_get_nowait(port, &link);
    DBG("[port %u] link %s %u Mbps\n",
        port,
        link.link_status ? "UP" : "DOWN",
        link.link_speed);
}

struct worker_ctx {
    struct app_config   *cfg;
    struct if_state     *lan;
    struct if_state     *wan;
    const struct fi_table *fib;
    struct nat_table    *nat;
};

static int lan_to_wan_loop(void *arg)
{
    struct worker_ctx *ctx = (struct worker_ctx *)arg;
    const uint16_t BURST = 64;
    struct rte_mbuf *pkts[BURST];

    while (keep_running) {
        uint16_t n = rte_eth_rx_burst(ctx->lan->port_id, 0, pkts, BURST);
        if (n == 0)
            continue;

        for (uint16_t i = 0; i < n; i++) {
            if (i + 4 < n){
                rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 4], void *));
            }
            struct rte_mbuf *m = pkts[i];
            const struct rte_ether_hdr *eth;
            uint16_t et, l3off;

            if (l2_skip_vlan(m, &eth, &et, &l3off) < 0) {
                rte_pktmbuf_free(m);
                continue;
            }

            if (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                (void)arp_handle(ctx->lan, m);
                continue;
            }
            if (et != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                rte_pktmbuf_free(m);
                continue;
            }

            struct rte_ipv4_hdr *ip =
                rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, l3off);
            m->l2_len = l3off;
            m->l3_len = sizeof(*ip);

            if (ip_is_local(ip->dst_addr, ctx->lan, ctx->wan)) {
                if (ipv4_handle_local_icmp(ctx->lan, ctx->wan, m))
                    continue;
                rte_pktmbuf_free(m);
                continue;
            }

            nat_process_lan_outbound(ctx->cfg, ctx->nat, ip, m);

            if (!ipv4_forward_one(ctx->lan, ctx->wan, ctx->fib, m))
                rte_pktmbuf_free(m);
        }
    }

    return 0;
}

static int wan_to_lan_loop(void *arg)
{
    struct worker_ctx *ctx = (struct worker_ctx *)arg;
    const uint16_t BURST = 64;
    struct rte_mbuf *pkts[BURST];

    while (keep_running) {
        uint16_t n = rte_eth_rx_burst(ctx->wan->port_id, 0, pkts, BURST);
        if (n == 0)
            continue;

        for (uint16_t i = 0; i < n; i++) {
            if (i + 4 < n){
                rte_prefetch0(rte_pktmbuf_mtod(pkts[i + 4], void *));
            }
            struct rte_mbuf *m = pkts[i];
            const struct rte_ether_hdr *eth;
            uint16_t et, l3off;

            if (l2_skip_vlan(m, &eth, &et, &l3off) < 0) {
                rte_pktmbuf_free(m);
                continue;
            }

            if (et == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                (void)arp_handle(ctx->wan, m);
                continue;
            }
            if (et != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                rte_pktmbuf_free(m);
                continue;
            }

            struct rte_ipv4_hdr *ip =
                rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, l3off);
            m->l2_len = l3off;
            m->l3_len = sizeof(*ip);

            nat_process_wan_inbound(ctx->cfg, ctx->nat, ip, m);

            if (ip->dst_addr == ctx->wan->ip_be) {
                if (ipv4_handle_local_icmp(ctx->lan, ctx->wan, m))
                    continue;
                rte_pktmbuf_free(m);
                continue;
            }

            if (!ipv4_forward_one(ctx->lan, ctx->wan, ctx->fib, m))
                rte_pktmbuf_free(m);
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "--") != 0) {
        DBG("usage: natdpdk -- -c <config.yaml>\n");
        return 2;
    }

    const char *cfgpath = NULL;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-c") && i + 1 < argc)
            cfgpath = argv[++i];
    }
    if (!cfgpath) {
        DBG("config required\n");
        return 2;
    }

    struct app_config cfg;
    struct nat_table  nat;

    if (cfg_load(cfgpath, &cfg) < 0 || cfg_validate(&cfg) < 0)
        return 1;

    struct if_state lan = {0}, wan = {0};
    neigh_init(&lan.table);
    neigh_init(&wan.table);
    lan.ip_be = cfg.lan.ip_addr;
    wan.ip_be = cfg.wan.ip_addr;
    lan.txq = 0;
    wan.txq = 0;

    struct fi_table fib = {0};
    init_fib(&fib);

    struct in_addr a, b;
    inet_pton(AF_INET, "10.0.10.0", &a);
    inet_pton(AF_INET, "255.255.255.0", &b);
    fib_add(&fib, a.s_addr, b.s_addr, 24, 0, 0);

    fib_add(&fib, cfg.wan_net, cfg.wan_mask, 24, 1, 0);

    if (vdev_create(argv[0], &cfg) < 0)
        return 1;
    if (ports_configure(&lan, &wan,
                        DPDK_RX_DESC, DPDK_TX_DESC,
                        DPDK_MBUF_COUNT, DPDK_MBUF_CACHE) < 0)
        return 1;

    nat_table_init(&nat);

    wait_link(lan.port_id);
    wait_link(wan.port_id);

    signal(SIGINT, on_sigint);

    arp_send_gratuitous(&lan);
    arp_send_gratuitous(&wan);
    rte_delay_us_sleep(200 * 1000);
    arp_send_gratuitous(&lan);
    arp_send_gratuitous(&wan);

    struct worker_ctx ctx = {
        .cfg = &cfg,
        .lan = &lan,
        .wan = &wan,
        .fib = &fib,
        .nat = &nat,
    };

    unsigned first = rte_get_next_lcore(-1, 1, 0);
    unsigned second = rte_get_next_lcore(first, 1, 0);
    if (first == RTE_MAX_LCORE || second == RTE_MAX_LCORE) {
        DBG("not enough lcores for 2 workers\n");
        return 1;
    }

    DBG("Starting LAN->WAN on lcore %u, WAN->LAN on lcore %u\n",
        first, second);

    rte_eal_remote_launch(lan_to_wan_loop, &ctx, first);
    rte_eal_remote_launch(wan_to_lan_loop, &ctx, second);

    while (keep_running) {
        rte_delay_us_sleep(100000);
    }

    rte_eal_wait_lcore(first);
    rte_eal_wait_lcore(second);

    nat_table_destroy(&nat);

    rte_eth_dev_stop(lan.port_id);
    rte_eth_dev_stop(wan.port_id);
    rte_eth_dev_close(lan.port_id);
    rte_eth_dev_close(wan.port_id);
    rte_eal_cleanup();

    return 0;
}
