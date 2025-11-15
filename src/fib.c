#include "fib.h"
#include <arpa/inet.h>


static inline int mask_match(uint32_t ip, uint32_t net, uint32_t mask){
    return (ip & mask) == (net & mask);
}

int fib_add (struct fi_table *f, uint32_t dst, uint32_t mask, uint8_t prefix,
            uint16_t egress_port, uint32_t next_hop)
{
    if (f->count >= FIB_MAX_ROUTES) return -1;
    f->routes[f->count].dst = dst;
    f->routes[f->count].mask = mask;
    f->routes[f->count].prefix_length = prefix;
    f->routes[f->count].egress_port = egress_port;
    f->routes[f->count].next_hop = next_hop;
    ++f->count;
    return 0;
}

// int fib_lookup(const struct fi_table *f, uint32_t dst, 
//                 uint16_t *egress, uint32_t *hop)
// {
//     int best = -1;
//     uint8_t best_prefix = 0;
//     for(uint8_t i = 0; i < f->count; i++){
//         const struct route *route = &f->routes[i];
//         if (!mask_match(dst, route->dst, route->mask)) continue;
//         if (route->prefix_length >= best_prefix){
//             best = i;
//             best_prefix = route->prefix_length;
//         }
//     }    
//     if (best < 0) return 0;
//     const struct route *rt = &f->routes[best];
//     *egress = rt->egress_port;
//     *hop = (rt->next_hop != 0) ? rt->next_hop : dst;
//     return 1;
        
// }

int fib_lookup(const struct fi_table *f, uint32_t dst, 
                uint16_t *egress, uint32_t *hop)
{
    /* Debug: print the lookup address and route table */
    struct in_addr a;
    a.s_addr = dst;
    printf("[fib] lookup dst=%s (0x%08x), routes=%u\n", inet_ntoa(a), ntohl(dst), (unsigned)f->count);

    for (uint8_t i = 0; i < f->count; ++i) {
        struct in_addr rnet, rmask;
        rnet.s_addr = f->routes[i].dst;
        rmask.s_addr = f->routes[i].mask;
        printf("[fib]   route %u: net=%s mask=%s prefix=%u egress=%u next_hop=0x%08x\n",
               i, inet_ntoa(rnet), inet_ntoa(rmask), f->routes[i].prefix_length,
               f->routes[i].egress_port, ntohl(f->routes[i].next_hop));
    }

    int best = -1;
    uint8_t best_prefix = 0;
    for(uint8_t i = 0; i < f->count; i++){
        const struct route *route = &f->routes[i];
        if (!mask_match(dst, route->dst, route->mask)) {
            /* Debug: show which routes don't match */
            struct in_addr rnet; rnet.s_addr = route->dst;
            struct in_addr rmask; rmask.s_addr = route->mask;
            printf("[fib]   no match: dst=%s net=%s mask=%s\n",
                   inet_ntoa(a), inet_ntoa(rnet), inet_ntoa(rmask));
            continue;
        }
        if (route->prefix_length >= best_prefix){
            best = i;
            best_prefix = route->prefix_length;
        }
    }    
    if (best < 0) {
        printf("[fib] => no route matched\n");
        return 0;
    }
    const struct route *rt = &f->routes[best];
    *egress = rt->egress_port;
    *hop = (rt->next_hop != 0) ? rt->next_hop : dst;
    struct in_addr hopaddr; hopaddr.s_addr = *hop;
    printf("[fib] => matched route %d (prefix=%u) egress=%u hop=%s\n", best, rt->prefix_length, *egress, inet_ntoa(hopaddr));
    return 1;
        
}