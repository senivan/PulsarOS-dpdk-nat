#include "fib.h"
#include <arpa/inet.h>


static inline int mask_match(uint32_t ip, uint32_t mask, uint32_t net){
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

int fib_lookup(const struct fi_table *f, uint32_t dst, 
                uint16_t *egress, uint32_t *hop)
{
    int best = -1;
    uint8_t best_prefix = 0;
    for(uint8_t i = 0; i < f->count; i++){
        const struct route *route = &f->routes[i];
        if (!mask_match(dst, route->dst, route->mask)) continue;
        if (route->prefix_length >= best_prefix){
            best = i;
            best_prefix = route->prefix_length;
        }
    }    
    if (best < 0) return 0;
    const struct route *rt = &f->routes[best];
    *egress = rt->egress_port;
    *hop = (rt->next_hop != 0) ? rt->next_hop : dst;
    return 1;
        
}