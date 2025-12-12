#include "fib.h"
#include <arpa/inet.h>
#include <stdio.h>
#include "debug.h"

static inline int mask_match(uint32_t ip, uint32_t net, uint32_t mask){
    return (ip & mask) == (net & mask);
}


int fib_add(struct fi_table *f,
            uint32_t dst,
            uint32_t mask, uint8_t prefix, uint16_t egress_port, uint32_t next_hop)
{
    if (f->count >= FIB_MAX_ROUTES)
        return -1;
    dst &= mask;
    int pos = f->count;
    while (pos > 0 && f->routes[pos - 1].prefix_length < prefix) {
        f->routes[pos] = f->routes[pos - 1];
        --pos;
    }

    struct route *r = &f->routes[pos];
    r->dst            = dst;        
    r->mask           = mask;
    r->prefix_length  = prefix;
    r->egress_port    = egress_port;
    r->next_hop       = next_hop;

    f->count++;
    return 0;
}


static inline int route_match(uint32_t ip, const struct route *r)
{
    return (ip & r->mask) == r->dst;
}

int fib_lookup(const struct fi_table *f, uint32_t dst,
               uint16_t *egress, uint32_t *hop)
{
    struct in_addr a;
    a.s_addr = dst;
    DBG("[fib] lookup dst=%s (0x%08x), routes=%u\n",
        inet_ntoa(a), ntohl(dst), (unsigned)f->count);

    for (int i = 0; i < f->count; ++i) {
        const struct route *r = &f->routes[i];

        if (!route_match(dst, r))
            continue;

        *egress = r->egress_port;
        *hop    = (r->next_hop != 0) ? r->next_hop : dst;
        struct in_addr hopaddr;
        hopaddr.s_addr = *hop;
        DBG("[fib] => matched route %d (prefix=%u) egress=%u hop=%s\n",
            i, r->prefix_length, *egress, inet_ntoa(hopaddr));
        return 1;
    }

    DBG("[fib] => no route matched\n");
    return 0;
}



