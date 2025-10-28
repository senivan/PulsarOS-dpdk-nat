#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <yaml.h>
#include "config.h"

static uint32_t parse_ip(const char *addr, uint32_t* out){
    struct in_addr a;
    int rc = inet_pton(AF_INET, addr, &a);
    if(rc != 1) return -1;
    *out = a.s_addr;
    return 0;
}

static int parse_cidr(const char* cidr, uint32_t out_ip, uint32_t out_mask){
    char buf[64];
    strncpy(buf, cidr, sizeof(buf));
    buf[sizeof(buf) - 1] = 0;

    char *slash = strchr(buf, '/');
    int pfx = 32;
    if(slash){
        *slash = 0;
        char *end = NULL;
        long v = strtol(slash+1, &end, 10);
        if(!end || *end != '\0' || v < 0 || v > 32) return -1;
        pfx = (int)v;
    }

    uint32_t ip;
    if (parse_ip(buf, &ip) != 0) return -1;

    uint32_t host_mask = (pfx == 0) ? 0u : (~0u << (32 - pfx));
    *out_ip = ip;
    *out_mask = host_mask;
    return 0;
}