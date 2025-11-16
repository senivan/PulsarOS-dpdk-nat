#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <yaml.h>
#include <ctype.h>
#include <netinet/in.h>  

#include "config.h"
#include "nat.h" 

enum { BDF_CANON_LEN = 12 };


static int parse_ip(const char *addr, uint32_t *out) {
    if (!addr || !out) return -1;
    struct in_addr a;
    int rc = inet_pton(AF_INET, addr, &a);
    if (rc != 1) return -1;
    *out = a.s_addr; 
    return 0;
}

static int pcie_is_canon(const char *s) {
    if (!s) return 0;
    if (strlen(s) != BDF_CANON_LEN) return 0;

    for (int i = 0; i < BDF_CANON_LEN; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (i) {
            case 4:
            case 7:
                if (c != ':') return 0;
                break;
            case 10:
                if (c != '.') return 0;
                break;
            case 11:
                if (c < '0' || c > '7') return 0;
                break;
            default:
                if (!isxdigit(c)) return 0;
                break;
        }
    }
    return 1;
}

static int copy_clean_pcie(const char *src,
                           char *dst,
                           size_t dst_sz,
                           char *errbuf,
                           size_t errsz)
{
    if (!src || !dst || dst_sz == 0) {
        if (errbuf && errsz)
            snprintf(errbuf, errsz, "null src/dst");
        return -1;
    }

    char tmp[32];
    size_t n = strnlen(src, sizeof(tmp) - 1);
    memcpy(tmp, src, n);
    tmp[n] = '\0';

    char *p = tmp;
    while (*p && isspace((unsigned char)*p)) p++;

    char *e = p + strlen(p);
    while (e > p && isspace((unsigned char)e[-1])) e--;
    *e = '\0';

    if (!pcie_is_canon(p)) {
        if (errbuf && errsz)
            snprintf(errbuf, errsz, "bad pcie '%s'", p);
        return -1;
    }

    if (dst_sz < (size_t)BDF_CANON_LEN + 1) {
        if (errbuf && errsz)
            snprintf(errbuf, errsz, "dst too small");
        return -1;
    }

    memcpy(dst, p, BDF_CANON_LEN);
    dst[BDF_CANON_LEN] = '\0';
    return 0;
}

static int parse_cidr(const char *cidr,
                      uint32_t *out_ip,
                      uint32_t *out_mask)
{
    if (!cidr || !out_ip || !out_mask) return -1;

    char buf[64];
    size_t len = strlen(cidr);
    if (len == 0 || len >= sizeof(buf)) return -1;

    memcpy(buf, cidr, len + 1);

    char *slash = strchr(buf, '/');
    if (!slash) return -1;

    *slash = '\0';
    const char *prefix_str = slash + 1;

    char *endptr = NULL;
    long prefix = strtol(prefix_str, &endptr, 10);
    if (endptr == prefix_str || prefix < 0 || prefix > 32)
        return -1;

    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;

    uint32_t mask_h = (prefix == 0) ? 0U : (0xFFFFFFFFu << (32 - prefix));
    uint32_t ip_h   = ntohl(a.s_addr);
    uint32_t net_h  = ip_h & mask_h;

    *out_ip   = htonl(net_h);  
    *out_mask = htonl(mask_h);
    return 0;
}

static yaml_node_t *map_get(yaml_document_t *doc,
                            yaml_node_t *map,
                            const char *key)
{
    if (!map || map->type != YAML_MAPPING_NODE || !key)
        return NULL;

    for (yaml_node_pair_t *pair = map->data.mapping.pairs.start;
         pair && pair < map->data.mapping.pairs.top;
         ++pair)
    {
        yaml_node_t *k = yaml_document_get_node(doc, pair->key);
        if (k &&
            k->type == YAML_SCALAR_NODE &&
            k->data.scalar.value &&
            strcmp((char *)k->data.scalar.value, key) == 0)
        {
            return yaml_document_get_node(doc, pair->value);
        }
    }
    return NULL;
}

static const char *scalar(yaml_node_t *node) {
    return (node && node->type == YAML_SCALAR_NODE)
               ? (const char *)node->data.scalar.value
               : NULL;
}

static int parse_bool_scalar(const char *s, int *out)
{
    if (!s || !out) return -1;

    if (!strcasecmp(s, "true") ||
        !strcasecmp(s, "yes")  ||
        !strcmp(s, "1"))
    {
        *out = 1;
        return 0;
    }
    if (!strcasecmp(s, "false") ||
        !strcasecmp(s, "no")    ||
        !strcmp(s, "0"))
    {
        *out = 0;
        return 0;
    }
    return -1;
}
static void debug_print_dnat(const struct app_config *c)
{
    for (uint32_t i = 0; i < c->nat.dnat_count; i++) {
        const struct dnat_rule *r = &c->nat.dnat[i];
        struct in_addr a_ext = { .s_addr = r->ext_ip };
        struct in_addr a_int = { .s_addr = r->int_ip };
        char ext_buf[16], int_buf[16];

        inet_ntop(AF_INET, &a_ext, ext_buf, sizeof(ext_buf));
        inet_ntop(AF_INET, &a_int, int_buf, sizeof(int_buf));

        fprintf(stderr,"[cfg] DNAT[%u]: ext_ip=%s ext_port=%u "
               "int_ip=%s int_port=%u proto=%u\n",
               i,
               ext_buf, (unsigned)r->ext_port,
               int_buf, (unsigned)r->int_port,
               (unsigned)r->proto);
        fprintf(stderr,"\n\n\n\n\n");
    }
}
static void load_dnat_seq(yaml_document_t *doc,
                          yaml_node_t *seq,
                          struct app_config *conf)
{
    if (!seq || seq->type != YAML_SEQUENCE_NODE || !conf)
        return;

    for (yaml_node_item_t *it  = seq->data.sequence.items.start;
         it && it < seq->data.sequence.items.top &&
         conf->nat.dnat_count < NAT_MAX_DNAT_RULES;
         ++it)
    {
        yaml_node_t *item = yaml_document_get_node(doc, *it);
        if (!item || item->type != YAML_MAPPING_NODE)
            continue;

        const char *s_port = scalar(map_get(doc, item, "port"));
        const char *s_to   = scalar(map_get(doc, item, "to"));
        const char *s_protocol = scalar(map_get(doc, item, "protocol"));

        if (!s_port || !s_to)
            continue;

        unsigned ext_port = (unsigned)atoi(s_port);
        if (ext_port == 0 || ext_port > 65535)
            continue;

        char ip[64];
        unsigned prt = 0;
        if (sscanf(s_to, "%63[^:]:%u", ip, &prt) != 2)
            continue;
        if (prt == 0 || prt > 65535)
            continue;

        uint32_t internal_ip = 0;
        if (parse_ip(ip, &internal_ip) != 0) {
            fprintf(stderr,
                    "config: nat.dnat[%u]: invalid ip '%s'\n",
                    conf->nat.dnat_count, ip);
            continue;
        }

        uint8_t proto = 0; 

        if (s_protocol && *s_protocol) {
            if (!strcasecmp(s_protocol, "tcp")) {
                proto = IPPROTO_TCP;
            } else if (!strcasecmp(s_protocol, "udp")) {
                proto = IPPROTO_UDP;
            } else if (!strcasecmp(s_protocol, "icmp")) {
                proto = IPPROTO_ICMP;
            } else if (!strcasecmp(s_protocol, "any") ||
                       !strcasecmp(s_protocol, "all")) {
                proto = 0;  
            } else {
                char *endp = NULL;
                long v = strtol(s_protocol, &endp, 10);
                if (endp != s_protocol && *endp == '\0' &&
                    v >= 0 && v <= 255)
                {
                    proto = (uint8_t)v;
                } else {
                    fprintf(stderr,
                            "config: nat.dnat[%u]: unknown protocol '%s', using 'any'\n",
                            conf->nat.dnat_count, s_protocol);
                    proto = 0;
                }
            }
        }


        struct dnat_rule *r = &conf->nat.dnat[conf->nat.dnat_count];

        r->ext_ip   = conf->public_ip;          
        r->ext_port = (uint32_t)ext_port;       
        r->int_ip   = internal_ip;              
        r->int_port = (uint32_t)prt;            
        r->proto    = proto;                        

        conf->nat.dnat_count++;
    }
}


int cfg_load(const char *path, struct app_config *c)
{
    if (!path || !c) return -1;

    FILE *f = NULL;
    yaml_parser_t parser;
    yaml_document_t doc;
    int parser_inited = 0;
    int doc_loaded    = 0;
    int rc            = -1;

    memset(c, 0, sizeof(*c));
    c->to.tcp_established = DEFAULT_TCP_ESTABLISHED;
    c->to.tcp_transitory  = DEFAULT_TCP_TRANSITORY;
    c->to.udp             = DEFAULT_UDP_TIMEOUT;
    c->to.icmp            = DEFAULT_ICMP_TIMEOUT;

    f = fopen(path, "rb");
    if (!f) {
        perror("config: fopen");
        return -1;
    }

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "config: failed to init yaml parser\n");
        goto fail;
    }
    parser_inited = 1;

    yaml_parser_set_input_file(&parser, f);

    if (!yaml_parser_load(&parser, &doc)) {
        fprintf(stderr, "config: yaml_parser_load failed\n");
        goto fail;
    }
    doc_loaded = 1;

    yaml_node_t *root = yaml_document_get_root_node(&doc);
    if (!root || root->type != YAML_MAPPING_NODE) {
        fprintf(stderr, "config: root node is not a mapping\n");
        goto fail;
    }

    yaml_node_t *pmd = map_get(&doc, root, "pmd");
    const char  *mode = scalar(map_get(&doc, pmd, "mode"));
    if (mode) {
        if (!strcmp(mode, "tap"))            c->pmd = PMD_TAP;
        else if (!strcmp(mode, "af_packet")) c->pmd = PMD_AFPKT;
        else                                 c->pmd = PMD_PHYS;
    } else {
        c->pmd = PMD_PHYS;
    }

    yaml_node_t *ifc = map_get(&doc, root, "interfaces");
    yaml_node_t *lan = map_get(&doc, ifc, "lan");
    yaml_node_t *wan = map_get(&doc, ifc, "wan");

    const char *lan_name = scalar(map_get(&doc, lan, "name"));
    const char *wan_name = scalar(map_get(&doc, wan, "name"));
    const char *lan_addr = scalar(map_get(&doc, lan, "pcie_addr"));
    const char *wan_addr = scalar(map_get(&doc, wan, "pcie_addr"));
    const char *lan_ip   = scalar(map_get(&doc, lan, "ip"));
    const char *wan_ip   = scalar(map_get(&doc, wan, "ip"));

    if (lan_name)
        strncpy(c->lan.name, lan_name, sizeof(c->lan.name));
    if (wan_name)
        strncpy(c->wan.name, wan_name, sizeof(c->wan.name));

    char err[64];

    if (!lan_addr || copy_clean_pcie(lan_addr,
                                     c->lan.pcie_addr,
                                     sizeof(c->lan.pcie_addr),
                                     err, sizeof(err)) != 0)
    {
        fprintf(stderr,
                "config: lan pcie_addr invalid: %s\n",
                lan_addr ? err : "missing");
        goto fail;
    }

    if (!wan_addr || copy_clean_pcie(wan_addr,
                                     c->wan.pcie_addr,
                                     sizeof(c->wan.pcie_addr),
                                     err, sizeof(err)) != 0)
    {
        fprintf(stderr,
                "config: wan pcie_addr invalid: %s\n",
                wan_addr ? err : "missing");
        goto fail;
    }

    if (lan_ip && parse_ip(lan_ip, &c->lan.ip_addr) != 0) {
        fprintf(stderr, "config: interfaces.lan.ip invalid: '%s'\n", lan_ip);
        goto fail;
    }
    if (wan_ip && parse_ip(wan_ip, &c->wan.ip_addr) != 0) {
        fprintf(stderr, "config: interfaces.wan.ip invalid: '%s'\n", wan_ip);
        goto fail;
    }

    yaml_node_t *ips = map_get(&doc, root, "ips");
    const char *lan_cidr = scalar(map_get(&doc, ips, "lan"));
    const char *wan_cidr = scalar(map_get(&doc, ips, "wan"));

    if (lan_cidr && parse_cidr(lan_cidr, &c->lan_net, &c->lan_mask) != 0) {
        fprintf(stderr, "config: ips.lan invalid: '%s'\n", lan_cidr);
        goto fail;
    }
    if (wan_cidr && parse_cidr(wan_cidr, &c->wan_net, &c->wan_mask) != 0) {
        fprintf(stderr, "config: ips.wan invalid: '%s'\n", wan_cidr);
        goto fail;
    }
    c->public_ip = c->wan.ip_addr;

    yaml_node_t *nat = map_get(&doc, root, "nat");
    if (nat) {
        const char *hair = scalar(map_get(&doc, nat, "hairpin"));
        if (hair) {
            int b;
            if (parse_bool_scalar(hair, &b) == 0)
                c->nat.hairpin = (uint8_t)b;
        }

        yaml_node_t *dnat_seq = map_get(&doc, nat, "dnat");
        load_dnat_seq(&doc, dnat_seq, c);
    }

    yaml_node_t *tos = map_get(&doc, root, "timeouts");
    yaml_node_t *tcp = map_get(&doc, tos, "tcp");
    const char *t_est = scalar(map_get(&doc, tcp, "established"));
    const char *t_trn = scalar(map_get(&doc, tcp, "transitory"));
    const char *t_udp = scalar(map_get(&doc, tos, "udp"));
    const char *t_icm = scalar(map_get(&doc, tos, "icmp"));

    if (t_est) c->to.tcp_established = (uint32_t)atoi(t_est);
    if (t_trn) c->to.tcp_transitory  = (uint32_t)atoi(t_trn);
    if (t_udp) c->to.udp             = (uint32_t)atoi(t_udp);
    if (t_icm) c->to.icmp            = (uint32_t)atoi(t_icm);

    yaml_node_t *wrk = map_get(&doc, root, "workers");
    yaml_node_t *lcs = map_get(&doc, wrk, "lcores");
    if (lcs && lcs->type == YAML_SEQUENCE_NODE) {
        for (yaml_node_item_t *i = lcs->data.sequence.items.start;
             i && i < lcs->data.sequence.items.top;
             ++i)
        {
            yaml_node_t *v = yaml_document_get_node(&doc, *i);
            const char  *s = scalar(v);
            if (!s) continue;
            int lc = atoi(s);
            if (lc >= 0 && lc < LCORE_MASK_BITS)
                c->lcore_mask |= (1ULL << lc);
        }
    }

    yaml_node_t *arp = map_get(&doc, root, "arp");
    if (arp) {
        const char *cache_size = scalar(map_get(&doc, arp, "cache_size"));
        const char *reachable  = scalar(map_get(&doc, arp, "reachable_ms"));
        const char *stale      = scalar(map_get(&doc, arp, "stale_ms"));
        const char *request    = scalar(map_get(&doc, arp, "request_interval_ms"));
        const char *retries    = scalar(map_get(&doc, arp, "max_retries"));
        const char *pending    = scalar(map_get(&doc, arp, "max_pending_per_neighbor"));
        const char *on_start   = scalar(map_get(&doc, arp, "gratuitous_on_start"));

        if (cache_size) c->arp.cache_size               = (size_t)atoi(cache_size);
        if (reachable)  c->arp.reachable_ms             = (size_t)atoi(reachable);
        if (stale)      c->arp.stale_ms                 = (size_t)atoi(stale);
        if (request)    c->arp.request_interval_ms      = (size_t)atoi(request);
        if (retries)    c->arp.max_retries              = (size_t)atoi(retries);
        if (pending)    c->arp.max_pending_per_neighbor = (size_t)atoi(pending);
        if (on_start)   c->arp.gratuitous_on_start      = (size_t)atoi(on_start);
    }

    yaml_node_t *met = map_get(&doc, root, "metrics");
    if (met) {
        const char *m_en = scalar(map_get(&doc, met, "enabled"));
        const char *m_ad = scalar(map_get(&doc, met, "addr"));
        const char *m_pt = scalar(map_get(&doc, met, "port"));

        if (m_en) {
            int b;
            if (parse_bool_scalar(m_en, &b) == 0)
                c->use_metrics = b;
        }

        if (m_ad)
            strncpy(c->metrics_addr, m_ad, sizeof(c->metrics_addr));
        if (m_pt)
            c->metrics_port = (uint16_t)atoi(m_pt);
    }

    rc = 0;


fail:
    if (doc_loaded)
        yaml_document_delete(&doc);
    if (parser_inited)
        yaml_parser_delete(&parser);
    if (f)
        fclose(f);
    return rc;
}

int cfg_validate(const struct app_config *c)
{
    int ok = 1;

    if (!c->lan.name[0] || !c->wan.name[0]) {
        fprintf(stderr, "config: interfaces.lan/wan required\n");
        ok = 0;
    }
    if (!c->lan_net || !c->wan_net) {
        fprintf(stderr, "config: ips.lan/ips.wan required\n");
        ok = 0;
    }
    if (!c->public_ip) {
        fprintf(stderr,
                "config: public_ip not set (need ips.public or interfaces.wan.ip)\n");
        ok = 0;
    }

    for (uint32_t i = 0; i < c->nat.dnat_count; i++) {
        const struct dnat_rule *r = &c->nat.dnat[i];
        if (!r->ext_ip || !r->ext_port || !r->int_ip || !r->int_port) {
            fprintf(stderr, "config: nat.dnat[%u] invalid\n", i);
            ok = 0;
        }
    }

    debug_print_dnat(c);

    return ok ? 0 : -1;
}
