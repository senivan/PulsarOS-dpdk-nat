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

static int parse_cidr(const char* cidr, uint32_t *out_ip, uint32_t *out_mask){
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

static yaml_node_t* map_get(yaml_document_t *doc, yaml_node_t *map, const char *key){
    if(!map || map->type!=YAML_MAPPING_NODE) return NULL;
    for (yaml_node_pair_t *pair=map->data.mapping.pairs.start; 
            pair && pair < map->data.mapping.pairs.top; 
            ++pair){
        yaml_node_t *k = yaml_document_get_node(doc, pair->key);
        if(k && k->type == YAML_SCALAR_NODE && k->data.scalar.value
            && strcmp((char*)k->data.scalar.value,key) == 0)
            return yaml_document_get_node(doc, pair->value);
    }
    return NULL;
}

static const char* scalar(yaml_node_t *node){
    return (node && node->type == YAML_SCALAR_NODE) ? (const char * )node->data.scalar.value:NULL;
}

static void load_dnat_seq(yaml_document_t *doc, yaml_node_t *seq, struct app_config *conf){
    if (!seq || seq ->type!=YAML_SEQUENCE_NODE) return;
    for (yaml_node_item_t *it = seq->data.sequence.items.start; it && it < seq -> data.sequence.items.top && conf->dnat_cnt < 64; ++it){
        yaml_node_t *item  = yaml_document_get_node(doc, *it);
        const char *s_port = scalar(map_get(doc,item,"port"));
        const char *s_to   = scalar(map_get(doc,item,"to"));
        if(!s_port || !s_to) continue;
        unsigned ext = atoi(s_port); char ip[64]; unsigned prt=0;
        if (sscanf(s_to,"%63[^:]:%u",ip,&prt) == 2){
            conf->dnat[conf->dnat_cnt].egr_port  = htons((uint16_t)ext);
            conf->dnat[conf->dnat_cnt].ing_port = htons((uint16_t)prt);
            parse_ip(ip, &conf->dnat[conf->dnat_cnt].internal_ip);
            conf->dnat_cnt++;
        }
    }
}

static void load_snat_seq(yaml_document_t *doc, yaml_node_t *seq, struct app_config *conf){
  if(!seq || seq->type!=YAML_SEQUENCE_NODE) return;
  for(yaml_node_item_t *it = seq->data.sequence.items.start; it && it < seq -> data.sequence.items.top && conf->snat_cnt < 64; ++it){
    yaml_node_t *item = yaml_document_get_node(doc,*it);
    const char *from  = scalar(map_get(doc,item,"from"));
    const char *out   = scalar(map_get(doc,item,"out"));
    const char *to    = scalar(map_get(doc,item,"to"));

    if(!from) continue;
    parse_cidr(from, &conf->snat[conf->snat_cnt].int_net, &conf->snat[conf->snat_cnt].int_mask);
    if(out) {
        strncpy(conf->snat[conf->snat_cnt].out_if,out, sizeof(conf->snat[conf->snat_cnt].out_if));
    }
    to ? parse_ip(to, &conf->snat[conf->snat_cnt].ext_ip) : conf->public_ip;
    conf->snat_cnt++;
  }
}

int cfg_load(const char *path, struct app_config *c){
    memset(c, 0, sizeof(*c));
    c->to.tcp_established = 300;
    c->to.tcp_transitory  = 30;
    c->to.udp             = 30;
    c->to.icmp            = 10;

    FILE *f = fopen(path, "rb"); if(!f) return -1;
    yaml_parser_t parser;
    yaml_document_t doc;
    if(!yaml_parser_initialize(&parser)){ fclose(f); return -2; }
    yaml_parser_set_input_file(&parser,f);
    if(!yaml_parser_load(&parser,&doc)){ yaml_parser_delete(&parser); fclose(f); return -3; }
    yaml_parser_delete(&parser); fclose(f);

    yaml_node_t *root=yaml_document_get_root_node(&doc);
    if(!root || root->type!=YAML_MAPPING_NODE){ yaml_document_delete(&doc); return -4; }

    // pmd.mode
    const char *mode=scalar(map_get(&doc,map_get(&doc,root,"pmd"),"mode"));
    if(mode){ if(!strcmp(mode,"tap")) c->pmd=PMD_TAP; else if(!strcmp(mode,"af_packet")) c->pmd=PMD_AFPKT; else c->pmd=PMD_PHYS; }

    // interfaces
    yaml_node_t *ifc=map_get(&doc,root,"interfaces");
    const char *lan=scalar(map_get(&doc,ifc,"lan"));
    const char *wan=scalar(map_get(&doc,ifc,"wan"));
    if(lan) strncpy(c->lan_name,lan,sizeof(c->lan_name));
    if(wan) strncpy(c->wan_name,wan,sizeof(c->wan_name));

    // ips
    yaml_node_t *ips=map_get(&doc,root,"ips");
    const char *lan_cidr=scalar(map_get(&doc,ips,"lan"));
    const char *wan_cidr=scalar(map_get(&doc,ips,"wan"));
    const char *pub_ip  =scalar(map_get(&doc,ips,"public"));
    if(lan_cidr) parse_cidr(lan_cidr,&c->lan_net,&c->lan_mask);
    if(wan_cidr) parse_cidr(wan_cidr,&c->wan_net,&c->wan_mask);
    if(pub_ip)   parse_ip(pub_ip, &c->public_ip);

    // nat
    yaml_node_t *nat=map_get(&doc,root,"nat");
    const char *hair=scalar(map_get(&doc,nat,"hairpin"));
    c->hairpin = hair && (!strcmp(hair,"true")||!strcmp(hair,"yes")||!strcmp(hair,"1"));
    load_snat_seq(&doc,map_get(&doc,nat,"snat"),c);
    load_dnat_seq(&doc,map_get(&doc,nat,"dnat"),c);

    // timeouts
    yaml_node_t *tos=map_get(&doc,root,"timeouts");
    yaml_node_t *tcp=map_get(&doc,tos,"tcp");
    const char *t_est=scalar(map_get(&doc,tcp,"established"));
    const char *t_trn=scalar(map_get(&doc,tcp,"transitory"));
    const char *t_udp=scalar(map_get(&doc,tos,"udp"));
    const char *t_icm=scalar(map_get(&doc,tos,"icmp"));
    if(t_est) c->to.tcp_established=atoi(t_est);
    if(t_trn) c->to.tcp_transitory =atoi(t_trn);
    if(t_udp) c->to.udp=atoi(t_udp);
    if(t_icm) c->to.icmp=atoi(t_icm);

    // workers
    yaml_node_t *wrk=map_get(&doc,root,"workers");
    yaml_node_t *lcs=map_get(&doc,wrk,"lcores");
    if(lcs && lcs->type==YAML_SEQUENCE_NODE){
    for(yaml_node_item_t *i=lcs->data.sequence.items.start; i && i<lcs->data.sequence.items.top; ++i){
        yaml_node_t *v=yaml_document_get_node(&doc,*i);
        const char *s=scalar(v); if(!s) continue; int lc=atoi(s); if(lc>=0 && lc<64) c->lcore_mask |= (1ULL<<lc);
    }
    }

    // metrics
    yaml_node_t *met=map_get(&doc,root,"metrics");
    const char *m_en=scalar(map_get(&doc,met,"enabled"));
    const char *m_ad=scalar(map_get(&doc,met,"addr"));
    const char *m_pt=scalar(map_get(&doc,met,"port"));
    c->use_metrics = m_en && (!strcmp(m_en,"true")||!strcmp(m_en,"yes")||!strcmp(m_en,"1"));
    if(m_ad) strncpy(c->metrics_addr,m_ad,sizeof(c->metrics_addr));
    if(m_pt) c->metrics_port=atoi(m_pt);

    yaml_document_delete(&doc);
    return 0;
}

int cfg_validate(const struct app_config *c){
  int ok=1;
  if(!c->lan_name[0] || !c->wan_name[0]){ fprintf(stderr,"config: interfaces.lan/wan required\n"); ok=0; }
  if(!c->lan_net|| !c->wan_net){ fprintf(stderr,"config: ips.lan/ips.wan required\n"); ok=0; }
  if(!c->public_ip && c->snat_cnt==0){ fprintf(stderr,"config: ips.public or nat.snat[].to required\n"); ok=0; }
  for(int i=0;i<c->dnat_cnt;i++){
    if(!c->dnat[i].ing_port || !c->dnat[i].egr_port || !c->dnat[i].internal_ip){
      fprintf(stderr,"config: dnat[%d] invalid\n", i); ok=0;
    }
  }
  return ok?0:-1;
}