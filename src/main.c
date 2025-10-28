#include <stdio.h>
#include "config.h"

int main(int argc, char **argv){
  if (argc < 3 || strcmp(argv[1],"--")!=0){ fprintf(stderr,"usage: natdpdk -- -c <config.yaml>\n"); return 2; }
  const char *cfg=NULL; for (int i=2;i<argc;i++){ if(!strcmp(argv[i],"-c") && i+1<argc){ cfg=argv[++i]; } }
  if(!cfg){ fprintf(stderr,"config required\n"); return 2; }

  struct app_config c;
  if (cfg_load(cfg,&c) < 0 || cfg_validate(&c) < 0) return 1;
  printf("Config OK. Next step: DPDK init + ports.\n");
  return 0;
}
