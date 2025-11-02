#pragma once
#ifndef CONFIG_H
#define CONFIG_H

#include "app.h"


int cfg_load(const char *path, struct app_config *out);
int cfg_validate(const struct app_config *conf);
static int parse_cidr(const char* cidr, uint32_t *out_ip, uint32_t *out_mask);

#endif