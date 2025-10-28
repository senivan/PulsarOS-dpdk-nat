#pragma once
#ifndef CONFIG_H
#define CONFIG_H

#include "app.h"


int cfg_load(const char *path, struct app_config *out);
int cfg_validate(const struct app_config *conf);

#endif