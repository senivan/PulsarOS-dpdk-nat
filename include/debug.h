#pragma once
#include <stdio.h>

#ifdef DEBUG_OUTPUT
  #define DBG(...)                                                         \
    do {                                                                   \
      fprintf(stderr, "[%s:%d] ", __func__, __LINE__);                     \
      fprintf(stderr, __VA_ARGS__);                                        \
    } while (0)
#else
  #define DBG(...) do { } while (0)
#endif