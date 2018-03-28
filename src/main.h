#ifndef _MAIN_H_
#define _MAIN_H_

#include <time.h>

#ifdef DEBUG
#define debug(...) printf( __VA_ARGS__)
#else
#define debug(...)
#endif

#define UNUSED(expr) do { (void)(expr); } while (0)

extern time_t g_now;

#endif // _MAIN_H_