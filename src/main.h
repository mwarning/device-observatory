#ifndef _MAIN_H_
#define _MAIN_H_


#ifdef DEBUG
#define debug(...) printf( __VA_ARGS__)
#else
#define debug(...)
#endif

#define UNUSED(expr) do { (void)(expr); } while (0)

#endif // _MAIN_H_