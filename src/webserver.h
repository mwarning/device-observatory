#ifndef _PARSE_WEBSERVER_H_
#define _PARSE_WEBSERVER_H_

#include <sys/select.h> 

int webserver_start(const char path[], int port);
void webserver_before_select(fd_set *rs, fd_set *ws, fd_set *es, int *max_fd);
void webserver_after_select();

#endif // _PARSE_WEBSERVER_H_