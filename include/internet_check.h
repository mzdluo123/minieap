#ifndef _MINIEAP_INTERNET_CHECK_H
#define _MINIEAP_INTERNET_CHECK_H

#include "minieap_common.h"

RESULT internet_check_parse_url(const char* url, char* host, int hostlen, int* port, char* path, int pathlen);
void internet_check_start(void);
void internet_check_stop(void);
typedef RESULT (*internet_check_http_fn)(int* status_out);
void internet_check_set_http_fn(internet_check_http_fn fn);

#endif
