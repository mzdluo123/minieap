#ifndef MINIEAP_WIN32_H
#define MINIEAP_WIN32_H

#include "minieap_common.h"

#ifdef _WIN32
RESULT win32_power_init(void);
void win32_power_destroy(void);

/* Notifications only invalidate the session; the main thread owns recovery. */
void win32_request_reconnect(void);
int win32_reconnect_pending(void);
/* Call before opening a fresh capture handle, never after authentication starts. */
void win32_begin_network_attempt(void);
#endif

#endif
