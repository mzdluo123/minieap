#ifndef MINIEAP_WIN32_H
#define MINIEAP_WIN32_H

#include "minieap_common.h"

#ifdef _WIN32
RESULT win32_recovery_init(void);
void win32_recovery_destroy(void);

/* Callbacks only signal work; the main thread owns inspection and recovery. */
void win32_request_reconnect(void);
int win32_reconnect_pending(void);
void win32_poll_network(void);
/* Call before opening a fresh capture handle, never after authentication starts. */
void win32_begin_network_attempt(void);
/* Restrict link-state checks to the selected Windows interface. */
void win32_set_interface_luid(unsigned long long luid);
#endif

#endif
