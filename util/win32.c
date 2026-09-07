#include "win32.h"
#include "oscompat.h"
#include "logging.h"

#include <powrprof.h>

static HPOWERNOTIFY g_power_notification;
static volatile LONG g_network_generation;
static volatile LONG g_suspended;
/* Only the main thread advances the generation assigned to a capture handle. */
static LONG g_attempt_generation;

void win32_request_reconnect(void) {
    InterlockedIncrement(&g_network_generation);
}

int win32_reconnect_pending(void) {
    return InterlockedCompareExchange(&g_suspended, 0, 0) ||
        InterlockedCompareExchange(&g_network_generation, 0, 0) != g_attempt_generation;
}

void win32_begin_network_attempt(void) {
    g_attempt_generation = InterlockedCompareExchange(&g_network_generation, 0, 0);
}

static ULONG CALLBACK power_notification(void* context, ULONG type, void* setting) {
    (void)context;
    (void)setting;
    switch (type) {
        case PBT_APMSUSPEND:
            InterlockedExchange(&g_suspended, TRUE);
            win32_request_reconnect();
            break;
        case PBT_APMRESUMEAUTOMATIC:
            /* Every resume, including unattended wake, invalidates the old session. */
            win32_request_reconnect();
            InterlockedExchange(&g_suspended, FALSE);
            break;
        /* RESUMESUSPEND follows RESUMEAUTOMATIC when a user is present.
         * Do not tear down the new session again for the same wake. */
        default:
            break;
    }
    return ERROR_SUCCESS;
}

RESULT win32_power_init(void) {
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params = {power_notification, NULL};
    DWORD error = PowerRegisterSuspendResumeNotification(
        DEVICE_NOTIFY_CALLBACK, &params, &g_power_notification);
    if (error != ERROR_SUCCESS) {
        PR_ERR("注册 Windows 电源通知失败 (%lu)", error);
        return FAILURE;
    }
    return SUCCESS;
}

void win32_power_destroy(void) {
    if (g_power_notification) {
        PowerUnregisterSuspendResumeNotification(g_power_notification);
        g_power_notification = NULL;
    }
}
