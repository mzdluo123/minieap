#include "win32.h"
#include "oscompat.h"
#include "logging.h"

#include <iphlpapi.h>
#include <powrprof.h>

static HPOWERNOTIFY g_power_notification;
static HANDLE g_interface_notification;
static volatile LONG g_link_check_requested;
static volatile LONG g_network_generation;
static volatile LONG g_suspended;
static DECLSPEC_ALIGN(8) volatile LONG64 g_interface_luid;
/* Only the main thread advances the generation assigned to a capture handle. */
static LONG g_attempt_generation;
static ULONGLONG g_last_link_check;
static ULONGLONG g_last_tick;
static ULONGLONG g_last_awake;
static int g_clock_valid;

void win32_request_reconnect(void) {
    InterlockedIncrement(&g_network_generation);
}

int win32_reconnect_pending(void) {
    return InterlockedCompareExchange(&g_suspended, 0, 0) ||
        InterlockedCompareExchange(&g_network_generation, 0, 0) != g_attempt_generation;
}

void win32_begin_network_attempt(void) {
    g_attempt_generation = InterlockedCompareExchange(&g_network_generation, 0, 0);
    InterlockedExchange(&g_link_check_requested, TRUE);
    g_last_tick = GetTickCount64();
    g_clock_valid = QueryUnbiasedInterruptTime(&g_last_awake);
}

void win32_set_interface_luid(unsigned long long luid) {
    InterlockedExchange64(&g_interface_luid, (LONG64)luid);
    InterlockedExchange(&g_link_check_requested, TRUE);
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
        case PBT_APMRESUMESUSPEND:
            /* Normally follows RESUMEAUTOMATIC: only recover here if we are
             * still suspended, so one wake cannot tear down a new session twice. */
            if (InterlockedExchange(&g_suspended, FALSE)) win32_request_reconnect();
            break;
    }
    return ERROR_SUCCESS;
}

static VOID CALLBACK interface_notification(
    void* context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type) {
    LONG64 selected;
    (void)context;
    (void)type;
    if (!row) return;
    selected = InterlockedCompareExchange64(&g_interface_luid, 0, 0);
    if (selected && row->InterfaceLuid.Value == (ULONG64)selected) {
        /* DHCP and IPv6 changes are not evidence of an invalid EAP session.
         * Query current media state on the owner thread instead. */
        InterlockedExchange(&g_link_check_requested, TRUE);
    }
}

void win32_poll_network(void) {
    ULONGLONG now = GetTickCount64(), awake;
    MIB_IF_ROW2 row = {0};
    if (win32_reconnect_pending()) return;

    /* Unlike GetTickCount64, unbiased time excludes sleep. This also catches
     * resumes whose power callback was not delivered, without treating a long
     * synchronous DHCP script or wall-clock adjustment as a suspend. */
    if (QueryUnbiasedInterruptTime(&awake)) {
        if (g_clock_valid && now >= g_last_tick && awake >= g_last_awake &&
            now - g_last_tick > (awake - g_last_awake) / 10000 + 2000) {
            PR_WARN("检测到未通知的系统睡眠，将重建网络会话");
            win32_request_reconnect();
        }
        g_last_awake = awake;
        g_last_tick = now;
        g_clock_valid = TRUE;
    } else {
        g_clock_valid = FALSE;
    }
    if (win32_reconnect_pending()) return;
    if (!InterlockedExchange(&g_link_check_requested, FALSE) &&
        now - g_last_link_check < 1000) return;
    g_last_link_check = now;
    row.InterfaceLuid.Value = (ULONG64)InterlockedCompareExchange64(&g_interface_luid, 0, 0);
    if (!row.InterfaceLuid.Value) return;
    if (GetIfEntry2(&row) != NO_ERROR ||
        row.AdminStatus != NET_IF_ADMIN_STATUS_UP ||
        row.MediaConnectState != MediaConnectStateConnected) {
        PR_WARN("认证网卡已断开或不可用，将重建网络会话");
        win32_request_reconnect();
    }
}

RESULT win32_recovery_init(void) {
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params = {power_notification, NULL};
    DWORD error = PowerRegisterSuspendResumeNotification(
        DEVICE_NOTIFY_CALLBACK, &params, &g_power_notification);
    if (error != ERROR_SUCCESS) {
        PR_ERR("注册 Windows 电源通知失败 (%lu)", error);
        return FAILURE;
    }
    error = NotifyIpInterfaceChange(
        AF_UNSPEC, interface_notification, NULL, FALSE, &g_interface_notification);
    if (error != NO_ERROR) {
        PR_ERR("注册 Windows 接口变化通知失败 (%lu)", error);
        PowerUnregisterSuspendResumeNotification(g_power_notification);
        g_power_notification = NULL;
        return FAILURE;
    }
    return SUCCESS;
}

void win32_recovery_destroy(void) {
    if (g_interface_notification) {
        CancelMibChangeNotify2(g_interface_notification);
        g_interface_notification = NULL;
    }
    if (g_power_notification) {
        PowerUnregisterSuspendResumeNotification(g_power_notification);
        g_power_notification = NULL;
    }
}
