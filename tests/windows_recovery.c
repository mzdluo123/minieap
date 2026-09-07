/* Exercise the real main loop, state machine, scheduler and RJv3 heartbeat.
 * Only OS time/power delivery and adapter I/O are substituted: no real EAP
 * traffic is sent and the host is never suspended. Including these translation
 * units keeps fault injection out of the production API. */
#include "oscompat.h"
#include "net_util.h"
#include "win32.h"
#include "packet_plugin_rjv3_priv.h"
#include "packet_plugin_rjv3_keepalive.h"
#include <pcap.h>
#include <powrprof.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


PACKET_PLUGIN* packet_plugin_rjv3_new(void);
static ULONGLONG test_tick(void);
static void test_sleep(DWORD ms);
static DWORD test_wait(HANDLE event, DWORD ms);
static DWORD test_register(DWORD flags, HANDLE recipient, PHPOWERNOTIFY registration);
static DWORD test_unregister(HPOWERNOTIFY registration);
static RESULT test_prepare(const char* name, char* out, int size);
static RESULT test_mac(const char* name, uint8_t* mac);
static pcap_t* test_open(const char* name, int size, int promisc, int timeout, char* error);
static void test_close(pcap_t* pcap);
static int test_compile(pcap_t* pcap, struct bpf_program* program, const char* filter, int optimize, bpf_u_int32 mask);
static int test_filter(pcap_t* pcap, struct bpf_program* program);
static void test_freecode(struct bpf_program* program);
static int test_nonblock(pcap_t* pcap, int nonblock, char* error);
static HANDLE test_event(pcap_t* pcap);
static int test_dispatch(pcap_t* pcap, int count, pcap_handler callback, u_char* user);
static int test_send(pcap_t* pcap, const u_char* bytes, int size);
static char* test_error(pcap_t* pcap);
static void test_break(pcap_t* pcap);

#define GetTickCount64 test_tick
#define Sleep test_sleep
#define WaitForSingleObject test_wait
#define PowerRegisterSuspendResumeNotification test_register
#define PowerUnregisterSuspendResumeNotification test_unregister
#define win32_prepare_iface test_prepare
#define obtain_iface_mac test_mac
#define pcap_open_live test_open
#define pcap_close test_close
#define pcap_compile test_compile
#define pcap_setfilter test_filter
#define pcap_freecode test_freecode
#define pcap_setnonblock test_nonblock
#define pcap_getevent test_event
#define pcap_dispatch test_dispatch
#define pcap_sendpacket test_send
#define pcap_geterr test_error
#define pcap_breakloop test_break
#define main minieap_program_main
#include "../minieap.c"
#undef main
#include "../util/win32.c"
#include "../util/sched_alarm.c"
#include "../if_impl/libpcap/if_impl_libpcap.c"
#undef PRIV
#include "../eap_state_machine.c"
#undef PRIV
#include "../packet_plugin/rjv3/packet_plugin_rjv3_keepalive.c"
#undef PRIV
#undef PowerRegisterSuspendResumeNotification
#undef PowerUnregisterSuspendResumeNotification

typedef enum { RESUME_IDLE, RESUME_DURING_OPEN, CAPTURE_ERROR, SEND_ERROR, WATCHDOG_TIMEOUT, UNIT } SCENARIO;
typedef struct { int id; int dispatches; } CAPTURE;
static struct {
    SCENARIO scenario;
    ULONGLONG now;
    int opens, closes, starts, sends, heartbeats, retries, done;
    int stale_callbacks, filter_failure, nonblock_failure, heartbeat_failure;
    int filter_programs;
    CAPTURE* active;
    PDEVICE_NOTIFY_CALLBACK_ROUTINE callback;
    void* context;
} f;
static jmp_buf finished;

static ULONGLONG test_tick(void) { return f.now; }
static void stale_callback(void* unused) { (void)unused; ++f.stale_callbacks; }
static void resume(void) {
    assert(f.callback);
    f.callback(f.context, PBT_APMSUSPEND, NULL);
    f.now += 3600000; /* A long S3/S4 interval: all old deadlines are overdue. */
    f.callback(f.context, PBT_APMRESUMEAUTOMATIC, NULL);
}
static void test_sleep(DWORD ms) {
    assert(f.active == NULL); /* Release before waiting for NIC readiness. */
    assert(f.stale_callbacks == 0);
    if (f.done) longjmp(finished, 1);
    assert(++f.retries < 12); /* A broken recovery loop must fail, not hang. */
    f.now += ms;
}
static DWORD test_wait(HANDLE event, DWORD ms) {
    (void)event;
    assert(ms <= 100);
    f.now += ms;
    if (f.scenario == RESUME_IDLE && f.active->id == 1 && f.active->dispatches == 1) {
        schedule_alarm(1, stale_callback, NULL);
        resume();
    }
    return WAIT_TIMEOUT;
}
static DWORD test_register(DWORD flags, HANDLE recipient, PHPOWERNOTIFY registration) {
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS* params = recipient;
    assert(flags == DEVICE_NOTIFY_CALLBACK);
    f.callback = params->Callback;
    f.context = params->Context;
    *registration = (HPOWERNOTIFY)1;
    return ERROR_SUCCESS;
}
static DWORD test_unregister(HPOWERNOTIFY registration) {
    assert(registration == (HPOWERNOTIFY)1);
    f.callback = NULL;
    return ERROR_SUCCESS;
}
static RESULT test_prepare(const char* name, char* out, int size) {
    (void)name;
    /* After resume, the NIC takes two further retry intervals to return. */
    if (f.scenario == RESUME_IDLE && f.opens == 1 && f.retries < 3) return FAILURE;
    assert(size > 8);
    strcpy(out, "fixture");
    return SUCCESS;
}
static RESULT test_mac(const char* name, uint8_t* mac) {
    const uint8_t local[] = {2, 0, 0, 0, 0, 1};
    (void)name;
    memcpy(mac, local, sizeof(local));
    return SUCCESS;
}
static pcap_t* test_open(const char* name, int size, int promisc, int timeout, char* error) {
    (void)name; (void)size; (void)promisc; (void)timeout; (void)error;
    assert(!f.active);
    f.active = calloc(1, sizeof(*f.active));
    assert(f.active);
    f.active->id = ++f.opens;
    if (f.scenario == RESUME_DURING_OPEN && f.opens == 1) resume();
    return (pcap_t*)f.active;
}
static void test_close(pcap_t* pcap) {
    assert(pcap == (pcap_t*)f.active);
    free(f.active);
    f.active = NULL;
    ++f.closes;
}
static int test_compile(pcap_t* pcap, struct bpf_program* program, const char* filter, int optimize, bpf_u_int32 mask) {
    (void)pcap; (void)filter; (void)optimize; (void)mask;
    memset(program, 0, sizeof(*program));
    ++f.filter_programs;
    return 0;
}
static int test_filter(pcap_t* pcap, struct bpf_program* program) {
    (void)pcap; (void)program;
    return f.filter_failure ? -1 : 0;
}
static void test_freecode(struct bpf_program* program) { (void)program; --f.filter_programs; }
static int test_nonblock(pcap_t* pcap, int nonblock, char* error) {
    (void)pcap; (void)error;
    assert(nonblock);
    return f.nonblock_failure ? -1 : 0;
}
static HANDLE test_event(pcap_t* pcap) { return (HANDLE)pcap; }
static int test_dispatch(pcap_t* pcap, int count, pcap_handler callback, u_char* user) {
    CAPTURE* capture = (CAPTURE*)pcap;
    (void)count;
    if (f.scenario == UNIT) return PCAP_ERROR;
    if (f.scenario == CAPTURE_ERROR && capture->id == 1) return PCAP_ERROR;
    if (f.scenario == WATCHDOG_TIMEOUT && capture->id == 1) return 0;
    if (f.scenario == RESUME_IDLE && capture->id == 1) {
        FRAME_HEADER header = {0};
        struct pcap_pkthdr packet = {0};
        header.eapol_hdr.type[0] = EAP_PACKET;
        header.eap_hdr.code[0] = EAP_SUCCESS;
        packet.caplen = packet.len = sizeof(header);
        callback(user, &packet, (const u_char*)&header);
        ++capture->dispatches;
        return 1;
    }
    assert(capture->id == 2);
    /* A later user-presence notification must not cancel the newly started
     * authentication for the same resume. */
    if (f.scenario == RESUME_IDLE || f.scenario == RESUME_DURING_OPEN) {
        f.callback(f.context, PBT_APMRESUMESUSPEND, NULL);
        assert(!win32_reconnect_pending());
    }
    f.done = 1;
    win32_request_reconnect();
    return 0;
}
static int test_send(pcap_t* pcap, const u_char* bytes, int size) {
    const FRAME_HEADER* header = (const FRAME_HEADER*)bytes;
    const uint8_t broadcast[] = {1, 0x80, 0xc2, 0, 0, 3};
    assert(pcap == (pcap_t*)f.active && size >= sizeof(ETHERNET_HEADER) + sizeof(EAPOL_HEADER));
    ++f.sends;
    if (header->eapol_hdr.type[0] == EAPOL_START) {
        assert(memcmp(header->eth_hdr.dest_mac, broadcast, sizeof(broadcast)) == 0);
        if (f.scenario == SEND_ERROR && f.active->id == 1) return -1;
        ++f.starts;
    } else {
        assert(header->eapol_hdr.type[0] == EAPOL_RJ_PROPRIETARY_KEEPALIVE);
        if (f.heartbeat_failure) return -1;
        ++f.heartbeats;
    }
    return 0;
}
static char* test_error(pcap_t* pcap) { (void)pcap; return "injected adapter failure"; }
static void test_break(pcap_t* pcap) { (void)pcap; }

static void init_fixture(SCENARIO scenario) {
    memset(&f, 0, sizeof(f));
    f.scenario = scenario;
    win32_begin_network_attempt();
    load_default_params();
    set_log_destination(LOG_TO_CONSOLE);
    start_log();
    get_program_config()->ifname = strdup("fixture");
    if (scenario == WATCHDOG_TIMEOUT) {
        get_program_config()->max_retries = 2;
        get_program_config()->stage_timeout = 1;
    }
    init_if_impl_list();
    assert(select_if_impl("libpcap") == SUCCESS);
    init_packet_plugin_list();
    assert(init_if() == SUCCESS);
    assert(sched_alarm_init() == SUCCESS);
}
static void destroy_fixture(void) {
    win32_power_destroy();
    packet_plugin_destroy();
    eap_state_machine_destroy();
    sched_alarm_destroy();
    free_if_impl();
    free_config();
    close_log();
}
static void test_recovery(SCENARIO scenario, const char* label) {
    init_fixture(scenario);
    if (setjmp(finished) == 0) {
        run_windows_network();
        assert(!"recovery loop returned unexpectedly");
    }
    assert(f.opens == 2 && f.closes == 2 && f.filter_programs == 0);
    if (scenario == WATCHDOG_TIMEOUT) {
        assert(f.starts == get_program_config()->max_retries + 1);
    } else {
        assert(f.starts == ((scenario == RESUME_DURING_OPEN || scenario == SEND_ERROR) ? 1 : 2));
    }
    assert(f.stale_callbacks == 0);
    destroy_fixture();
    printf("PASS %s\n", label);
}
static void reschedule(void* count) {
    ++*(int*)count;
    schedule_alarm(60, reschedule, count);
}
static void invalidate(void* unused) { (void)unused; win32_request_reconnect(); }
static void test_timer_recovery(void) {
    int count = 0;
    init_fixture(UNIT);
    schedule_alarm(60, reschedule, &count);
    f.now = 3600000;
    sched_alarm_poll();
    assert(count == 1);
    sched_alarm_poll();
    assert(count == 1); /* No catch-up storm after a long suspension. */
    sched_alarm_destroy();
    schedule_alarm(0, invalidate, NULL);
    schedule_alarm(0, stale_callback, NULL);
    sched_alarm_poll();
    assert(f.stale_callbacks == 0); /* Stop dispatch when a callback invalidates the session. */
    sched_alarm_destroy();
    win32_begin_network_attempt();
    sched_alarm_poll();
    assert(f.stale_callbacks == 0);
    destroy_fixture();
    puts("PASS overdue timers and invalidation during timer dispatch");
}
static void test_prepare_cleanup(void) {
    IF_IMPL* impl;
    init_fixture(UNIT);
    impl = get_if_impl();
    f.filter_failure = 1;
    assert(impl->prepare_interface(impl) == FAILURE);
    assert(!f.active && f.filter_programs == 0);
    f.filter_failure = 0;
    f.nonblock_failure = 1;
    assert(impl->prepare_interface(impl) == FAILURE);
    assert(!f.active && f.filter_programs == 0);
    f.nonblock_failure = 0;
    assert(impl->prepare_interface(impl) == SUCCESS);
    assert(impl->start_capture(impl) == FAILURE);
    impl->release_interface(impl);
    impl->release_interface(impl);
    assert(f.opens == 3 && f.closes == 3);
    destroy_fixture();
    puts("PASS failed capture preparation releases resources before retry");
}
static void test_plugin_reset(void) {
    PACKET_PLUGIN* plugin;
    rjv3_priv* priv;
    IF_IMPL* impl;
    init_fixture(UNIT);
    impl = get_if_impl();
    assert(impl->prepare_interface(impl) == SUCCESS);
    plugin = packet_plugin_rjv3_new();
    assert(plugin);
    plugin->load_default_params(plugin);
    priv = plugin->priv;
    rjv3_start_keepalive(plugin);
    priv->secondary_auth_alarm_id = schedule_alarm(1, stale_callback, NULL);
    plugin->reset_session(plugin);
    f.now += 3600000;
    sched_alarm_poll();
    assert(f.heartbeats == 0 && f.stale_callbacks == 0);
    rjv3_start_keepalive(plugin);
    f.now += 1000;
    sched_alarm_poll();
    assert(f.heartbeats == 1);
    plugin->reset_session(plugin);
    f.now += 3600000;
    sched_alarm_poll();
    assert(f.heartbeats == 1); /* Repeating heartbeat was cancelled too. */
    rjv3_start_keepalive(plugin);
    f.heartbeat_failure = 1;
    f.now += 1000;
    sched_alarm_poll();
    assert(win32_reconnect_pending()); /* Failure returns to recovery rather than exiting. */
    plugin->destroy(plugin);
    destroy_fixture();
    puts("PASS initial/repeating heartbeat, DHCP cancellation and heartbeat failure");
}
static ULONG CALLBACK native_probe(void* context, ULONG type, void* setting) {
    (void)context; (void)type; (void)setting;
    return ERROR_SUCCESS;
}
int main(void) {
    HPOWERNOTIFY registration;
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params = {native_probe, NULL};
    test_recovery(RESUME_IDLE, "resume after success with silent peer and delayed NIC");
    test_recovery(RESUME_DURING_OPEN, "resume racing with capture open");
    test_recovery(CAPTURE_ERROR, "capture error reopens and authenticates");
    test_recovery(SEND_ERROR, "initial send error reopens and authenticates");
    test_recovery(WATCHDOG_TIMEOUT, "authentication timeout rebuilds the session");
    test_timer_recovery();
    test_prepare_cleanup();
    test_plugin_reset();
    assert(PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &params, &registration) == ERROR_SUCCESS);
    assert(PowerUnregisterSuspendResumeNotification(registration) == ERROR_SUCCESS);
    puts("PASS native Windows power notification registration/unregistration");
    return 0;
}
