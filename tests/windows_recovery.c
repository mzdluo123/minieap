/* Exercise the real main loop, state machine, scheduler and RJv3 heartbeat.
 * Only OS time/power delivery and adapter I/O are substituted: no real EAP
 * traffic is sent and the host is never suspended. Including these translation
 * units keeps fault injection out of the production API. */
#include "oscompat.h"
#include "net_util.h"
#include "win32.h"
#include "packet_plugin_rjv3_priv.h"
#include "internet_check.h"
#include "packet_plugin_rjv3_keepalive.h"
#include <pcap.h>
#include <iphlpapi.h>
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
static BOOL test_awake(PULONGLONG awake);
static DWORD test_link(PMIB_IF_ROW2 row);
static void test_sleep(DWORD ms);
static DWORD test_wait(HANDLE event, DWORD ms);
static DWORD test_register(DWORD flags, HANDLE recipient, PHPOWERNOTIFY registration);
static DWORD test_unregister(HPOWERNOTIFY registration);
static DWORD test_interface_register(ADDRESS_FAMILY family,
    PIPINTERFACE_CHANGE_CALLBACK callback, PVOID context,
    BOOLEAN initial, HANDLE* registration);
static DWORD test_interface_unregister(HANDLE registration);
static RESULT test_addresses(const char* name, LIST_ELEMENT** list);
static RESULT test_dns(LIST_ELEMENT** list);
static RESULT test_gateway(const char* name, uint8_t* address);
static int test_script(const char* command);
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
#define QueryUnbiasedInterruptTime test_awake
#define GetIfEntry2 test_link
#define Sleep test_sleep
#define WaitForSingleObject test_wait
#define PowerRegisterSuspendResumeNotification test_register
#define PowerUnregisterSuspendResumeNotification test_unregister
#define NotifyIpInterfaceChange test_interface_register
#define CancelMibChangeNotify2 test_interface_unregister
#define win32_prepare_iface test_prepare
#define obtain_iface_mac test_mac
#define obtain_iface_ip_mask test_addresses
#define obtain_dns_list test_dns
#define obtain_iface_ipv4_gateway test_gateway
#define system test_script
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
#include "../packet_plugin/rjv3/packet_plugin_rjv3.c"
#undef PRIV
#include "../packet_plugin/rjv3/packet_plugin_rjv3_priv.c"
#undef PRIV
#undef PowerRegisterSuspendResumeNotification
#undef PowerUnregisterSuspendResumeNotification
#undef NotifyIpInterfaceChange
#undef CancelMibChangeNotify2

typedef enum {
    RESUME_IDLE, RESUME_DURING_OPEN, LINK_CHANGE_IDLE, LINK_POLL_IDLE,
    SILENT_SLEEP, SILENT_STANDBY, CAPTURE_ERROR, SEND_ERROR, WATCHDOG_TIMEOUT, UNIT
} SCENARIO;
typedef struct { int id; int dispatches; } CAPTURE;
static struct {
    SCENARIO scenario;
    ULONGLONG now;
    ULONGLONG suspended_ms;
    int link_down, link_error, no_addresses, address_error, scripts;
    int opens, closes, starts, sends, heartbeats, retries, done;
    int stale_callbacks, filter_failure, nonblock_failure, heartbeat_failure;
    int filter_programs;
    uint8_t last_start[FRAME_BUF_SIZE];
    int last_start_size;
    CAPTURE* active;
    PDEVICE_NOTIFY_CALLBACK_ROUTINE power_callback;
    void* power_context;
    PIPINTERFACE_CHANGE_CALLBACK interface_callback;
    void* interface_context;
} f;
static jmp_buf finished;

static ULONGLONG test_tick(void) { return f.now; }
static BOOL test_awake(PULONGLONG awake) {
    *awake = (f.now - f.suspended_ms) * 10000;
    return TRUE;
}
static DWORD test_link(PMIB_IF_ROW2 row) {
    assert(row->InterfaceLuid.Value == 42);
    if (f.link_error) return ERROR_NOT_FOUND;
    row->AdminStatus = NET_IF_ADMIN_STATUS_UP;
    row->MediaConnectState = f.link_down ? MediaConnectStateDisconnected : MediaConnectStateConnected;
    row->OperStatus = IfOperStatusDormant; /* Not authenticated is not link-down. */
    return NO_ERROR;
}
static void stale_callback(void* unused) { (void)unused; ++f.stale_callbacks; }
static void resume(void) {
    assert(f.power_callback);
    f.power_callback(f.power_context, PBT_APMSUSPEND, NULL);
    f.now += 3600000; /* A long S3/S4 interval: all old deadlines are overdue. */
    f.power_callback(f.power_context, PBT_APMRESUMEAUTOMATIC, NULL);
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
    if (f.scenario <= SILENT_STANDBY && f.scenario != RESUME_DURING_OPEN &&
        f.active->id == 1 && f.active->dispatches == 1) {
        schedule_alarm(1, stale_callback, NULL);
        if (f.scenario == RESUME_IDLE) {
            resume();
        } else if (f.scenario == SILENT_SLEEP) {
            f.now += 10000;
            f.suspended_ms += 10000;
        } else if (f.scenario == SILENT_STANDBY) {
            f.now += 60000; /* S0 process freeze, both OS clocks advance. */
        } else {
            f.link_down = 1;
            if (f.scenario == LINK_CHANGE_IDLE) {
                MIB_IPINTERFACE_ROW row = {0};
                row.InterfaceLuid.Value = 42;
                f.interface_callback(f.interface_context, &row, MibParameterNotification);
            } else {
                f.now += 1000; /* No notification and no IP change. */
            }
        }
    }
    return WAIT_TIMEOUT;
}
static DWORD test_register(DWORD flags, HANDLE recipient, PHPOWERNOTIFY registration) {
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS* params = recipient;
    assert(flags == DEVICE_NOTIFY_CALLBACK);
    f.power_callback = params->Callback;
    f.power_context = params->Context;
    *registration = (HPOWERNOTIFY)1;
    return ERROR_SUCCESS;
}
static DWORD test_unregister(HPOWERNOTIFY registration) {
    assert(registration == (HPOWERNOTIFY)1);
    f.power_callback = NULL;
    return ERROR_SUCCESS;
}
static DWORD test_interface_register(ADDRESS_FAMILY family,
    PIPINTERFACE_CHANGE_CALLBACK callback, PVOID context,
    BOOLEAN initial, HANDLE* registration) {
    assert(family == AF_UNSPEC && !initial);
    f.interface_callback = callback;
    f.interface_context = context;
    *registration = (HANDLE)2;
    return NO_ERROR;
}
static DWORD test_interface_unregister(HANDLE registration) {
    assert(registration == (HANDLE)2);
    f.interface_callback = NULL;
    return NO_ERROR;
}
static RESULT test_addresses(const char* name, LIST_ELEMENT** list) {
    IP_ADDR* address;
    (void)name;
    if (f.address_error) return FAILURE;
    if (f.no_addresses) return SUCCESS;
    address = calloc(1, sizeof(*address));
    assert(address);
    address->family = AF_INET;
    address->ip[0] = 192;
    address->ip[1] = 0;
    address->ip[2] = 2;
    address->ip[3] = 10;
    memset(address->mask, 255, 3);
    insert_data(list, address);
    return SUCCESS;
}
static RESULT test_dns(LIST_ELEMENT** list) {
    insert_data(list, strdup("192.0.2.53"));
    insert_data(list, strdup("192.0.2.54"));
    return SUCCESS;
}
static RESULT test_gateway(const char* name, uint8_t* address) {
    const uint8_t gateway[] = {192, 0, 2, 1};
    (void)name;
    memcpy(address, gateway, sizeof(gateway));
    return SUCCESS;
}
static int test_script(const char* command) {
    MIB_IPINTERFACE_ROW row = {0};
    (void)command;
    ++f.scripts;
    /* A slow DHCP script is awake time, not evidence of suspend. */
    f.now += 60000;
    row.InterfaceLuid.Value = 42;
    f.interface_callback(f.interface_context, &row, MibParameterNotification);
    return 0;
}
static RESULT test_prepare(const char* name, char* out, int size) {
    (void)name;
    win32_set_interface_luid(42);
    f.link_down = 0;
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
    if (f.scenario <= SILENT_STANDBY && capture->id == 1) {
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
    if (f.scenario == RESUME_IDLE || f.scenario == RESUME_DURING_OPEN ||
        f.scenario == LINK_CHANGE_IDLE) {
        f.power_callback(f.power_context, PBT_APMRESUMESUSPEND, NULL);
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
        assert(size <= sizeof(f.last_start));
        memcpy(f.last_start, bytes, size);
        f.last_start_size = size;
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
    win32_recovery_destroy();
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
static void test_link_notifications(void) {
    MIB_IPINTERFACE_ROW row = {0};
    init_fixture(UNIT);
    assert(win32_recovery_init() == SUCCESS);
    win32_set_interface_luid(42);
    win32_poll_network();
    assert(!win32_reconnect_pending());
    /* Neither normal IPv4/IPv6 interface changes nor other NICs invalidate EAP. */
    row.InterfaceLuid.Value = 42;
    row.Family = AF_INET;
    f.interface_callback(NULL, &row, MibParameterNotification);
    row.Family = AF_INET6;
    f.interface_callback(NULL, &row, MibAddInstance);
    f.interface_callback(NULL, &row, MibDeleteInstance);
    win32_poll_network();
    assert(!win32_reconnect_pending());
    row.InterfaceLuid.Value = 7;
    f.interface_callback(NULL, &row, MibDeleteInstance);
    win32_poll_network();
    assert(!win32_reconnect_pending());
    f.link_error = 1;
    f.now += 1000;
    win32_poll_network();
    assert(win32_reconnect_pending());
    destroy_fixture();
    puts("PASS address churn preserves EAP; vanished adapter triggers recovery");
}

static void assert_zero_ipv6_properties(void) {
    const uint8_t types[] = {RJV3_TYPE_LL_IPV6, RJV3_TYPE_LL_IPV6_T, RJV3_TYPE_GLB_IPV6};
    const uint8_t zero[16] = {0};
    int type, i;
    for (type = 0; type < sizeof(types); ++type) {
        for (i = sizeof(ETHERNET_HEADER) + sizeof(EAPOL_HEADER); i + 24 <= f.last_start_size; ++i) {
            const uint8_t prefix[] = {0x1a, 24, 0, 0, 0x13, 0x11, types[type], 18};
            if (memcmp(f.last_start + i, prefix, sizeof(prefix)) == 0) break;
        }
        assert(i + 24 <= f.last_start_size);
        assert(memcmp(f.last_start + i + 8, zero, sizeof(zero)) == 0);
    }
}

static void init_rjv3_session(const char* dhcp_type) {
    char* options[] = {"fixture", "--dhcp-type", (char*)dhcp_type, "--fake-serial", "fixture"};
    init_fixture(UNIT);
    assert(win32_recovery_init() == SUCCESS);
    assert(select_packet_plugin("rjv3") == SUCCESS);
    packet_plugin_load_default_params();
    assert(packet_plugin_process_cmdline_opts(5, options) == SUCCESS);
    assert(get_if_impl()->prepare_interface(get_if_impl()) == SUCCESS);
    assert(eap_state_machine_init() == SUCCESS);
}

static void test_no_addresses(void) {
    init_rjv3_session("0");
    f.no_addresses = 1;
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    assert(f.starts == 1);
    assert_zero_ipv6_properties();
    f.address_error = 1;
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    assert(f.starts == 2);
    assert_zero_ipv6_properties();
    destroy_fixture();
    puts("PASS RJv3 emits Start with zero IPv6 fields before addresses exist or on query failure");
}

static void deliver_success(void) {
    uint8_t bytes[sizeof(FRAME_HEADER) + 16] = {0};
    ETH_EAP_FRAME frame = {0};
    uint8_t key[] = {0, 0, 0x13, 0x11, 1, 12, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4};
    frame.content = bytes;
    frame.buffer_len = sizeof(bytes);
    frame.actual_len = sizeof(FRAME_HEADER) - 1 + sizeof(key);
    frame.header->eapol_hdr.type[0] = EAP_PACKET;
    frame.header->eap_hdr.code[0] = EAP_SUCCESS;
    memcpy(bytes + sizeof(FRAME_HEADER) - 1, key, sizeof(key));
    eap_state_machine_recv_handler(&frame);
}

static void test_dhcp_session(void) {
    init_rjv3_session("1");
    f.no_addresses = 1;
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success(); /* State machine frees the borrowed Success frame here. */
    win32_poll_network();
    assert(!win32_reconnect_pending() && f.scripts == 1 && f.starts == 1);
    f.no_addresses = 0;
    f.now += 5000;
    sched_alarm_poll(); /* Delayed second Start must not read the freed frame. */
    assert(f.starts == 2);
    assert_zero_ipv6_properties();
    deliver_success();
    f.now += 1000;
    sched_alarm_poll();
    assert(f.heartbeats == 1 && f.scripts == 1);
    destroy_fixture();

    init_rjv3_session("2");
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    win32_poll_network();
    assert(!win32_reconnect_pending() && f.starts == 1 && f.scripts == 1);
    f.now += 1000;
    sched_alarm_poll();
    assert(f.heartbeats == 1);
    destroy_fixture();
    puts("PASS delayed double authentication and post-auth DHCP preserve their sessions");
}

static void test_zero_heartbeat(void) {
    PACKET_PLUGIN* plugin;
    rjv3_priv* priv;
    init_fixture(UNIT);
    assert(get_if_impl()->prepare_interface(get_if_impl()) == SUCCESS);
    plugin = packet_plugin_rjv3_new();
    assert(plugin);
    plugin->load_default_params(plugin);
    priv = plugin->priv;
    priv->heartbeat_interval = 0;
    rjv3_start_keepalive(plugin);
    f.now += 3600000;
    sched_alarm_poll();
    sched_alarm_poll();
    assert(f.heartbeats == 0);
    priv->heartbeat_interval = 1;
    rjv3_start_keepalive(plugin);
    f.now += 1000;
    sched_alarm_poll();
    assert(f.heartbeats == 1);
    priv->heartbeat_interval = 0; /* An already queued callback must not send either. */
    f.now += 1000;
    sched_alarm_poll();
    sched_alarm_poll();
    assert(f.heartbeats == 1);
    plugin->destroy(plugin);
    destroy_fixture();
    puts("PASS heartbeat zero disables initial and already scheduled sends");
}
static void test_md5_request_lifetime(void) {
    PACKET_PLUGIN* plugin;
    ETH_EAP_FRAME request = {0}, response = {0};
    uint8_t first[FRAME_BUF_SIZE], second[FRAME_BUF_SIZE];
    int first_len;
    init_fixture(UNIT);
    get_eap_config()->username = strdup("fixture");
    get_eap_config()->password = strdup("fixture-password");
    plugin = packet_plugin_rjv3_new();
    assert(plugin);
    plugin->load_default_params(plugin);
    request.actual_len = request.buffer_len = sizeof(FRAME_HEADER) + 17;
    request.content = calloc(1, request.actual_len);
    assert(request.content);
    request.header->eapol_hdr.type[0] = EAP_PACKET;
    request.header->eap_hdr.code[0] = EAP_REQUEST;
    request.header->eap_hdr.type[0] = MD5_CHALLENGE;
    request.content[sizeof(FRAME_HEADER)] = 16;
    memset(request.content + sizeof(FRAME_HEADER) + 1, 0x5a, 16);
    assert(plugin->on_frame_received(plugin, &request) == SUCCESS);
    memset(first, 0, sizeof(first));
    response.content = first;
    response.buffer_len = sizeof(first);
    response.actual_len = sizeof(FRAME_HEADER);
    response.header->eapol_hdr.type[0] = EAP_PACKET;
    response.header->eap_hdr.code[0] = EAP_RESPONSE;
    response.header->eap_hdr.type[0] = MD5_CHALLENGE;
    assert(plugin->prepare_frame(plugin, &response) == SUCCESS);
    first_len = response.actual_len;
    memset(request.content, 0xa5, request.actual_len);
    free(request.content);
    request.content = NULL;
    memset(second, 0, sizeof(second));
    memcpy(second, first, sizeof(FRAME_HEADER));
    response.content = second;
    response.actual_len = sizeof(FRAME_HEADER);
    assert(plugin->prepare_frame(plugin, &response) == SUCCESS);
    assert(response.actual_len == first_len && memcmp(first, second, first_len) == 0);
    plugin->destroy(plugin);
    destroy_fixture();
    puts("PASS retransmitted MD5 response survives release of caller-owned request");
}

static RESULT http_fail(int* s) { (void)s; return FAILURE; }
static RESULT http_204(int* s) { *s = 204; return SUCCESS; }
static RESULT http_200(int* s) { *s = 200; return SUCCESS; }
static RESULT http_skip(int* s) { *s = 0; return SUCCESS; }

static void test_internet_check(void) {
    PROG_CONFIG* cfg;
    char host[256], path[256];
    int port = 0;

    assert(internet_check_parse_url("http://connect.rom.miui.com/generate_204",
        host, (int)sizeof(host), &port, path, (int)sizeof(path)) == SUCCESS);
    assert(strcmp(host, "connect.rom.miui.com") == 0);
    assert(port == 80);
    assert(strcmp(path, "/generate_204") == 0);
    assert(internet_check_parse_url("https://example.com/x",
        host, (int)sizeof(host), &port, path, (int)sizeof(path)) == FAILURE);
    assert(internet_check_parse_url("http://127.0.0.1:8080/foo",
        host, (int)sizeof(host), &port, path, (int)sizeof(path)) == SUCCESS);
    assert(strcmp(host, "127.0.0.1") == 0);
    assert(port == 8080);
    assert(strcmp(path, "/foo") == 0);

    init_rjv3_session("0");
    cfg = get_program_config();
    cfg->internet_check = 1;
    cfg->internet_check_interval = 1;
    cfg->internet_check_max_fail = 2;
    cfg->internet_check_timeout = 1;
    internet_check_set_http_fn(http_fail);
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    assert(f.starts == 1);
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 1);
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 2);
    internet_check_set_http_fn(NULL);
    destroy_fixture();

    init_rjv3_session("0");
    cfg = get_program_config();
    cfg->internet_check = 1;
    cfg->internet_check_interval = 1;
    cfg->internet_check_max_fail = 2;
    cfg->internet_check_timeout = 1;
    internet_check_set_http_fn(http_204);
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    f.now += 1000;
    sched_alarm_poll();
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 1);
    internet_check_set_http_fn(NULL);
    destroy_fixture();

    init_rjv3_session("0");
    cfg = get_program_config();
    cfg->internet_check = 1;
    cfg->internet_check_interval = 1;
    cfg->internet_check_max_fail = 1;
    cfg->internet_check_timeout = 1;
    internet_check_set_http_fn(http_200);
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 2);
    internet_check_set_http_fn(NULL);
    destroy_fixture();

    init_rjv3_session("0");
    cfg = get_program_config();
    cfg->internet_check = 1;
    cfg->internet_check_interval = 1;
    cfg->internet_check_max_fail = 1;
    cfg->internet_check_timeout = 1;
    cfg->restart_on_logoff = 0;
    internet_check_set_http_fn(http_fail);
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 1);
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 1);
    internet_check_set_http_fn(NULL);
    destroy_fixture();

    init_rjv3_session("0");
    cfg = get_program_config();
    cfg->internet_check = 1;
    cfg->internet_check_interval = 1;
    cfg->internet_check_max_fail = 1;
    cfg->internet_check_timeout = 1;
    internet_check_set_http_fn(http_skip);
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    f.now += 1000;
    sched_alarm_poll();
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 1);
    internet_check_set_http_fn(NULL);
    destroy_fixture();

    init_rjv3_session("0");
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    f.now += 3600000;
    sched_alarm_poll();
    assert(f.starts == 1);
    destroy_fixture();

    init_rjv3_session("0");
    cfg = get_program_config();
    cfg->internet_check = 1;
    cfg->internet_check_interval = 1;
    cfg->internet_check_max_fail = 1;
    cfg->internet_check_timeout = 1;
    internet_check_set_http_fn(http_fail);
    assert(switch_to_state(EAP_STATE_START_SENT, NULL) == SUCCESS);
    deliver_success();
    win32_request_reconnect();
    f.now += 1000;
    sched_alarm_poll();
    assert(f.starts == 1);
    internet_check_set_http_fn(NULL);
    destroy_fixture();

    puts("PASS internet check URL parser, reauth, skip, default-off and reconnect");
}

static ULONG CALLBACK native_probe(void* context, ULONG type, void* setting) {
    (void)context; (void)type; (void)setting;
    return ERROR_SUCCESS;
}
static VOID CALLBACK native_interface_probe(
    void* context, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type) {
    (void)context; (void)row; (void)type;
}
int main(void) {
    HPOWERNOTIFY registration;
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS params = {native_probe, NULL};
    HANDLE interface_registration;
    test_recovery(RESUME_IDLE, "resume after success with silent peer and delayed NIC");
    test_recovery(RESUME_DURING_OPEN, "resume racing with capture open");
    test_recovery(LINK_CHANGE_IDLE, "selected adapter link change after silent wake");
    test_recovery(LINK_POLL_IDLE, "silent link loss with unchanged IP and no notifications");
    test_recovery(SILENT_SLEEP, "sleep detected without power or interface notifications");
    test_recovery(SILENT_STANDBY, "bounded capture wait detects a Modern Standby process freeze");
    test_recovery(CAPTURE_ERROR, "capture error reopens and authenticates");
    test_recovery(SEND_ERROR, "initial send error reopens and authenticates");
    test_recovery(WATCHDOG_TIMEOUT, "authentication timeout rebuilds the session");
    test_timer_recovery();
    test_prepare_cleanup();
    test_plugin_reset();
    test_link_notifications();
    test_no_addresses();
    test_dhcp_session();
    test_zero_heartbeat();
    test_md5_request_lifetime();
    test_internet_check();
    assert(PowerRegisterSuspendResumeNotification(DEVICE_NOTIFY_CALLBACK, &params, &registration) == ERROR_SUCCESS);
    assert(PowerUnregisterSuspendResumeNotification(registration) == ERROR_SUCCESS);
    assert(NotifyIpInterfaceChange(
        AF_UNSPEC, native_interface_probe, NULL, FALSE, &interface_registration) == NO_ERROR);
    assert(CancelMibChangeNotify2(interface_registration) == NO_ERROR);
    puts("PASS native Windows recovery notification registration/unregistration");
    return 0;
}
