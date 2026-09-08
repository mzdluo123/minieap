/*
 * Implement packet sending/receiving by libpcap.
 * It's portable but the program size (+ libpcap)
 * is considerably larger.
 */
#include "if_impl.h"
#include "minieap_common.h"
#include "logging.h"
#include "sched_alarm.h"
#include "oscompat.h"
#include "net_util.h"
#include "win32.h"

#include <pcap.h>
#include <stdlib.h>
#ifndef PCAP_ERROR
#define PCAP_ERROR -1
#endif
#ifndef PCAP_ERROR_BREAK
#define PCAP_ERROR_BREAK -2
#endif

typedef struct _if_impl_libpcap_priv {
    int promisc;
    char ifname[IFNAMSIZ];
    short proto;
    pcap_t* pcapdev;
    void (*handler)(ETH_EAP_FRAME* frame); /* Packet handler */
} libpcap_priv;

#define PRIV ((libpcap_priv*)(this->priv))

static void libpcap_packet_handler(uint8_t* vthis, const struct pcap_pkthdr* pkthdr, const uint8_t* packet) {
    ETH_EAP_FRAME _frame;
    IF_IMPL* this = (IF_IMPL*)vthis;

#ifdef _WIN32
    if (win32_reconnect_pending()) return;
#endif
    _frame.buffer_len = _frame.actual_len = pkthdr->caplen;
    _frame.content = (uint8_t*)packet;
    PRIV->handler(&_frame);
}

RESULT libpcap_set_ifname(struct _if_impl* this, const char* ifname) {
    if (strlen(ifname) >= sizeof(PRIV->ifname)) return FAILURE;
    strcpy(PRIV->ifname, ifname);
    return SUCCESS;
}

RESULT libpcap_get_ifname(struct _if_impl* this, char* buf, int buflen) {
    if (buflen <= strnlen(PRIV->ifname, IFNAMSIZ)) {
        return FAILURE;
    }
    strncpy(buf, PRIV->ifname, buflen);
    return SUCCESS;
}

RESULT libpcap_setup_capture_params(struct _if_impl* this, unsigned short eth_protocol, int promisc) {
    PRIV->proto = eth_protocol;
    PRIV->promisc = promisc;
    return SUCCESS;
}

static void libpcap_print_devices(void) {
    pcap_if_t* alldevs = NULL;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        PR_ERR("%s", errbuf);
        return;
    }
    for (d = alldevs; d; d = d->next) {
        PR_INFO("  %s (%s)", d->name, d->description ? d->description : "");
    }
    pcap_freealldevs(alldevs);
}

void if_impl_print_pcap_devices(void) {
    libpcap_print_devices();
}

static void libpcap_release_interface(struct _if_impl* this) {
    if (PRIV->pcapdev) {
        pcap_close(PRIV->pcapdev);
        PRIV->pcapdev = NULL;
    }
}

RESULT libpcap_prepare_interface(struct _if_impl* this) {
    char _err_buf[PCAP_ERRBUF_SIZE] = {0};
    char _filter_str[30] = {0};
    struct bpf_program _bpf;
    const char* name = PRIV->ifname;
#ifdef _WIN32
    char pcap_name[IFNAMSIZ];
#endif
    libpcap_release_interface(this);
#ifdef _WIN32
    if (win32_reconnect_pending() ||
        IS_FAIL(win32_prepare_iface(PRIV->ifname, pcap_name, sizeof(pcap_name)))) {
        return FAILURE;
    }
    name = pcap_name;
#endif
    PRIV->pcapdev = pcap_open_live(name, FRAME_BUF_SIZE, PRIV->promisc, 100, _err_buf);
    if (PRIV->pcapdev == NULL) {
        PR_ERR("libpcap 打开设备失败： %s", _err_buf);
        return FAILURE;
    }

    sprintf(_filter_str, "ether proto 0x%hx", PRIV->proto);
    if (pcap_compile(PRIV->pcapdev, &_bpf, _filter_str, 0, 0) < 0) {
        PR_ERR("libpcap 过滤器编译失败： %s", pcap_geterr(PRIV->pcapdev));
        goto fail;
    }
    int r = pcap_setfilter(PRIV->pcapdev, &_bpf);
    pcap_freecode(&_bpf);
    if (r < 0) {
        PR_ERR("libpcap 过滤器设置失败： %s", pcap_geterr(PRIV->pcapdev));
        goto fail;
    }
#ifdef _WIN32
    /* Readiness waits below are bounded even with no traffic or a stale NIC.
     * The pcap read timeout alone does not guarantee that dispatch returns. */
    if (pcap_setnonblock(PRIV->pcapdev, 1, _err_buf) < 0) {
        PR_ERR("libpcap 非阻塞设置失败： %s", _err_buf);
        goto fail;
    }
#endif
    return SUCCESS;
fail:
    libpcap_release_interface(this);
    return FAILURE;
}

RESULT libpcap_start_capture(struct _if_impl* this) {
    if (!PRIV->pcapdev) return FAILURE;
#ifdef _WIN32
    HANDLE ready = pcap_getevent(PRIV->pcapdev);
    if (!ready || ready == INVALID_HANDLE_VALUE) {
        PR_ERR("无法获取 Npcap 捕获事件");
        return FAILURE;
    }
    while (!win32_reconnect_pending()) {
        ULONGLONG wait_started = GetTickCount64();
        DWORD wait = WaitForSingleObject(ready, 100);
        if (wait == WAIT_FAILED) {
            PR_ERR("等待 Npcap 捕获事件失败 (%lu)", GetLastError());
            return FAILURE;
        }
        /* Modern Standby may freeze this process without a system suspend.
         * Measure only the bounded wait, not DHCP scripts in packet callbacks. */
        if (GetTickCount64() - wait_started > 30000) {
            PR_WARN("捕获等待期间进程长时间暂停，将重建网络会话");
            win32_request_reconnect();
        }
        win32_poll_network();
        if (win32_reconnect_pending()) break;
        /* Bound each batch so a busy interface cannot starve timers/recovery. */
        int r = pcap_dispatch(PRIV->pcapdev, 32, libpcap_packet_handler, (uint8_t*)this);
        if (r == PCAP_ERROR) {
            PR_ERR("libpcap 捕获失败： %s", pcap_geterr(PRIV->pcapdev));
            return FAILURE;
        }
        if (r == PCAP_ERROR_BREAK) return SUCCESS;
        win32_poll_network();
        if (!win32_reconnect_pending()) sched_alarm_poll();
    }
    return SUCCESS;
#else
    if (pcap_loop(PRIV->pcapdev, -1, libpcap_packet_handler, (uint8_t*)this) == PCAP_ERROR) {
        PR_ERR("libpcap 捕获失败： %s", pcap_geterr(PRIV->pcapdev));
        return FAILURE;
    }
    return SUCCESS;
#endif
}

RESULT libpcap_stop_capture(struct _if_impl* this) {
    if (PRIV->pcapdev) {
        pcap_breakloop(PRIV->pcapdev);
        return SUCCESS;
    } else {
        return FAILURE;
    }
}

RESULT libpcap_send_frame(struct _if_impl* this, ETH_EAP_FRAME* frame) {
#ifdef _WIN32
    if (win32_reconnect_pending()) return FAILURE;
#endif
    if (!PRIV->pcapdev || pcap_sendpacket(PRIV->pcapdev, frame->content, frame->actual_len) < 0) {
        PR_ERR("libpcap 发送失败： %s",
            PRIV->pcapdev ? pcap_geterr(PRIV->pcapdev) : "设备未打开");
#ifdef _WIN32
        win32_request_reconnect();
#endif
        return FAILURE;
    }
    return SUCCESS;
}

void libpcap_set_frame_handler(struct _if_impl* this, void (*handler)(ETH_EAP_FRAME* frame)) {
    PRIV->handler = handler;
}

void libpcap_destroy(IF_IMPL* this) {
    libpcap_release_interface(this);
    free(PRIV);
    free(this);
}

IF_IMPL* libpcap_new() {
    IF_IMPL* this = (IF_IMPL*)malloc(sizeof(IF_IMPL));
    if (this == NULL) {
        PR_ERRNO("libpcap 主结构内存分配失败");
        return NULL;
    }
    memset(this, 0, sizeof(IF_IMPL));

    /* The priv pointer in if_impl.h is a libpcap_priv* here */
    this->priv = (libpcap_priv*)malloc(sizeof(libpcap_priv));
    if (this->priv == NULL) {
        PR_ERRNO("libpcap 私有结构内存分配失败");
        free(this);
        return NULL;
    }
    memset(this->priv, 0, sizeof(libpcap_priv));

    this->set_ifname = libpcap_set_ifname;
    this->get_ifname = libpcap_get_ifname;
    this->destroy = libpcap_destroy;
    this->setup_capture_params = libpcap_setup_capture_params;
    this->prepare_interface = libpcap_prepare_interface;
    this->release_interface = libpcap_release_interface;
    this->start_capture = libpcap_start_capture;
    this->stop_capture = libpcap_stop_capture;
    this->send_frame = libpcap_send_frame;
    this->set_frame_handler = libpcap_set_frame_handler;
    this->name = "libpcap";
#ifdef _WIN32
    this->description = "采用 Npcap/libpcap 进行通信的网络接口模块";
#else
    this->description = "采用 libpcap 进行通信的可移植网络接口模块";
#endif
    return this;
}
IF_IMPL_INIT(libpcap_new);
