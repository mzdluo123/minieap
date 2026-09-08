#include "internet_check.h"
#include "config.h"
#include "eap_state_machine.h"
#include "logging.h"
#include "net_util.h"
#include "oscompat.h"
#include "sched_alarm.h"
#include "win32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

enum {
    IC_OK = 0,
    IC_FAIL = 1,
    IC_SKIP = 2
};

static int g_alarm_id = -1;
static int g_fail_count;
static internet_check_http_fn g_http_fn;

#ifdef _WIN32
#define IC_SOCK SOCKET
#define IC_INVALID INVALID_SOCKET
#define ic_close(s) closesocket(s)
#else
#define IC_SOCK int
#define IC_INVALID (-1)
#define ic_close(s) close(s)
#endif

RESULT internet_check_parse_url(const char* url, char* host, int hostlen, int* port, char* path, int pathlen) {
    const char* p;
    const char* host_end;
    size_t host_n, path_n;
    int parsed_port;

    if (!url || !host || !port || !path || hostlen <= 1 || pathlen <= 1)
        return FAILURE;
    if (strncmp(url, "http://", 7) != 0)
        return FAILURE;

    p = url + 7;
    if (*p == '\0' || *p == '/' || *p == ':')
        return FAILURE;

    host_end = p;
    while (*host_end && *host_end != '/' && *host_end != ':')
        host_end++;
    host_n = (size_t)(host_end - p);
    if (host_n == 0 || host_n >= (size_t)hostlen)
        return FAILURE;
    memcpy(host, p, host_n);
    host[host_n] = '\0';

    *port = 80;
    if (*host_end == ':') {
        const char* port_start = host_end + 1;
        const char* port_end = port_start;
        if (*port_start == '\0' || *port_start == '/')
            return FAILURE;
        while (*port_end && *port_end != '/')
            port_end++;
        parsed_port = atoi(port_start);
        if (parsed_port < 1 || parsed_port > 65535)
            return FAILURE;
        *port = parsed_port;
        host_end = port_end;
    }

    if (*host_end == '/') {
        path_n = strlen(host_end);
        if (path_n >= (size_t)pathlen)
            return FAILURE;
        memcpy(path, host_end, path_n + 1);
    } else if (*host_end == '\0') {
        path[0] = '/';
        path[1] = '\0';
    } else {
        return FAILURE;
    }
    return SUCCESS;
}

static int internet_check_wait_connect(IC_SOCK s, int timeout_sec) {
    fd_set wset;
    struct timeval tv;
    int sel;
#ifdef _WIN32
    int soerr;
    int solen = sizeof(soerr);
#else
    int soerr;
    socklen_t solen = sizeof(soerr);
#endif

    FD_ZERO(&wset);
    FD_SET(s, &wset);
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
#ifdef _WIN32
    sel = select(0, NULL, &wset, NULL, &tv);
#else
    sel = select((int)s + 1, NULL, &wset, NULL, &tv);
#endif
    if (sel <= 0)
        return -1;
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soerr, &solen) != 0 || soerr != 0)
        return -1;
    return 0;
}

static int internet_check_http_get(void) {
    PROG_CONFIG* cfg = get_program_config();
    char host[INTERNET_CHECK_URL_MAX];
    char path[INTERNET_CHECK_URL_MAX];
    char portstr[8];
    char req[1024];
    char buf[512];
    int port = 80;
    int req_len, n, got, code;
    LIST_ELEMENT* list = NULL;
    IP_ADDR* ipv4;
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    struct sockaddr_in local;
    IC_SOCK s = IC_INVALID;
    int result = IC_FAIL;
    const char* status;

    if (IS_FAIL(internet_check_parse_url(cfg->internet_check_url, host, (int)sizeof(host),
            &port, path, (int)sizeof(path))))
        return IC_FAIL;

    if (IS_FAIL(obtain_iface_ip_mask(cfg->ifname, &list)) ||
            (ipv4 = find_ip_with_family(list, AF_INET)) == NULL) {
        free_ip_list(&list);
        return IC_SKIP;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        free_ip_list(&list);
        return IC_FAIL;
    }

    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == IC_INVALID)
        goto out;

    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    memcpy(&local.sin_addr, ipv4->ip, 4);
    local.sin_port = 0;
    if (bind(s, (struct sockaddr*)&local, sizeof(local)) != 0) {
        result = IC_SKIP;
        goto out;
    }

#ifdef _WIN32
    {
        u_long nb = 1;
        if (ioctlsocket(s, FIONBIO, &nb) != 0)
            goto out;
        if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0 &&
                WSAGetLastError() != WSAEWOULDBLOCK)
            goto out;
        if (internet_check_wait_connect(s, cfg->internet_check_timeout) != 0)
            goto out;
        nb = 0;
        if (ioctlsocket(s, FIONBIO, &nb) != 0)
            goto out;
    }
#else
    {
        int flags = fcntl(s, F_GETFL, 0);
        if (flags < 0)
            goto out;
        if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
            goto out;
        if (connect(s, res->ai_addr, res->ai_addrlen) != 0 && errno != EINPROGRESS)
            goto out;
        if (internet_check_wait_connect(s, cfg->internet_check_timeout) != 0)
            goto out;
        if (fcntl(s, F_SETFL, flags) < 0)
            goto out;
    }
#endif

#ifdef _WIN32
    {
        DWORD tv = (DWORD)cfg->internet_check_timeout * 1000;
        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) != 0 ||
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) != 0)
            goto out;
    }
#else
    {
        struct timeval tv;
        tv.tv_sec = cfg->internet_check_timeout;
        tv.tv_usec = 0;
        if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
                setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0)
            goto out;
    }
#endif

    if (port == 80) {
        req_len = snprintf(req, sizeof(req),
            "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: MiniEAP\r\nConnection: close\r\n\r\n",
            path, host);
    } else {
        req_len = snprintf(req, sizeof(req),
            "GET %s HTTP/1.0\r\nHost: %s:%d\r\nUser-Agent: MiniEAP\r\nConnection: close\r\n\r\n",
            path, host, port);
    }
    if (req_len <= 0 || req_len >= (int)sizeof(req))
        goto out;
    if (send(s, req, req_len, 0) != req_len)
        goto out;

    n = 0;
    while (n < (int)sizeof(buf) - 1) {
        got = recv(s, buf + n, (int)sizeof(buf) - 1 - n, 0);
        if (got <= 0)
            break;
        n += got;
        buf[n] = '\0';
        if (strchr(buf, '\n'))
            break;
    }
    if (n <= 0)
        goto out;
    buf[n] = '\0';
    if (strncmp(buf, "HTTP/1.", 7) != 0)
        goto out;
    status = buf + 7;
    while (*status && *status != ' ')
        status++;
    while (*status == ' ')
        status++;
    code = atoi(status);
    result = (code == 204) ? IC_OK : IC_FAIL;

out:
    if (s != IC_INVALID)
        ic_close(s);
    if (res)
        freeaddrinfo(res);
    free_ip_list(&list);
    return result;
}

static int internet_check_probe(void) {
    int status = 0;

    if (g_http_fn == NULL)
        return internet_check_http_get();
    if (g_http_fn(&status) == FAILURE)
        return IC_FAIL;
    if (status == 204)
        return IC_OK;
    if (status == 0)
        return IC_SKIP;
    return IC_FAIL;
}

static void internet_check_timed(void* unused);

static void internet_check_reschedule(PROG_CONFIG* cfg) {
    g_alarm_id = schedule_alarm(cfg->internet_check_interval, internet_check_timed, NULL);
}


static void internet_check_timed(void* unused) {
    PROG_CONFIG* cfg = get_program_config();
    int outcome;

    (void)unused;
    g_alarm_id = -1;
    if (!cfg->internet_check)
        return;
#ifdef _WIN32
    if (win32_reconnect_pending())
        return;
#endif
    if (eap_state_machine_get_state() != EAP_STATE_SUCCESS)
        return;

    outcome = internet_check_probe();

    if (eap_state_machine_get_state() != EAP_STATE_SUCCESS)
        return;
#ifdef _WIN32
    if (win32_reconnect_pending())
        return;
#endif

    if (outcome == IC_SKIP) {
        internet_check_reschedule(cfg);
        return;
    }
    if (outcome == IC_OK) {
        if (g_fail_count > 0)
            PR_INFO("联网检测恢复");
        g_fail_count = 0;
        internet_check_reschedule(cfg);
        return;
    }

    g_fail_count++;
    PR_WARN("联网检测失败（%d/%d）", g_fail_count, cfg->internet_check_max_fail);
    if (g_fail_count < cfg->internet_check_max_fail) {
        internet_check_reschedule(cfg);
        return;
    }
    if (!cfg->restart_on_logoff) {
        PR_WARN("联网检测连续失败，因 --no-auto-reauth 不重新认证");
        return;
    }
    PR_WARN("连续 %d 次无法联网，将重新认证", cfg->internet_check_max_fail);
    eap_state_machine_restart_from_offline();
}


void internet_check_stop(void) {
    if (g_alarm_id >= 0)
        unschedule_alarm(g_alarm_id);
    g_alarm_id = -1;
    g_fail_count = 0;
}

void internet_check_start(void) {
    PROG_CONFIG* cfg;

    internet_check_stop();
    cfg = get_program_config();
    if (!cfg->internet_check)
        return;
    g_alarm_id = schedule_alarm(cfg->internet_check_interval, internet_check_timed, NULL);
    PR_INFO("已启用 HTTP 联网检测：%s ，间隔 %d 秒", cfg->internet_check_url, cfg->internet_check_interval);
}

void internet_check_set_http_fn(internet_check_http_fn fn) {
    g_http_fn = fn;
}
