#include "minieap_common.h"
#include "linkedlist.h"
#include "logging.h"
#include "misc.h"
#include "sched_alarm.h"
#include "win32.h"

#include "oscompat.h"
#include <limits.h>
#include <stdlib.h>
#ifndef _WIN32
#include <signal.h>
#endif

typedef struct _alarm_event {
#ifdef _WIN32
    ULONGLONG deadline_ms;
#else
    int remaining;
#endif
    int id;
    int marked_delete;
    void (*func)(void*);
    void* user;
} ALARM_EVENT;

#define EVENT ((ALARM_EVENT*)alarm_event)

static LIST_ELEMENT* g_alarm_list = NULL;
static LIST_ELEMENT* g_alarm_list_add_temp = NULL;
static int g_last_id = 0;
static int g_ringing = 0;
#ifndef _WIN32
static int g_last_set_time = 0;
#endif

#ifdef DEBUG
static void print_list(LIST_ELEMENT** list) {
    ALARM_EVENT* elem;
    LIST_ELEMENT** ref = list;
    while (*ref) {
        PR_DBG("List print: node at %p", *ref);
        PR_DBG("    next at %p", (*ref)->next);
        PR_DBG("    content at %p", (*ref)->content);
        elem = (*ref)->content;
#ifdef _WIN32
        PR_DBG("    deadline %llu", (unsigned long long)elem->deadline_ms);
#else
        PR_DBG("    remain %d", elem->remaining);
#endif
        PR_DBG("    id %d", elem->id);
        PR_DBG("    marked delete %d", elem->marked_delete);
        PR_DBG("    func %p", elem->func);
        PR_DBG("    user %p", elem->user);
        ref = &(*ref)->next;
    }
    PR_DBG("List print end.");
}
#endif

#ifndef _WIN32
static void set_alarm(int time) {
    alarm(time);
    g_last_set_time = time;
}

static int find_min_remaining(LIST_ELEMENT* list) {
    LIST_ELEMENT* _curr;
    int _min = INT_MAX;

    for (_curr = list; _curr; _curr = _curr->next) {
#define CURR ((ALARM_EVENT*)_curr->content)
        if (CURR->remaining != 0 && CURR->remaining< _min) {
            _min = CURR->remaining;
        }
    }
    return _min;
}

static void update_remaining_single(void* alarm_event, void* secs) {
    EVENT->remaining -= *(int*)secs;
}

static void fire_single(void* alarm_event, void* unused) {
    if (EVENT->remaining <= 0) {
        EVENT->func(EVENT->user);
    }
}
#endif

/* cmpfunc: 0 = match (should be cleaned / not valid), other = unmatch */
static int alarm_valid_cmpfunc(void* unused, void* alarm_event) {
#ifdef _WIN32
    return EVENT->marked_delete == FALSE;
#else
    return EVENT->remaining > 0 && EVENT->marked_delete == FALSE;
#endif
}

#ifndef _WIN32
void alarm_sig_handler(int sig) {
    g_ringing = TRUE;
#ifdef DEBUG
    PR_DBG("RING!");
    print_list(&g_alarm_list);
#endif

    /* We need to avoid maniputing the alarm list during traverse,so
     * 1. Update all the remaining time fields before calling user func
     *    to make sure schedule_alarm works.
     *    Or find_min_remaining in user func may return some value that
     *    will expire just in this triggered alarm.
     * 2. Call user func, and prevent removing/adding nodes during this process.
     *    This will ensure the list's integrity during traversing.
     * 3. Apply deletion / insertion, clean up expired alarms.
     */
    list_traverse(g_alarm_list, update_remaining_single, &g_last_set_time);
    list_traverse(g_alarm_list, fire_single, NULL);

    /* Clean up expired and mark-as-delete alarms */
    remove_data(&g_alarm_list, NULL, alarm_valid_cmpfunc, TRUE);

    /* Append newly scheduled alarms */
    list_concat(&g_alarm_list, g_alarm_list_add_temp);
    /* Prepare for further new lists */
    g_alarm_list_add_temp = NULL;

    int _curr_remaining = find_min_remaining(g_alarm_list);
    set_alarm(_curr_remaining);

#ifdef DEBUG
    PR_DBG("RING END!");
    print_list(&g_alarm_list);
#endif
    g_ringing = FALSE;
}
#endif

RESULT sched_alarm_init() {
    sched_alarm_destroy();
#ifndef _WIN32
    signal(SIGALRM, alarm_sig_handler);
#endif
    return SUCCESS;
}

void sched_alarm_destroy() {
#ifndef _WIN32
    alarm(0);
    g_last_set_time = 0;
#endif
    list_destroy(&g_alarm_list, TRUE);
    list_destroy(&g_alarm_list_add_temp, TRUE);
    g_ringing = FALSE;
}

#ifdef _WIN32
void sched_alarm_poll(void) {
    LIST_ELEMENT* node;
    ULONGLONG now;

    if (g_ringing) return;
    now = GetTickCount64();
    g_ringing = TRUE;
    for (node = g_alarm_list; node; node = node->next) {
        ALARM_EVENT* event = node->content;
        if (win32_reconnect_pending()) break;
        if (!event->marked_delete && event->deadline_ms <= now) {
            /* Consume before calling out; cancellation can mark later entries. */
            event->marked_delete = TRUE;
            event->func(event->user);
        }
    }
    remove_data(&g_alarm_list, NULL, alarm_valid_cmpfunc, TRUE);
    remove_data(&g_alarm_list_add_temp, NULL, alarm_valid_cmpfunc, TRUE);
    list_concat(&g_alarm_list, g_alarm_list_add_temp);
    g_alarm_list_add_temp = NULL;
    g_ringing = FALSE;
}
#endif

static void alarm_mark_as_delete_single(void* alarm_event, void* id) {
    if (EVENT->id == *(int*)id) {
        EVENT->marked_delete = TRUE;
    }
}

static int alarm_event_id_node_cmpfunc(void* id, void* node) {
    if (*(int*)id == ((ALARM_EVENT*)node)->id) {
        return 0;
    }
    return 1;
}

void unschedule_alarm(int id) {
    if (g_ringing) {
        list_traverse(g_alarm_list, alarm_mark_as_delete_single, &id);
        list_traverse(g_alarm_list_add_temp, alarm_mark_as_delete_single, &id);
#ifdef DEBUG
        PR_DBG("Marked event id = %d as deletion", id);
        print_list(&g_alarm_list);
#endif
    } else {
        remove_data(&g_alarm_list, &id, alarm_event_id_node_cmpfunc, TRUE);
#ifdef DEBUG
        PR_DBG("Removed event id = %d", id);
        print_list(&g_alarm_list);
#endif
    }
}

int schedule_alarm(int secs, void (*func)(void*), void* user) {
    ALARM_EVENT* _event = (ALARM_EVENT*)malloc(sizeof(ALARM_EVENT));
    if (_event == NULL) {
        PR_ERR("无法为闹钟事件分配内存");
        return -1;
    }
#ifdef _WIN32
    _event->deadline_ms = GetTickCount64() + (secs > 0 ? (ULONGLONG)secs * 1000 : 0);
#else
    _event->remaining = secs;
#endif
    _event->id = ++g_last_id;
    _event->func = func;
    _event->user = user;
    _event->marked_delete = FALSE;

    if (g_ringing) {
        /* It's ringing. Do not reset alarm here. The signal handler will do this */
        insert_data(&g_alarm_list_add_temp, _event);
#ifdef DEBUG
        PR_DBG("Pending new alarm event insertion");
        print_list(&g_alarm_list_add_temp);
#endif
    } else {
#ifdef _WIN32
        /* Scheduling never dispatches callbacks; only an explicit poll does. */
        insert_data(&g_alarm_list, _event);
#else
        /* Not ringing. Time to next alarm should be obtained by alarm(0) */
        int _curr_remaining = alarm(0);
        /* When there is no alarm set, alarm(0) would be 0. Fix to INT_MAX for comparsion */
        if (_curr_remaining == 0) _curr_remaining = INT_MAX;
        /* Reset since we stopped the alarm half way. */
        set_alarm(_curr_remaining < secs ? _curr_remaining : secs);
        insert_data(&g_alarm_list, _event);
#endif
#ifdef DEBUG
        PR_DBG("New alarm event added");
        print_list(&g_alarm_list);
#endif
    }
    return _event->id;
}
