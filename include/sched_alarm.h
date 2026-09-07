#ifndef _MINIEAP_SCHED_ALARM_H
#define _MINIEAP_SCHED_ALARM_H

/*
 * The scheduler based on alarm() on POSIX, and monotonic polling on Windows.
 *
 * It will call `func` after `secs` seconds, and pass `user` as the argument to `func`.
 * `schedule_alarm` returns the job ID. `unschedule_alarm` needs this ID to remove the
 * corresponding alarm event.
 * On Windows, nonpositive delays are due at the next poll. Each poll uses one
 * time snapshot, and events scheduled by callbacks wait until the next poll.
 * Scheduling never dispatches callbacks; cancellation also applies to events
 * scheduled during a callback.
 *
 * POSIX details:
 * We know that later calls to alarm() will override the time value set by previous calls,
 * and alarm(0) cancels the timer and returns time left to next alarm.
 *
 * We can make a list of events to be executed, and always set alarm() to time to nearest event.
 * This time value is stored for further use.
 *
 * When the alarm goes off, we know that stored number of seconds has passed, and update the list
 * subtracting the time value from other events. Then we find the nearest event and set alarm() again.
 */
int schedule_alarm(int secs, void (*func)(void*), void* user);
void unschedule_alarm(int id);

/*
 * Initializes an empty scheduler, discarding any old alarms and installing the
 * signal handler where needed. Init and destroy must run outside callbacks.
 * Destroy releases all pending alarms without invoking their callbacks.
 */
RESULT sched_alarm_init();
void sched_alarm_destroy();

#ifdef _WIN32
void sched_alarm_poll(void);
#endif
#endif
