/*
 * Copyright (C) 2012-2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <cutils/sched_policy.h>
#include <utils/threads.h>
#ifdef HAVE_AEE_FEATURE
#include "aee.h"
#endif
#include <unordered_map>

#include <cutils/properties.h>
#include <log/logger.h>

#include "LogBuffer.h"
#include "LogKlog.h"
#include "LogReader.h"
#include "LogUtils.h"

// Default
#define LOG_BUFFER_SIZE (256 * 1024) // Tuned with ro.logd.size per-platform
#define log_buffer_size(id) mMaxSize[id]
#define LOG_BUFFER_MIN_SIZE (64 * 1024UL)
#define LOG_BUFFER_MAX_SIZE (256 * 1024 * 1024UL)

#define DEBUG_DETECT_LOG_COUNT  5000
#define DEBUG_LOG_PERFORMANCE_TIME  1000000     // each log time 1ms

static bool valid_size(unsigned long value) {
    if ((value < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < value)) {
        return false;
    }

    long pages = sysconf(_SC_PHYS_PAGES);
    if (pages < 1) {
        return true;
    }

    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 1) {
        pagesize = PAGE_SIZE;
    }

    // maximum memory impact a somewhat arbitrary ~3%
    pages = (pages + 31) / 32;
    unsigned long maximum = pages * pagesize;

    if ((maximum < LOG_BUFFER_MIN_SIZE) || (LOG_BUFFER_MAX_SIZE < maximum)) {
        return true;
    }

    return value <= maximum;
}

#if defined(HAVE_AEE_FEATURE) && defined(ANDROID_LOG_MUCH_COUNT)
#include <cutils/sockets.h>

char aee_string[70];
char *log_much_buf;
int log_much_used_size;
bool log_much_detected = false;
int log_much_alloc_size;
#define EACH_LOG_SIZE 300   /* each log size * detect count = alloc size*/

static void *logmuchaee_thread_start(void * /*obj*/) {
    prctl(PR_SET_NAME, "logd.logmuch");
    kernel_log_print("logd:logmuch file total size %d.\n", log_much_used_size);
    if (log_much_used_size < log_much_alloc_size)
        log_much_buf[log_much_used_size] = 0;
    set_sched_policy(0, SP_FOREGROUND);
    aee_system_warning(aee_string, NULL, DB_OPT_DUMMY_DUMP|DB_OPT_PRINTK_TOO_MUCH, log_much_buf);
    if (log_much_buf != NULL) {
       free(log_much_buf);
       log_much_buf = NULL;
    }
    log_much_used_size = 0;
    log_much_detected = false;
    return NULL;
}
#endif

#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG)
static void *logd_memory_leak_thread_start(void * /*obj*/) {
    prctl(PR_SET_NAME, "logd.memoryleak");
    set_sched_policy(0, SP_FOREGROUND);
    aee_system_warning("Logd memory leak", NULL, DB_OPT_DEFAULT, "Logd memory leak");
    return NULL;
}
#endif

#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG_PERFORMANCE)
static void *logd_performance_issue_thread_start(void * /*obj*/) {
    prctl(PR_SET_NAME, "logd.performance");
    set_sched_policy(0, SP_FOREGROUND);
    aee_system_warning("Logd cpu usage high", NULL, DB_OPT_DEFAULT, "Logd cpu usage high");
    return NULL;
}
#endif



static unsigned long property_get_size(const char *key) {
    char property[PROPERTY_VALUE_MAX];
    property_get(key, property, "");

    char *cp;
    unsigned long value = strtoul(property, &cp, 10);

    switch(*cp) {
    case 'm':
    case 'M':
        value *= 1024;
    /* FALLTHRU */
    case 'k':
    case 'K':
        value *= 1024;
    /* FALLTHRU */
    case '\0':
        break;

    default:
        value = 0;
    }

    if (!valid_size(value)) {
        value = 0;
    }

    return value;
}

void LogBuffer::init() {
    static const char global_tuneable[] = "persist.logd.size"; // Settings App
    static const char global_default[] = "ro.logd.size";       // BoardConfig.mk

    unsigned long default_size = property_get_size(global_tuneable);
    if (!default_size) {
        default_size = property_get_size(global_default);
        if (!default_size) {
            default_size = property_get_bool("ro.config.low_ram",
                                             BOOL_DEFAULT_FALSE)
                ? LOG_BUFFER_MIN_SIZE // 64K
                : LOG_BUFFER_SIZE;    // 256K
        }
    }

    log_id_for_each(i) {
        mLastSet[i] = false;
        mLast[i] = mLogElements.begin();

        char key[PROP_NAME_MAX];

        snprintf(key, sizeof(key), "%s.%s",
                 global_tuneable, android_log_id_to_name(i));
        unsigned long property_size = property_get_size(key);

        if (!property_size) {
            snprintf(key, sizeof(key), "%s.%s",
                     global_default, android_log_id_to_name(i));
            property_size = property_get_size(key);
        }

        if (!property_size) {
            property_size = default_size;
        }

        if (!property_size) {
            property_size = LOG_BUFFER_SIZE;
        }
#if defined(HAVE_AEE_FEATURE) && defined(ANDROID_LOG_MUCH_COUNT)
        if (i == LOG_ID_MAIN || i == LOG_ID_RADIO) {
            property_size = 5 * property_size;
        }
#endif

        if (setSize(i, property_size)) {
            setSize(i, LOG_BUFFER_MIN_SIZE);
        }
    }
    bool lastMonotonic = monotonic;
    monotonic = android_log_clockid() == CLOCK_MONOTONIC;
    if (lastMonotonic != monotonic) {
        //
        // Fixup all timestamps, may not be 100% accurate, but better than
        // throwing what we have away when we get 'surprised' by a change.
        // In-place element fixup so no need to check reader-lock. Entries
        // should already be in timestamp order, but we could end up with a
        // few out-of-order entries if new monotonics come in before we
        // are notified of the reinit change in status. A Typical example would
        // be:
        //  --------- beginning of system
        //      10.494082   184   201 D Cryptfs : Just triggered post_fs_data
        //  --------- beginning of kernel
        //       0.000000     0     0 I         : Initializing cgroup subsys
        // as the act of mounting /data would trigger persist.logd.timestamp to
        // be corrected. 1/30 corner case YMMV.
        //
        pthread_mutex_lock(&mLogElementsLock);
        LogBufferElementCollection::iterator it = mLogElements.begin();
        while((it != mLogElements.end())) {
            LogBufferElement *e = *it;
            if (monotonic) {
                if (!android::isMonotonic(e->mRealTime)) {
                    LogKlog::convertRealToMonotonic(e->mRealTime);
                }
            } else {
                if (android::isMonotonic(e->mRealTime)) {
                    LogKlog::convertMonotonicToReal(e->mRealTime);
                }
            }
            ++it;
        }
        pthread_mutex_unlock(&mLogElementsLock);
    }

    // We may have been triggered by a SIGHUP. Release any sleeping reader
    // threads to dump their current content.
    //
    // NB: this is _not_ performed in the context of a SIGHUP, it is
    // performed during startup, and in context of reinit administrative thread
    LogTimeEntry::lock();

    LastLogTimes::iterator times = mTimes.begin();
    while(times != mTimes.end()) {
        LogTimeEntry *entry = (*times);
        if (entry->owned_Locked()) {
            entry->triggerReader_Locked();
        }
        times++;
    }

    LogTimeEntry::unlock();
}

LogBuffer::LogBuffer(LastLogTimes *times):
        monotonic(android_log_clockid() == CLOCK_MONOTONIC),
        mTimes(*times) {
    pthread_mutex_init(&mLogElementsLock, NULL);

    init();
}

int LogBuffer::log(log_id_t log_id, log_time realtime,
                   uid_t uid, pid_t pid, pid_t tid,
                   const char *msg, unsigned short len) {
    if ((log_id >= LOG_ID_MAX) || (log_id < 0)) {
        return -EINVAL;
    }

    LogBufferElement *elem = new LogBufferElement(log_id, realtime,
                                                  uid, pid, tid, msg, len);
    int prio = ANDROID_LOG_INFO;
    const char *tag = NULL;
       int time_find_count = 0;
#ifdef MTK_LOGD_DEBUG
    struct timespec ts_0, ts_1, ts_2, ts_3, ts_4;
    static struct timespec ts_diff;
    static uint64_t diff_time[4] = {0};
    static uint64_t total_time;
    static uint32_t diff_count = 0;
    static uint32_t filter_count = 0;
#endif
#if defined(HAVE_AEE_FEATURE) && defined(ANDROID_LOG_MUCH_COUNT)
    static int line_count = 0;
    time_t logs_time, now_time;
    static time_t old_time;
    static struct timespec pause_time = {0, 0};
    struct timespec pause_time_now;
    static int pause_detect = 1;
    static int original_detect_value;
    static int delay_time = 3*60;
    int file_count = 0;
    char *buff = NULL;
    char log_type[7];
    const char *log_tag = NULL;
    char *log_msg;
    int log_prio = ANDROID_LOG_INFO;
    int i, fd_file, ret;
    int buf_len, msg_len;
#if !defined(_WIN32)
    struct tm tmBuf;
#endif
    struct tm* ptm;
#endif

#ifdef MTK_LOGD_DEBUG
    ts_0 = ts_1 = ts_2 = ts_3 = ts_4 = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &ts_0);
#endif

    if (log_id != LOG_ID_SECURITY) {
        if (log_id == LOG_ID_EVENTS) {
            tag = android::tagToName(elem->getTag());
            if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
                // Log traffic received to total
                pthread_mutex_lock(&mLogElementsLock);
                stats.add_total_size(elem);
                pthread_mutex_unlock(&mLogElementsLock);
                delete elem;
#ifdef MTK_LOGD_DEBUG

                clock_gettime(CLOCK_MONOTONIC, &ts_1);
                diff_time[0] += (ts_1.tv_sec - ts_0.tv_sec)*1000000000-ts_0.tv_nsec+ts_1.tv_nsec;
                filter_count++;
#endif
                return -EACCES;
            }
        } else {
            prio = *msg;
            tag = msg + 1;
        }
    }

#ifdef MTK_LOGD_DEBUG
   clock_gettime(CLOCK_MONOTONIC, &ts_1);
#endif

    pthread_mutex_lock(&mLogElementsLock);
#if defined(HAVE_AEE_FEATURE) && defined(ANDROID_LOG_MUCH_COUNT)
    if (log_detect_value == 0) {
        pause_detect = 0;
        delay_time = 0;
        original_detect_value = 0;
    }
    if (pause_detect == 1) {
        if (pause_time.tv_sec == 0) {
            clock_gettime(CLOCK_MONOTONIC, &pause_time);
        }
        clock_gettime(CLOCK_MONOTONIC, &pause_time_now);
        if (pause_time_now.tv_sec - pause_time.tv_sec > delay_time) {
            pause_detect = 0;
            delay_time = 0;
            log_detect_value = original_detect_value;
            original_detect_value = 0;
            kernel_log_print("logd: detect delay end:level %d,old level %d.\n",
            log_detect_value, original_detect_value);
        }
    }

  if (log_detect_value > 0 && log_much_detected == false) {
    if (log_id == LOG_ID_KERNEL) {
        goto log_much_exit;
    }

    now_time = realtime.tv_sec;
    if (old_time == 0) {
        log_much_delay_detect = 181;
    }

    if (log_much_delay_detect == 1) {
        line_count = 1;
        old_time = now_time + 1;
        log_much_delay_detect = 0;
        pause_detect = 0;
        delay_time = 0;
        original_detect_value = log_detect_value;
    }

    if (log_much_delay_detect > 0) {
        pause_detect = 1;
        clock_gettime(CLOCK_MONOTONIC, &pause_time);
        delay_time = log_much_delay_detect;
        log_much_delay_detect = 0;
        old_time = now_time;
        if (original_detect_value == 0) {
            original_detect_value = log_detect_value;
        } else {
            log_detect_value = original_detect_value;
        }
        log_detect_value = 2 * log_detect_value;
        kernel_log_print("logd: detect delay:time %d, level %d,old level %d.\n",
            delay_time, log_detect_value, original_detect_value);
     }

    if (old_time > now_time) {
        line_count = 0;
        goto log_much_exit;
    }

    if (now_time > (old_time + detect_time - 1)) {
       if (line_count > (log_detect_value * detect_time)) {
        buff = new char[1024];
        if (buff == NULL)
            goto log_much_exit;

        if (log_much_buf == NULL) {
            log_much_alloc_size = (log_detect_value * detect_time) * EACH_LOG_SIZE;
            log_much_buf = (char*) malloc(log_much_alloc_size);
            if (log_much_buf == NULL)
                goto log_much_exit;
            log_much_used_size = 0;
        } else {
            memset(log_much_buf, 0, log_much_alloc_size);
            log_much_used_size = 0;
        }

#if !defined(_WIN32)
        ptm = localtime_r(&now_time, &tmBuf);
#else
        ptm = localtime(&now_time);
#endif
        strftime(buff, 1024, "%m-%d %H:%M:%S", ptm);

        kernel_log_print("logd: android log much:line %d, time %d, %lu.\n",
            line_count, realtime.tv_sec, old_time);

        LogTimeEntry::lock();
        LogBufferElementCollection::iterator test = mLogElements.end();
        LogBufferElementCollection::iterator test_last = test;
        while (test_last != mLogElements.begin()) {
            --test;
            logs_time = (*test)->getRealTime().tv_sec;
            if (logs_time < old_time || logs_time > (old_time + detect_time -1)) {
                goto next_log;
            }
#if !defined(_WIN32)
            ptm = localtime_r(&logs_time, &tmBuf);
#else
            ptm = localtime(&logs_time);
#endif
            switch ((*test)->getLogId()) {
                case LOG_ID_KERNEL:
                    goto next_log;

                case LOG_ID_EVENTS:
                    strcpy(log_type, "EVENTS");
                    log_tag = android::tagToName((*test)->getTag());
                    log_msg = NULL;
                    break;

                case LOG_ID_MAIN:
                    strcpy(log_type, "MAIN");
                    log_prio = (*test)->getMsg()[0];
                    log_tag = (*test)->getMsg() + 1;
                    log_msg = (*test)->getMsg() + strlen(log_tag) + 2;
                    break;

                case LOG_ID_SYSTEM:
                    strcpy(log_type, "SYSTEM");
                    log_prio = (*test)->getMsg()[0];
                    log_tag = (*test)->getMsg() + 1;
                    log_msg = (*test)->getMsg() + strlen(log_tag) + 2;
                    break;

                case LOG_ID_CRASH:
                    strcpy(log_type, "CRASH");
                    log_prio = (*test)->getMsg()[0];
                    log_tag = (*test)->getMsg() + 1;
                    log_msg = (*test)->getMsg() + strlen(log_tag) + 2;
                    break;

                case LOG_ID_RADIO:
                    strcpy(log_type, "RADIO");
                    log_prio = (*test)->getMsg()[0];
                    log_tag = (*test)->getMsg() + 1;
                    log_msg = (*test)->getMsg() + strlen(log_tag) + 2;
                    break;

                default:
                    goto next_log;
            }

            /* strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", ptm); */
            buff[0]='\n';
            strftime(buff+1, 1024, "%m-%d %H:%M:%S", ptm);
            buf_len = strlen(buff);
            buf_len += sprintf(buff + buf_len, ".%06d ", (*test)->getRealTime().tv_nsec / 1000);
            /* event log tag */
            buf_len += sprintf(buff + buf_len, "%d, %d,[%s],[%d],[Tag]%s[TAG]:",
                        (*test)->getPid(), (*test)->getTid(), log_type, log_prio, log_tag);
           if ((*test)->getLogId() == LOG_ID_EVENTS || log_msg == NULL) {
               /* event log message*/
            } else if (1023 - buf_len > (int)strlen(log_msg)) {
                strcpy(buff + buf_len, log_msg);
                buf_len += strlen(log_msg);
            } else {
                strncpy(buff + buf_len, log_msg, 1023 - buf_len);
                buff[1022] = '\n';
                buff[1023] = '\0';
                buf_len = 1023;
            }
            file_count++;

            if (buf_len < log_much_alloc_size - log_much_used_size) {
                memcpy(log_much_buf + log_much_used_size, buff, buf_len);
                log_much_used_size += buf_len;
            } else {
                buf_len = log_much_alloc_size - log_much_used_size;
                memcpy(log_much_buf + log_much_used_size, buff, buf_len);
                log_much_used_size += buf_len;
                log_much_buf[log_much_alloc_size - 1] = 0;
                break;
            }
next_log:
                test_last = test;
        }
        LogTimeEntry::unlock();
        /* close(fd_file); */
        pthread_attr_t attr;
        if ((file_count / 8 > (log_detect_value * detect_time) / 10) && !pthread_attr_init(&attr)) {
            struct sched_param param;

            memset(aee_string, 0, 70);
            kernel_log_print("logd:logmuch file total size %d.\n", log_much_used_size);
            sprintf(aee_string, "Android log much: %d, %d.detect time %d.level %d.", line_count, file_count, detect_time,log_detect_value);
            memset(&param, 0, sizeof(param));
            pthread_attr_setschedparam(&attr, &param);
            pthread_attr_setschedpolicy(&attr, SCHED_BATCH);
            if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
                pthread_t thread;
                log_much_detected  = true;
                pthread_create(&thread, &attr, logmuchaee_thread_start, NULL);
            }
            pthread_attr_destroy(&attr);
        }

        old_time = now_time + DETECT_DELAY_TIME;
        line_count = 0;
        delete buff;
        buff = NULL;
      } else {
        line_count = 1;
        old_time = now_time + detect_time;
       }
      } else {
        line_count++;
      }
    }
log_much_exit:
    if (buff != NULL) {
        delete buff;
        buff = NULL;
    }
#endif


    // Insert elements in time sorted order if possible
    //  NB: if end is region locked, place element at end of list
    LogBufferElementCollection::iterator it = mLogElements.end();
    LogBufferElementCollection::iterator last = it;
    while (last != mLogElements.begin()) {
        --it;
        if ((*it)->getRealTime() <= realtime) {
            break;
        }
        last = it;
        time_find_count++;
    }
#ifdef MTK_LOGD_DEBUG
    clock_gettime(CLOCK_MONOTONIC, &ts_2);
#endif
    if (last == mLogElements.end() || time_find_count > 20) {
        mLogElements.push_back(elem);
    } else {
        uint64_t end = 1;
        bool end_set = false;
        bool end_always = false;

        LogTimeEntry::lock();

        LastLogTimes::iterator times = mTimes.begin();
        while(times != mTimes.end()) {
            LogTimeEntry *entry = (*times);
            if (entry->owned_Locked()) {
                if (!entry->mNonBlock) {
                    end_always = true;
                    break;
                }
                if (!end_set || (end <= entry->mEnd)) {
                    end = entry->mEnd;
                    end_set = true;
                }
            }
            times++;
        }

        if (end_always
                || (end_set && (end >= (*last)->getSequence()))) {
            mLogElements.push_back(elem);
        } else {
            mLogElements.insert(last,elem);
        }

        LogTimeEntry::unlock();
    }

    stats.add(elem);
#ifdef MTK_LOGD_DEBUG
    clock_gettime(CLOCK_MONOTONIC, &ts_3);
#endif
    maybePrune(log_id);
    pthread_mutex_unlock(&mLogElementsLock);

    if (log_id == LOG_ID_KERNEL)
        return len;

#ifdef MTK_LOGD_DEBUG
    clock_gettime(CLOCK_MONOTONIC, &ts_4);
    diff_time[0] += (ts_1.tv_sec - ts_0.tv_sec)*1000000000-ts_0.tv_nsec+ts_1.tv_nsec;
    diff_time[1] += (ts_2.tv_sec - ts_1.tv_sec)*1000000000-ts_1.tv_nsec+ts_2.tv_nsec;
    diff_time[2] += (ts_3.tv_sec - ts_2.tv_sec)*1000000000-ts_2.tv_nsec+ts_3.tv_nsec;
    diff_time[3] += (ts_4.tv_sec - ts_3.tv_sec)*1000000000-ts_3.tv_nsec+ts_4.tv_nsec;
    total_time += (ts_4.tv_sec - ts_0.tv_sec)*1000000000-ts_0.tv_nsec+ts_4.tv_nsec;
    diff_count++;

    if (diff_count >= DEBUG_DETECT_LOG_COUNT) {
#if defined(__LP64__)
      kernel_log_print("logd:diff time %ld, run time %lu, count %u,step 1 %lu,2 %lu,3 %lu,4 %lu. filter count %u.\n",
             (ts_4.tv_sec-ts_diff.tv_sec)*1000000000-ts_diff.tv_nsec+ts_4.tv_nsec, total_time, diff_count,
             diff_time[0]/diff_count, diff_time[1]/diff_count, diff_time[2]/diff_count, diff_time[3]/diff_count,
             filter_count);
#else
        kernel_log_print("logd:diff %lld, run %llu, count %u,step 1 %llu,2 %llu,3 %llu,4 %llu. filter count %u.\n",
             (long long int)(ts_4.tv_sec-ts_diff.tv_sec)*1000000000-ts_diff.tv_nsec+ts_4.tv_nsec, total_time,
             diff_count, diff_time[0]/diff_count, diff_time[1]/diff_count, diff_time[2]/diff_count,
             diff_time[3]/diff_count, filter_count);

#endif
#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG_PERFORMANCE)
        static bool performance_issue;
        if ((performance_issue == false)  && (total_time / DEBUG_DETECT_LOG_COUNT > DEBUG_LOG_PERFORMANCE_TIME) &&
        (ts_4.tv_sec - ts_diff.tv_sec) > (DEBUG_DETECT_LOG_COUNT / 1000 * 2 * DEBUG_LOG_PERFORMANCE_TIME / 1000000)) {
            // logd cpuusage larger than 50%
            pthread_attr_t attr_p;

            if (!pthread_attr_init(&attr_p)) {
                struct sched_param param_p;
                performance_issue = true;
                memset(&param_p, 0, sizeof(param_p));
                pthread_attr_setschedparam(&attr_p, &param_p);
                pthread_attr_setschedpolicy(&attr_p, SCHED_BATCH);
                if (!pthread_attr_setdetachstate(&attr_p, PTHREAD_CREATE_DETACHED)) {
                    pthread_t thread;
                    pthread_create(&thread, &attr_p, logd_performance_issue_thread_start, NULL);
                }
                pthread_attr_destroy(&attr_p);
            }
        }
#endif

        diff_time[1] = diff_time[2] = diff_time[3] = diff_time[0] = diff_count = filter_count = 0;
        total_time = 0;
         ts_diff.tv_sec = ts_4.tv_sec;
         ts_diff.tv_nsec = ts_4.tv_nsec;
    }
#endif

    return len;
}

// Prune at most 10% of the log entries or maxPrune, whichever is less.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::maybePrune(log_id_t id) {
    size_t sizes = stats.sizes(id);
    unsigned long maxSize = log_buffer_size(id);
    if (sizes > maxSize) {
        size_t sizeOver = sizes - ((maxSize * 9) / 10);
        size_t elements = stats.realElements(id);
        size_t minElements = elements / 100;
        if (minElements < minPrune) {
            minElements = minPrune;
        }
        unsigned long pruneRows = elements * sizeOver / sizes;
        if (pruneRows < minElements) {
            pruneRows = minElements;
        }
        if (pruneRows > maxPrune) {
            pruneRows = maxPrune;
        }
        prune(id, pruneRows);
    }
}

void LogBuffer::poison(
        LogBufferElementCollection::iterator it) {
    unsigned long *it_addr = (unsigned long *)((unsigned long)&(*it));
    memset(it_addr, 0x6b, sizeof(unsigned long));
}

LogBufferElementCollection::iterator LogBuffer::erase(
        LogBufferElementCollection::iterator it, bool coalesce) {
    LogBufferElement *element = *it;
    log_id_t id = element->getLogId();

    // Remove iterator references in the various lists that will become stale
    // after the element is erased from the main logging list.

    {   // start of scope for uid found iterator
        LogBufferIteratorMap::iterator found =
            mLastWorstUid[id].find(element->getUid());
        if ((found != mLastWorstUid[id].end())
                && (it == found->second)) {
            mLastWorstUid[id].erase(found);
        }
    }

    {   // start of scope for pid found iterator
        // element->getUid() may not be AID_SYSTEM for next-best-watermark.
        LogBufferPidIteratorMap::iterator found =
            mLastWorstPidOfSystem[id].find(element->getPid());
        if ((found != mLastWorstPidOfSystem[id].end())
                && (it == found->second)) {
            mLastWorstPidOfSystem[id].erase(found);
        }
    }

    bool setLast[LOG_ID_MAX];
    bool doSetLast = false;
    log_id_for_each(i) {
        doSetLast |= setLast[i] = mLastSet[i] && (it == mLast[i]);
    }
    poison(it);
    it = mLogElements.erase(it);
    if (doSetLast) {
        log_id_for_each(i) {
            if (setLast[i]) {
                if (it == mLogElements.end()) { // unlikely
                    mLastSet[i] = false;
                } else {
                    mLast[i] = it;
                }
            }
        }
    }
    if (coalesce) {
        stats.erase(element);
    } else {
        stats.subtract(element);
    }
    delete element;

    return it;
}

// Define a temporary mechanism to report the last LogBufferElement pointer
// for the specified uid, pid and tid. Used below to help merge-sort when
// pruning for worst UID.
class LogBufferElementKey {
    const union {
        struct {
            uint16_t uid;
            uint16_t pid;
            uint16_t tid;
            uint16_t padding;
        } __packed;
        uint64_t value;
    } __packed;

public:
    LogBufferElementKey(uid_t uid, pid_t pid, pid_t tid):
            uid(uid),
            pid(pid),
            tid(tid),
            padding(0) {
    }
    LogBufferElementKey(uint64_t key):value(key) { }

    uint64_t getKey() { return value; }
};

class LogBufferElementLast {

    typedef std::unordered_map<uint64_t, LogBufferElement *> LogBufferElementMap;
    LogBufferElementMap map;

public:

    bool coalesce(LogBufferElement *element, unsigned short dropped) {
        LogBufferElementKey key(element->getUid(),
                                element->getPid(),
                                element->getTid());
        LogBufferElementMap::iterator it = map.find(key.getKey());
        if (it != map.end()) {
            LogBufferElement *found = it->second;
            unsigned short moreDropped = found->getDropped();
            if ((dropped + moreDropped) > USHRT_MAX) {
                map.erase(it);
            } else {
                found->setDropped(dropped + moreDropped);
                return true;
            }
        }
        return false;
    }

    void add(LogBufferElement *element) {
        LogBufferElementKey key(element->getUid(),
                                element->getPid(),
                                element->getTid());
        map[key.getKey()] = element;
    }

    inline void clear() {
        map.clear();
    }

    void clear(LogBufferElement *element) {
        uint64_t current = element->getRealTime().nsec()
                         - (EXPIRE_RATELIMIT * NS_PER_SEC);
        for(LogBufferElementMap::iterator it = map.begin(); it != map.end();) {
            LogBufferElement *mapElement = it->second;
            if ((mapElement->getDropped() >= EXPIRE_THRESHOLD)
                    && (current > mapElement->getRealTime().nsec())) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }

};

// prune "pruneRows" of type "id" from the buffer.
//
// This garbage collection task is used to expire log entries. It is called to
// remove all logs (clear), all UID logs (unprivileged clear), or every
// 256 or 10% of the total logs (whichever is less) to prune the logs.
//
// First there is a prep phase where we discover the reader region lock that
// acts as a backstop to any pruning activity to stop there and go no further.
//
// There are three major pruning loops that follow. All expire from the oldest
// entries. Since there are multiple log buffers, the Android logging facility
// will appear to drop entries 'in the middle' when looking at multiple log
// sources and buffers. This effect is slightly more prominent when we prune
// the worst offender by logging source. Thus the logs slowly loose content
// and value as you move back in time. This is preferred since chatty sources
// invariably move the logs value down faster as less chatty sources would be
// expired in the noise.
//
// The first loop performs blacklisting and worst offender pruning. Falling
// through when there are no notable worst offenders and have not hit the
// region lock preventing further worst offender pruning. This loop also looks
// after managing the chatty log entries and merging to help provide
// statistical basis for blame. The chatty entries are not a notification of
// how much logs you may have, but instead represent how much logs you would
// have had in a virtual log buffer that is extended to cover all the in-memory
// logs without loss. They last much longer than the represented pruned logs
// since they get multiplied by the gains in the non-chatty log sources.
//
// The second loop get complicated because an algorithm of watermarks and
// history is maintained to reduce the order and keep processing time
// down to a minimum at scale. These algorithms can be costly in the face
// of larger log buffers, or severly limited processing time granted to a
// background task at lowest priority.
//
// This second loop does straight-up expiration from the end of the logs
// (again, remember for the specified log buffer id) but does some whitelist
// preservation. Thus whitelist is a Hail Mary low priority, blacklists and
// spam filtration all take priority. This second loop also checks if a region
// lock is causing us to buffer too much in the logs to help the reader(s),
// and will tell the slowest reader thread to skip log entries, and if
// persistent and hits a further threshold, kill the reader thread.
//
// The third thread is optional, and only gets hit if there was a whitelist
// and more needs to be pruned against the backstop of the region lock.
//
// mLogElementsLock must be held when this function is called.
//
bool LogBuffer::prune(log_id_t id, unsigned long pruneRows, uid_t caller_uid) {
    LogTimeEntry *oldest = NULL;
    bool busy = false;
    bool clearAll = pruneRows == ULONG_MAX;
    int Times_count = 0;

    LogTimeEntry::lock();

    // Region locked?
    LastLogTimes::iterator times = mTimes.begin();
    while(times != mTimes.end()) {
        LogTimeEntry *entry = (*times);
        if (entry->owned_Locked() && entry->isWatching(id)
                && (!oldest ||
                    (oldest->mStart > entry->mStart) ||
                    ((oldest->mStart == entry->mStart) &&
                     (entry->mTimeout.tv_sec || entry->mTimeout.tv_nsec)))) {
            oldest = entry;
        }
        times++;
        Times_count++;
    }

    LogBufferElementCollection::iterator it;

    if (stats.sizes(id) > (100 * log_buffer_size(id))) {
#if defined(__LP64__)
        kernel_log_print("logd: the %d log size is %lu.\n", id, stats.sizes(id));
#else
        kernel_log_print("logd: the %d log size is %d.\n", id, stats.sizes(id));
#endif
    if (pruneRows == maxPrune) {
        pruneRows = stats.realElements(id) * (stats.sizes(id) - log_buffer_size(id)) / stats.sizes(id);
    }

times = mTimes.begin();
        while (times != mTimes.end()) {
            LogTimeEntry *entry = (*times);
            if (entry->owned_Locked() && entry->isWatching(id)) {
                entry->release_Locked();
            }
            times++;
            Times_count++;
        }
        it = mLogElements.begin();
        while ((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement *e = *it;

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            it = erase(it);
            pruneRows--;
        }

#if defined(__LP64__)
        kernel_log_print("logd: have %d read thread, the %d log size is %lu.\n",
            Times_count, id, stats.sizes(id));
#else
        kernel_log_print("logd: have %d read thread, the %d log size is %d.\n",
            Times_count, id, stats.sizes(id));
#endif

        LogTimeEntry::unlock();
#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG)
        pthread_attr_t attr_m;
        static bool memory_issue;

        if (memory_issue == true)
            return true;

        if (!pthread_attr_init(&attr_m)) {
            struct sched_param param_m;

            memory_issue = true;
            memset(&param_m, 0, sizeof(param_m));
            pthread_attr_setschedparam(&attr_m, &param_m);
            pthread_attr_setschedpolicy(&attr_m, SCHED_BATCH);
            if (!pthread_attr_setdetachstate(&attr_m, PTHREAD_CREATE_DETACHED)) {
                pthread_t thread;
                pthread_create(&thread, &attr_m, logd_memory_leak_thread_start, NULL);
            }
            pthread_attr_destroy(&attr_m);
       }
#endif
        return true;
    }

    if (oldest && (oldest->getSkipAhead(id) != 0)) {
        //kernel_log_print("oldest still has skip item!%ld", stats.sizes(id));
        LogTimeEntry::unlock();
        return false;
    }



    if (caller_uid != AID_ROOT) {
        // Only here if clearAll condition (pruneRows == ULONG_MAX)
        it = mLastSet[id] ? mLast[id] : mLogElements.begin();
        while (it != mLogElements.end()) {
            LogBufferElement *element = *it;

            if ((element->getLogId() != id) || (element->getUid() != caller_uid)) {
                ++it;
                continue;
            }

            if (!mLastSet[id] || ((*mLast[id])->getLogId() != id)) {
                mLast[id] = it;
                mLastSet[id] = true;
            }

            if (oldest && (oldest->mStart <= element->getSequence())) {
                busy = true;
                if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                    oldest->triggerReader_Locked();
                } else {
                    oldest->triggerSkip_Locked(id, pruneRows);
                }
                break;
            }

            it = erase(it);
            pruneRows--;
        }
        LogTimeEntry::unlock();
        return busy;
    }

    // prune by worst offenders; by blacklist, UID, and by PID of system UID
    bool hasBlacklist = (id != LOG_ID_SECURITY) && mPrune.naughty();
#if 0
    goto PRUNE;
    while (!clearAll && (pruneRows > 0)) {
        // recalculate the worst offender on every batched pass
        uid_t worst = (uid_t) -1;
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;
        pid_t worstPid = 0; // POSIX guarantees PID != 0

        if (worstUidEnabledForLogid(id) && mPrune.worstUidEnabled()) {
            {   // begin scope for UID sorted list
                std::unique_ptr<const UidEntry *[]> sorted = stats.sort(
                    AID_ROOT, (pid_t)0, 2, id);

                if (sorted.get() && sorted[0] && sorted[1]) {
                    worst_sizes = sorted[0]->getSizes();
                    // Calculate threshold as 12.5% of available storage
                    size_t threshold = log_buffer_size(id) / 8;
                    if ((worst_sizes > threshold)
                        // Allow time horizon to extend roughly tenfold, assume
                        // average entry length is 100 characters.
                            && (worst_sizes > (10 * sorted[0]->getDropped()))) {
                        worst = sorted[0]->getKey();
                        second_worst_sizes = sorted[1]->getSizes();
                        if (second_worst_sizes < threshold) {
                            second_worst_sizes = threshold;
                        }
                    }
                }
            }

            if ((worst == AID_SYSTEM) && mPrune.worstPidOfSystemEnabled()) {
                // begin scope of PID sorted list
                std::unique_ptr<const PidEntry *[]> sorted = stats.sort(
                    worst, (pid_t)0, 2, id, worst);
                if (sorted.get() && sorted[0] && sorted[1]) {
                    worstPid = sorted[0]->getKey();
                    second_worst_sizes = worst_sizes
                                       - sorted[0]->getSizes()
                                       + sorted[1]->getSizes();
                }
            }
        }

        // skip if we have neither worst nor naughty filters
        if ((worst == (uid_t) -1) && !hasBlacklist) {
            break;
        }

        bool kick = false;
        bool leading = true;
        it = mLastSet[id] ? mLast[id] : mLogElements.begin();
        // Perform at least one mandatory garbage collection cycle in following
        // - clear leading chatty tags
        // - coalesce chatty tags
        // - check age-out of preserved logs
        bool gc = pruneRows <= 1;
        if (!gc && (worst != (uid_t) -1)) {
            {   // begin scope for uid worst found iterator
                LogBufferIteratorMap::iterator found = mLastWorstUid[id].find(worst);
                if ((found != mLastWorstUid[id].end())
                        && (found->second != mLogElements.end())) {
                    leading = false;
                    it = found->second;
                }
            }
            if (worstPid) {
                // begin scope for pid worst found iterator
                LogBufferPidIteratorMap::iterator found
                    = mLastWorstPidOfSystem[id].find(worstPid);
                if ((found != mLastWorstPidOfSystem[id].end())
                        && (found->second != mLogElements.end())) {
                    leading = false;
                    it = found->second;
                }
            }
        }
        static const timespec too_old = {
            EXPIRE_HOUR_THRESHOLD * 60 * 60, 0
        };
        LogBufferElementCollection::iterator lastt;
        lastt = mLogElements.end();
        --lastt;
        LogBufferElementLast last;
        while (it != mLogElements.end()) {
            LogBufferElement *element = *it;

            if (oldest && (oldest->mStart <= element->getSequence())) {
                busy = true;
                if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                    oldest->triggerReader_Locked();
                }
                break;
            }

            if (element->getLogId() != id) {
                ++it;
                continue;
            }
            // below this point element->getLogId() == id

            if (leading && (!mLastSet[id] || ((*mLast[id])->getLogId() != id))) {
                mLast[id] = it;
                mLastSet[id] = true;
            }

            unsigned short dropped = element->getDropped();

            // remove any leading drops
            if (leading && dropped) {
                it = erase(it);
                continue;
            }

            if (dropped && last.coalesce(element, dropped)) {
                it = erase(it, true);
                continue;
            }

            if (hasBlacklist && mPrune.naughty(element)) {
                last.clear(element);
                it = erase(it);
                if (dropped) {
                    continue;
                }

                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }

                if (element->getUid() == worst) {
                    kick = true;
                    if (worst_sizes < second_worst_sizes) {
                        break;
                    }
                    worst_sizes -= element->getMsgLen();
                }
                continue;
            }

            if ((element->getRealTime() < ((*lastt)->getRealTime() - too_old))
                    || (element->getRealTime() > (*lastt)->getRealTime())) {
                break;
            }

            if (dropped) {
                last.add(element);
                if (worstPid
                        && ((!gc && (element->getPid() == worstPid))
                            || (mLastWorstPidOfSystem[id].find(element->getPid())
                                == mLastWorstPidOfSystem[id].end()))) {
                    // element->getUid() may not be AID_SYSTEM, next best
                    // watermark if current one empty.
                    mLastWorstPidOfSystem[id][element->getPid()] = it;
                }
                if ((!gc && !worstPid && (element->getUid() == worst))
                        || (mLastWorstUid[id].find(element->getUid())
                            == mLastWorstUid[id].end())) {
                    mLastWorstUid[id][element->getUid()] = it;
                }
                ++it;
                continue;
            }

            if ((element->getUid() != worst)
                    || (worstPid && (element->getPid() != worstPid))) {
                leading = false;
                last.clear(element);
                ++it;
                continue;
            }
            // key == worst below here
            // If worstPid set, then element->getPid() == worstPid below here

            pruneRows--;
            if (pruneRows == 0) {
                break;
            }

            kick = true;

            unsigned short len = element->getMsgLen();

            // do not create any leading drops
            if (leading) {
                it = erase(it);
            } else {
                stats.drop(element);
                element->setDropped(1);
                if (last.coalesce(element, 1)) {
                    it = erase(it, true);
                } else {
                    last.add(element);
                    if (worstPid && (!gc
                                || (mLastWorstPidOfSystem[id].find(worstPid)
                                    == mLastWorstPidOfSystem[id].end()))) {
                        // element->getUid() may not be AID_SYSTEM, next best
                        // watermark if current one empty.
                        mLastWorstPidOfSystem[id][worstPid] = it;
                    }
                    if ((!gc && !worstPid) || (mLastWorstUid[id].find(worst)
                                == mLastWorstUid[id].end())) {
                        mLastWorstUid[id][worst] = it;
                    }
                    ++it;
                }
            }
            if (worst_sizes < second_worst_sizes) {
                break;
            }
            worst_sizes -= len;
        }
        last.clear();

        if (!kick || !mPrune.worstUidEnabled()) {
            break; // the following loop will ask bad clients to skip/drop
        }
    }
PRUNE:
#endif
    bool whitelist = false;
    bool hasWhitelist = (id != LOG_ID_SECURITY) && mPrune.nice() && !clearAll;
    it = mLastSet[id] ? mLast[id] : mLogElements.begin();
    while((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement *element = *it;

        if (element->getLogId() != id) {
            it++;
            continue;
        }

        if (!mLastSet[id] || ((*mLast[id])->getLogId() != id)) {
            mLast[id] = it;
            mLastSet[id] = true;
        }

        if (oldest && (oldest->mStart <= element->getSequence())) {
            busy = true;
            if (whitelist) {
                break;
            }

            if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                // kick a misbehaving log reader client off the island
                oldest->release_Locked();
            } else if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                oldest->triggerReader_Locked();
            } else {
                oldest->triggerSkip_Locked(id, pruneRows);
            }
            break;
        }

        if (hasWhitelist && !element->getDropped() && mPrune.nice(element)) {
            // WhiteListed
            whitelist = true;
            it++;
            continue;
        }

        it = erase(it);
        pruneRows--;
    }

    // Do not save the whitelist if we are reader range limited
    if (whitelist && (pruneRows > 0)) {
        it = mLastSet[id] ? mLast[id] : mLogElements.begin();
        while((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement *element = *it;

            if (element->getLogId() != id) {
                ++it;
                continue;
            }

            if (!mLastSet[id] || ((*mLast[id])->getLogId() != id)) {
                mLast[id] = it;
                mLastSet[id] = true;
            }

            if (oldest && (oldest->mStart <= element->getSequence())) {
                busy = true;
                if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                    // kick a misbehaving log reader client off the island
                    oldest->release_Locked();
                } else if (oldest->mTimeout.tv_sec || oldest->mTimeout.tv_nsec) {
                    oldest->triggerReader_Locked();
                } else {
                    oldest->triggerSkip_Locked(id, pruneRows);
                }
                break;
            }

            it = erase(it);
            pruneRows--;
        }
    }

    LogTimeEntry::unlock();

    return (pruneRows > 0) && busy;
}

// clear all rows of type "id" from the buffer.
bool LogBuffer::clear(log_id_t id, uid_t uid) {
    bool busy = true;
    // If it takes more than 4 tries (seconds) to clear, then kill reader(s)
    for (int retry = 4;;) {
        if (retry == 1) { // last pass
            // Check if it is still busy after the sleep, we say prune
            // one entry, not another clear run, so we are looking for
            // the quick side effect of the return value to tell us if
            // we have a _blocked_ reader.
            pthread_mutex_lock(&mLogElementsLock);
            busy = prune(id, 1, uid);
            pthread_mutex_unlock(&mLogElementsLock);
            // It is still busy, blocked reader(s), lets kill them all!
            // otherwise, lets be a good citizen and preserve the slow
            // readers and let the clear run (below) deal with determining
            // if we are still blocked and return an error code to caller.
            if (busy) {
                LogTimeEntry::lock();
                LastLogTimes::iterator times = mTimes.begin();
                while (times != mTimes.end()) {
                    LogTimeEntry *entry = (*times);
                    // Killer punch
                    if (entry->owned_Locked() && entry->isWatching(id)) {
                        entry->release_Locked();
                    }
                    times++;
                }
                LogTimeEntry::unlock();
            }
        }
        pthread_mutex_lock(&mLogElementsLock);
        busy = prune(id, ULONG_MAX, uid);
        pthread_mutex_unlock(&mLogElementsLock);
        if (!busy || !--retry) {
            break;
        }
        sleep (1); // Let reader(s) catch up after notification
    }
    return busy;
}

// get the used space associated with "id".
unsigned long LogBuffer::getSizeUsed(log_id_t id) {
    pthread_mutex_lock(&mLogElementsLock);
    size_t retval = stats.sizes(id);
    pthread_mutex_unlock(&mLogElementsLock);
    return retval;
}

// set the total space allocated to "id"
int LogBuffer::setSize(log_id_t id, unsigned long size) {
    // Reasonable limits ...
    if (!valid_size(size)) {
        return -1;
    }
    pthread_mutex_lock(&mLogElementsLock);
    log_buffer_size(id) = size;
    pthread_mutex_unlock(&mLogElementsLock);
    return 0;
}

// get the total space allocated to "id"
unsigned long LogBuffer::getSize(log_id_t id) {
    pthread_mutex_lock(&mLogElementsLock);
    size_t retval = log_buffer_size(id);
    pthread_mutex_unlock(&mLogElementsLock);
    return retval;
}

uint64_t LogBuffer::flushTo(
        SocketClient *reader, const uint64_t start,
        bool privileged, bool security,
        int (*filter)(const LogBufferElement *element, void *arg), void *arg) {
    LogBufferElementCollection::iterator it;
    uint64_t max = start;
    uid_t uid = reader->getUid();
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(arg);
    unsigned long oldit_value;

    pthread_mutex_lock(&mLogElementsLock);

    if (start <= 1) {
        // client wants to start from the beginning
        it = mLogElements.begin();
    } else {
        // Client wants to start from some specified time. Chances are
        // we are better off starting from the end of the time sorted list.
        for (it = mLogElements.end(); it != mLogElements.begin(); /* do nothing */) {
            --it;
            LogBufferElement *element = *it;
            if (element->getSequence() <= start) {
                it++;
                break;
            }
        }
    }

    for (; it != mLogElements.end(); ++it) {
        LogBufferElement *element = *it;

        oldit_value = (unsigned long)*it;

        if (!privileged && (element->getUid() != uid)) {
            continue;
        }

        if (!security && (element->getLogId() == LOG_ID_SECURITY)) {
            continue;
        }

        if (element->getSequence() <= start) {
            continue;
        }

        // NB: calling out to another object with mLogElementsLock held (safe)
        if (filter) {
            int ret = (*filter)(element, arg);
            if (ret == false) {
                continue;
            }
            if (ret != true) {
                break;
            }
        }

        pthread_mutex_unlock(&mLogElementsLock);

        // range locking in LastLogTimes looks after us
        max = element->flushTo(reader, this, privileged);

        if (max == element->FLUSH_ERROR) {
            return max;
        }

        pthread_mutex_lock(&mLogElementsLock);
        if (me->isError_Locked())
            break;

        if (oldit_value != (unsigned long)*it) {
            pthread_mutex_unlock(&mLogElementsLock);
            return max;
        }

    }
    pthread_mutex_unlock(&mLogElementsLock);

    return max;
}

std::string LogBuffer::formatStatistics(uid_t uid, pid_t pid,
                                        unsigned int logMask) {
    pthread_mutex_lock(&mLogElementsLock);

    std::string ret = stats.format(uid, pid, logMask);

    pthread_mutex_unlock(&mLogElementsLock);

    return ret;
}
