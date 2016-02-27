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
#include "LogReader.h"
#include "logutils.h"

// Default
#define LOG_BUFFER_SIZE (256 * 1024) // Tuned on a per-platform basis here?
#define log_buffer_size(id) mMaxSize[id]
#define LOG_BUFFER_MIN_SIZE (64 * 1024UL)
#define LOG_BUFFER_MAX_SIZE (256 * 1024 * 1024UL)

#define DEBUG_DETECT_LOG_COUNT  5000

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

#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG)
static void *logd_memory_leak_thread_start(void * /*obj*/) {
    prctl(PR_SET_NAME, "logd.memoryleak");
    set_sched_policy(0, SP_FOREGROUND);
    aee_system_warning("Logd memory leak", NULL, DB_OPT_DEFAULT, "Logd memory leak");
    return NULL;
}
#endif

#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG)
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
    }

    log_id_for_each(i) {
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

        if (setSize(i, property_size)) {
            setSize(i, LOG_BUFFER_MIN_SIZE);
        }
    }
}

LogBuffer::LogBuffer(LastLogTimes *times) : mTimes(*times) {
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
    struct timespec ts_0, ts_1, ts_2, ts_3, ts_4;
    static struct timespec ts_diff;
    static uint64_t diff_time[4] = {0};
    static uint64_t total_time;
    static uint32_t diff_count = 0;
    static uint32_t filter_count = 0;
    int time_find_count = 0;

    ts_0 = ts_1 = ts_2 = ts_3 = ts_4 = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &ts_0);
    if (log_id == LOG_ID_EVENTS) {
        tag = android::tagToName(elem->getTag());
    } else {
        prio = *msg;
        tag = msg + 1;
    }
    if (!__android_log_is_loggable(prio, tag, ANDROID_LOG_VERBOSE)) {
        // Log traffic received to total
        pthread_mutex_lock(&mLogElementsLock);
            stats.add_total_size(elem);
        pthread_mutex_unlock(&mLogElementsLock);
        delete elem;
        clock_gettime(CLOCK_MONOTONIC, &ts_1);
        diff_time[0] += (ts_1.tv_sec - ts_0.tv_sec)*1000000000-ts_0.tv_nsec+ts_1.tv_nsec;
            filter_count++;
        return -EACCES;
    }
        clock_gettime(CLOCK_MONOTONIC, &ts_1);

    pthread_mutex_lock(&mLogElementsLock);

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
    clock_gettime(CLOCK_MONOTONIC, &ts_2);

    if (last == mLogElements.end() || time_find_count > 20) {
        mLogElements.push_back(elem);
    } else {
        uint64_t end = 1;
        bool end_set = false;
        bool end_always = false;

        LogTimeEntry::lock();

        LastLogTimes::iterator t = mTimes.begin();
        while(t != mTimes.end()) {
            LogTimeEntry *entry = (*t);
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
            t++;
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
    clock_gettime(CLOCK_MONOTONIC, &ts_3);
    maybePrune(log_id);
    pthread_mutex_unlock(&mLogElementsLock);

    clock_gettime(CLOCK_MONOTONIC, &ts_4);
    diff_time[0] += (ts_1.tv_sec - ts_0.tv_sec)*1000000000-ts_0.tv_nsec+ts_1.tv_nsec;
    diff_time[1] += (ts_2.tv_sec - ts_1.tv_sec)*1000000000-ts_1.tv_nsec+ts_2.tv_nsec;
    diff_time[2] += (ts_3.tv_sec - ts_2.tv_sec)*1000000000-ts_2.tv_nsec+ts_3.tv_nsec;
    diff_time[3] += (ts_4.tv_sec - ts_3.tv_sec)*1000000000-ts_3.tv_nsec+ts_4.tv_nsec;
    total_time += (ts_4.tv_sec - ts_0.tv_sec)*1000000000-ts_0.tv_nsec+ts_4.tv_nsec;
    diff_count++;

    if (diff_count >= DEBUG_DETECT_LOG_COUNT) {
         kernel_log_print("logd:diff time %ld, run time  %ld, count %d,step 1 %d,2 %d,3 %d,4 %d. filter count %d.\n",
             (ts_4.tv_sec-ts_diff.tv_sec)*1000000000-ts_diff.tv_nsec+ts_4.tv_nsec, total_time, diff_count,
             diff_time[0]/diff_count, diff_time[1]/diff_count, diff_time[2]/diff_count, diff_time[3]/diff_count,
             filter_count);
#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG)
        static bool performance_issue;
        if ((performance_issue == false)  && (total_time / DEBUG_DETECT_LOG_COUNT > 1000000)) {
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

    return len;
}

// If we're using more than 256K of memory for log entries, prune
// at least 10% of the log entries.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::maybePrune(log_id_t id) {
    size_t sizes = stats.sizes(id);
    if (sizes > log_buffer_size(id)) {
        size_t sizeOver90Percent = sizes - ((log_buffer_size(id) * 9) / 10);
        size_t elements = stats.elements(id);
        unsigned long pruneRows = elements * sizeOver90Percent / sizes;
        elements /= 10;
        if (pruneRows <= elements) {
            pruneRows = elements;
        }
        prune(id, pruneRows);
    }
}

LogBufferElementCollection::iterator LogBuffer::erase(LogBufferElementCollection::iterator it) {
    LogBufferElement *e = *it;

    it = mLogElements.erase(it);
    stats.subtract(e);
    delete e;

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
    LogBufferElementKey(uid_t u, pid_t p, pid_t t):uid(u),pid(p),tid(t),padding(0) { }
    LogBufferElementKey(uint64_t k):value(k) { }

    uint64_t getKey() { return value; }
};

class LogBufferElementLast {

    typedef std::unordered_map<uint64_t, LogBufferElement *> LogBufferElementMap;
    LogBufferElementMap map;

public:

    bool merge(LogBufferElement *e, unsigned short dropped) {
        LogBufferElementKey key(e->getUid(), e->getPid(), e->getTid());
        LogBufferElementMap::iterator it = map.find(key.getKey());
        if (it != map.end()) {
            LogBufferElement *l = it->second;
            unsigned short d = l->getDropped();
            if ((dropped + d) > USHRT_MAX) {
                map.erase(it);
            } else {
                l->setDropped(dropped + d);
                return true;
            }
        }
        return false;
    }

    void add(LogBufferElement *e) {
        LogBufferElementKey key(e->getUid(), e->getPid(), e->getTid());
        map[key.getKey()] = e;
    }

    inline void clear() {
        map.clear();
    }

    void clear(LogBufferElement *e) {
        uint64_t current = e->getRealTime().nsec()
                         - (EXPIRE_RATELIMIT * NS_PER_SEC);
        for(LogBufferElementMap::iterator it = map.begin(); it != map.end();) {
            LogBufferElement *l = it->second;
            if ((l->getDropped() >= EXPIRE_THRESHOLD)
                    && (current > l->getRealTime().nsec())) {
                it = map.erase(it);
            } else {
                ++it;
            }
        }
    }

};

// prune "pruneRows" of type "id" from the buffer.
//
// mLogElementsLock must be held when this function is called.
void LogBuffer::prune(log_id_t id, unsigned long pruneRows, uid_t caller_uid) {
    LogTimeEntry *oldest = NULL;
    int Times_count = 0;

    LogTimeEntry::lock();

    // Region locked?
    LastLogTimes::iterator t = mTimes.begin();
    while(t != mTimes.end()) {
        LogTimeEntry *entry = (*t);
        if (entry->owned_Locked() && entry->isWatching(id)
                && (!oldest || (oldest->mStart > entry->mStart))) {
            oldest = entry;
        }
        t++;
        Times_count++;
    }

    LogBufferElementCollection::iterator it;

    if (stats.sizes(id) > (10 * log_buffer_size(id))) {
        if (oldest) {
            oldest->release_Locked();
        }

        kernel_log_print("logd: have %d read thread, the %d log size is %d.\n",
            Times_count, id, stats.sizes(id));

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

        LogTimeEntry::unlock();
#if defined(HAVE_AEE_FEATURE) && defined(MTK_LOGD_DEBUG)
        pthread_attr_t attr_m;
        static bool memory_issue;

        if (memory_issue == true)
            return;

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
        return;
    }

    if (oldest && (oldest->getSkipAhead(id) != 0)) {
        //kernel_log_print("oldest still has skip item!%ld", stats.sizes(id));
        LogTimeEntry::unlock();
        return;
    }



    if (caller_uid != AID_ROOT) {
        for(it = mLogElements.begin(); it != mLogElements.end();) {
            LogBufferElement *e = *it;

            if (oldest && (oldest->mStart <= e->getSequence())) {
                break;
            }

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            if (e->getUid() == caller_uid) {
                it = erase(it);
                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }
            } else {
                ++it;
            }
        }
        LogTimeEntry::unlock();
        return;
    }

    // prune by worst offender by uid
    bool hasBlacklist = mPrune.naughty();
    goto PRUNE;
    while (pruneRows > 0) {
        // recalculate the worst offender on every batched pass
        uid_t worst = (uid_t) -1;
        size_t worst_sizes = 0;
        size_t second_worst_sizes = 0;

        if (worstUidEnabledForLogid(id) && mPrune.worstUidEnabled()) {
            std::unique_ptr<const UidEntry *[]> sorted = stats.sort(2, id);

            if (sorted.get()) {
                if (sorted[0] && sorted[1]) {
                    worst_sizes = sorted[0]->getSizes();
                    // Calculate threshold as 12.5% of available storage
                    size_t threshold = log_buffer_size(id) / 8;
                    if (worst_sizes > threshold) {
                        worst = sorted[0]->getKey();
                        second_worst_sizes = sorted[1]->getSizes();
                        if (second_worst_sizes < threshold) {
                            second_worst_sizes = threshold;
                        }
                    }
                }
            }
        }

        // skip if we have neither worst nor naughty filters
        if ((worst == (uid_t) -1) && !hasBlacklist) {
            break;
        }

        bool kick = false;
        bool leading = true;
        LogBufferElementLast last;
        for(it = mLogElements.begin(); it != mLogElements.end();) {
            LogBufferElement *e = *it;

            if (oldest && (oldest->mStart <= e->getSequence())) {
                break;
            }

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            unsigned short dropped = e->getDropped();

            // remove any leading drops
            if (leading && dropped) {
                it = erase(it);
                continue;
            }

            // merge any drops
            if (dropped && last.merge(e, dropped)) {
                it = mLogElements.erase(it);
                stats.erase(e);
                delete e;
                continue;
            }

            if (hasBlacklist && mPrune.naughty(e)) {
                last.clear(e);
                it = erase(it);
                if (dropped) {
                    continue;
                }

                pruneRows--;
                if (pruneRows == 0) {
                    break;
                }

                if (e->getUid() == worst) {
                    kick = true;
                    if (worst_sizes < second_worst_sizes) {
                        break;
                    }
                    worst_sizes -= e->getMsgLen();
                }
                continue;
            }

            if (dropped) {
                last.add(e);
                ++it;
                continue;
            }

            if (e->getUid() != worst) {
                if (leading) {
                    static const timespec too_old = {
                        EXPIRE_HOUR_THRESHOLD * 60 * 60, 0
                    };
                    LogBufferElementCollection::iterator last;
                    last = mLogElements.end();
                    --last;
                    if ((e->getRealTime() < ((*last)->getRealTime() - too_old))
                            || (e->getRealTime() > (*last)->getRealTime())) {
                        break;
                    }
                }
                leading = false;
                last.clear(e);
                ++it;
                continue;
            }

            pruneRows--;
            if (pruneRows == 0) {
                break;
            }

            kick = true;

            unsigned short len = e->getMsgLen();

            // do not create any leading drops
            if (leading) {
                it = erase(it);
            } else {
                stats.drop(e);
                e->setDropped(1);
                if (last.merge(e, 1)) {
                    it = mLogElements.erase(it);
                    stats.erase(e);
                    delete e;
                } else {
                    last.add(e);
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
    bool whitelist = false;
    bool hasWhitelist = mPrune.nice();
    it = mLogElements.begin();
    while((pruneRows > 0) && (it != mLogElements.end())) {
        LogBufferElement *e = *it;

        if (e->getLogId() != id) {
            it++;
            continue;
        }

        if (oldest && (oldest->mStart <= e->getSequence())) {
            if (whitelist) {
                break;
            }

            if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                // kick a misbehaving log reader client off the island
                oldest->release_Locked();
            } else {
                oldest->triggerSkip_Locked(id, pruneRows);
            }
            break;
        }

        if (hasWhitelist && !e->getDropped() && mPrune.nice(e)) { // WhiteListed
            whitelist = true;
            it++;
            continue;
        }

        it = erase(it);
        pruneRows--;
    }

    // Do not save the whitelist if we are reader range limited
    if (whitelist && (pruneRows > 0)) {
        it = mLogElements.begin();
        while((it != mLogElements.end()) && (pruneRows > 0)) {
            LogBufferElement *e = *it;

            if (e->getLogId() != id) {
                ++it;
                continue;
            }

            if (oldest && (oldest->mStart <= e->getSequence())) {
                if (stats.sizes(id) > (2 * log_buffer_size(id))) {
                    // kick a misbehaving log reader client off the island
                    oldest->release_Locked();
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
}

// clear all rows of type "id" from the buffer.
void LogBuffer::clear(log_id_t id, uid_t uid) {
    pthread_mutex_lock(&mLogElementsLock);
    prune(id, ULONG_MAX, uid);
    pthread_mutex_unlock(&mLogElementsLock);
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
        SocketClient *reader, const uint64_t start, bool privileged,
        int (*filter)(const LogBufferElement *element, void *arg), void *arg) {
    LogBufferElementCollection::iterator it;
    uint64_t max = start;
    uid_t uid = reader->getUid();

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

        if (!privileged && (element->getUid() != uid)) {
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
        max = element->flushTo(reader, this);

        if (max == element->FLUSH_ERROR) {
            return max;
        }

        pthread_mutex_lock(&mLogElementsLock);
    }
    pthread_mutex_unlock(&mLogElementsLock);

    return max;
}

void LogBuffer::formatStatistics(char **strp, uid_t uid, unsigned int logMask) {
    pthread_mutex_lock(&mLogElementsLock);

    stats.format(strp, uid, logMask);

    pthread_mutex_unlock(&mLogElementsLock);
}
