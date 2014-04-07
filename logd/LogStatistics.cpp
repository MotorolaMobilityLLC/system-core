/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <fcntl.h>
#include <stdarg.h>
#include <time.h>

#include <log/logger.h>
#include <private/android_filesystem_config.h>
#include <utils/String8.h>

#include "LogStatistics.h"

PidStatistics::PidStatistics(pid_t pid, char *name)
        : pid(pid)
        , mSizesTotal(0)
        , mElementsTotal(0)
        , mSizes(0)
        , mElements(0)
        , name(name)
{ }

#ifdef DO_NOT_ERROR_IF_PIDSTATISTICS_USES_A_COPY_CONSTRUCTOR
PidStatistics::PidStatistics(const PidStatistics &copy)
        : pid(copy->pid)
        , name(copy->name ? strdup(copy->name) : NULL)
        , mSizesTotal(copy->mSizesTotal)
        , mElementsTotal(copy->mElementsTotal)
        , mSizes(copy->mSizes)
        , mElements(copy->mElements)
{ }
#endif

PidStatistics::~PidStatistics() {
    free(name);
}

void PidStatistics::setName(char *new_name) {
    free(name);
    name = new_name;
}

void PidStatistics::add(unsigned short size) {
    mSizesTotal += size;
    ++mElementsTotal;
    mSizes += size;
    ++mElements;
}

bool PidStatistics::subtract(unsigned short size) {
    mSizes -= size;
    --mElements;
    return mElements == 0 && kill(pid, 0);
}

void PidStatistics::addTotal(size_t size, size_t element) {
    if (pid == gone) {
        mSizesTotal += size;
        mElementsTotal += element;
    }
}

// must call free to release return value
char *PidStatistics::pidToName(pid_t pid) {
    char *retval = NULL;
    if (pid != PidStatistics::gone) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), "/proc/%u/cmdline", pid);
        int fd = open(buffer, O_RDONLY);
        if (fd >= 0) {
            ssize_t ret = read(fd, buffer, sizeof(buffer));
            if (ret > 0) {
                buffer[sizeof(buffer)-1] = '\0';
                // frameworks intermediate state
                if (strcmp(buffer, "<pre-initialized>")) {
                    retval = strdup(buffer);
                }
            }
            close(fd);
        }
    }
    return retval;
}

UidStatistics::UidStatistics(uid_t uid)
        : uid(uid) {
    Pids.clear();
}

UidStatistics::~UidStatistics() {
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end();) {
        delete (*it);
        it = Pids.erase(it);
    }
}

void UidStatistics::add(unsigned short size, pid_t pid) {
    PidStatistics *p;
    PidStatisticsCollection::iterator last;
    PidStatisticsCollection::iterator it;
    for (last = it = begin(); it != end(); last = it, ++it) {
        p = *it;
        if (pid == p->getPid()) {
            p->add(size);
            // poor-man sort, bubble upwards if bigger than last
            if ((last != it) && ((*last)->sizesTotal() < p->sizesTotal())) {
                Pids.erase(it);
                Pids.insert(last, p);
            }
            return;
        }
    }
    // poor-man sort, insert if bigger than last or last is the gone entry.
    bool insert = (last != it)
        && ((p->getPid() == p->gone)
            || ((*last)->sizesTotal() < (size_t) size));
    p = new PidStatistics(pid, pidToName(pid));
    if (insert) {
        Pids.insert(last, p);
    } else {
        Pids.push_back(p);
    }
    p->add(size);
}

void UidStatistics::subtract(unsigned short size, pid_t pid) {
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if (pid == p->getPid()) {
            if (p->subtract(size)) {
                size_t szsTotal = p->sizesTotal();
                size_t elsTotal = p->elementsTotal();
                delete p;
                Pids.erase(it);
                it = end();
                --it;
                if (it == end()) {
                    p = new PidStatistics(p->gone);
                    Pids.push_back(p);
                } else {
                    p = *it;
                    if (p->getPid() != p->gone) {
                        p = new PidStatistics(p->gone);
                        Pids.push_back(p);
                    }
                }
                p->addTotal(szsTotal, elsTotal);
            }
            return;
        }
    }
}

size_t UidStatistics::sizes(pid_t pid) {
    size_t sizes = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            sizes += p->sizes();
        }
    }
    return sizes;
}

size_t UidStatistics::elements(pid_t pid) {
    size_t elements = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            elements += p->elements();
        }
    }
    return elements;
}

size_t UidStatistics::sizesTotal(pid_t pid) {
    size_t sizes = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            sizes += p->sizesTotal();
        }
    }
    return sizes;
}

size_t UidStatistics::elementsTotal(pid_t pid) {
    size_t elements = 0;
    PidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        PidStatistics *p = *it;
        if ((pid == pid_all) || (pid == p->getPid())) {
            elements += p->elementsTotal();
        }
    }
    return elements;
}

LidStatistics::LidStatistics() {
    Uids.clear();
}

LidStatistics::~LidStatistics() {
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end();) {
        delete (*it);
        it = Uids.erase(it);
    }
}

void LidStatistics::add(unsigned short size, uid_t uid, pid_t pid) {
    UidStatistics *u;
    UidStatisticsCollection::iterator it;
    UidStatisticsCollection::iterator last;

    if (uid == (uid_t) -1) { // init
        uid = (uid_t) AID_ROOT;
    }

    for (last = it = begin(); it != end(); last = it, ++it) {
        u = *it;
        if (uid == u->getUid()) {
            u->add(size, pid);
            if ((last != it) && ((*last)->sizesTotal() < u->sizesTotal())) {
                Uids.erase(it);
                Uids.insert(last, u);
            }
            return;
        }
    }
    u = new UidStatistics(uid);
    if ((last != it) && ((*last)->sizesTotal() < (size_t) size)) {
        Uids.insert(last, u);
    } else {
        Uids.push_back(u);
    }
    u->add(size, pid);
}

void LidStatistics::subtract(unsigned short size, uid_t uid, pid_t pid) {
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if (uid == u->getUid()) {
            u->subtract(size, pid);
            return;
        }
    }
}

size_t LidStatistics::sizes(uid_t uid, pid_t pid) {
    size_t sizes = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            sizes += u->sizes(pid);
        }
    }
    return sizes;
}

size_t LidStatistics::elements(uid_t uid, pid_t pid) {
    size_t elements = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            elements += u->elements(pid);
        }
    }
    return elements;
}

size_t LidStatistics::sizesTotal(uid_t uid, pid_t pid) {
    size_t sizes = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            sizes += u->sizesTotal(pid);
        }
    }
    return sizes;
}

size_t LidStatistics::elementsTotal(uid_t uid, pid_t pid) {
    size_t elements = 0;
    UidStatisticsCollection::iterator it;
    for (it = begin(); it != end(); ++it) {
        UidStatistics *u = *it;
        if ((uid == uid_all) || (uid == u->getUid())) {
            elements += u->elementsTotal(pid);
        }
    }
    return elements;
}

LogStatistics::LogStatistics()
        : start(CLOCK_MONOTONIC) {
    log_id_for_each(i) {
        mSizes[i] = 0;
        mElements[i] = 0;
    }

    dgram_qlen_statistics = false;
    for(unsigned short bucket = 0; dgram_qlen(bucket); ++bucket) {
        mMinimum[bucket].tv_sec = (uint32_t)-1;
        mMinimum[bucket].tv_nsec = 999999999UL;
    }
}

//   Each bucket below represents a dgram_qlen of log messages. By
//   finding the minimum period of time from start to finish
//   of each dgram_qlen, we can get a performance expectation for
//   the user space logger. The net result is that the period
//   of time divided by the dgram_qlen will give us the average time
//   between log messages; at the point where the average time
//   is greater than the throughput capability of the logger
//   we will not longer require the benefits of the FIFO formed
//   by max_dgram_qlen. We will also expect to see a very visible
//   knee in the average time between log messages at this point,
//   so we do not necessarily have to compare the rate against the
//   measured performance (BM_log_maximum_retry) of the logger.
//
//   for example (reformatted):
//
//       Minimum time between log events per dgram_qlen:
//       1   2   3   5   10  20  30  50  100  200 300 400 500 600
//       5u2 12u 13u 15u 16u 27u 30u 36u 407u 3m1 3m3 3m9 3m9 5m5
//
//   demonstrates a clear knee rising at 100, so this means that for this
//   case max_dgram_qlen = 100 would be more than sufficient to handle the
//   worst that the system could stuff into the logger. The
//   BM_log_maximum_retry performance (derated by the log collection) on the
//   same system was 33.2us so we would almost be fine with max_dgram_qlen = 50.
//   BM_log_maxumum_retry with statistics off is roughly 20us, so
//   max_dgram_qlen = 20 would work. We will be more than willing to have
//   a large engineering margin so the rule of thumb that lead us to 100 is
//   fine.
//
// bucket dgram_qlen are tuned for /proc/sys/net/unix/max_dgram_qlen = 300
const unsigned short LogStatistics::mBuckets[] = {
    1, 2, 3, 5, 10, 20, 30, 50, 100, 200, 300, 400, 500, 600
};

unsigned short LogStatistics::dgram_qlen(unsigned short bucket) {
    if (bucket >= sizeof(mBuckets) / sizeof(mBuckets[0])) {
        return 0;
    }
    return mBuckets[bucket];
}

unsigned long long LogStatistics::minimum(unsigned short bucket) {
    if (mMinimum[bucket].tv_sec == LONG_MAX) {
        return 0;
    }
    return mMinimum[bucket].nsec();
}

void LogStatistics::recordDiff(log_time diff, unsigned short bucket) {
    if ((diff.tv_sec || diff.tv_nsec) && (mMinimum[bucket] > diff)) {
        mMinimum[bucket] = diff;
    }
}

void LogStatistics::add(unsigned short size,
                        log_id_t log_id, uid_t uid, pid_t pid) {
    mSizes[log_id] += size;
    ++mElements[log_id];
    id(log_id).add(size, uid, pid);
}

void LogStatistics::subtract(unsigned short size,
                             log_id_t log_id, uid_t uid, pid_t pid) {
    mSizes[log_id] -= size;
    --mElements[log_id];
    id(log_id).subtract(size, uid, pid);
}

size_t LogStatistics::sizes(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).sizes(uid, pid);
    }
    size_t sizes = 0;
    log_id_for_each(i) {
        sizes += id(i).sizes(uid, pid);
    }
    return sizes;
}

size_t LogStatistics::elements(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).elements(uid, pid);
    }
    size_t elements = 0;
    log_id_for_each(i) {
        elements += id(i).elements(uid, pid);
    }
    return elements;
}

size_t LogStatistics::sizesTotal(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).sizesTotal(uid, pid);
    }
    size_t sizes = 0;
    log_id_for_each(i) {
        sizes += id(i).sizesTotal(uid, pid);
    }
    return sizes;
}

size_t LogStatistics::elementsTotal(log_id_t log_id, uid_t uid, pid_t pid) {
    if (log_id != log_id_all) {
        return id(log_id).elementsTotal(uid, pid);
    }
    size_t elements = 0;
    log_id_for_each(i) {
        elements += id(i).elementsTotal(uid, pid);
    }
    return elements;
}

void LogStatistics::format(char **buf,
                           uid_t uid, unsigned int logMask, log_time oldest) {
    static const unsigned short spaces_current = 13;
    static const unsigned short spaces_total = 19;

    if (*buf) {
        free(buf);
        *buf = NULL;
    }

    android::String8 string("        span -> size/num");
    size_t oldLength;
    short spaces = 2;

    log_id_for_each(i) {
        if (logMask & (1 << i)) {
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%s", spaces, "", android_log_id_to_name(i));
            spaces += spaces_total + oldLength - string.length();
        }
    }

    spaces = 1;
    log_time t(CLOCK_MONOTONIC);
    unsigned long long d = t.nsec() - start.nsec();
    string.appendFormat("\nTotal%4llu:%02llu:%02llu.%09llu",
                  d / NS_PER_SEC / 60 / 60, (d / NS_PER_SEC / 60) % 60,
                  (d / NS_PER_SEC) % 60, d % NS_PER_SEC);

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }
        oldLength = string.length();
        if (spaces < 0) {
            spaces = 0;
        }
        string.appendFormat("%*s%zu/%zu", spaces, "",
                            sizesTotal(i), elementsTotal(i));
        spaces += spaces_total + oldLength - string.length();
    }

    spaces = 1;
    d = t.nsec() - oldest.nsec();
    string.appendFormat("\nNow%6llu:%02llu:%02llu.%09llu",
                  d / NS_PER_SEC / 60 / 60, (d / NS_PER_SEC / 60) % 60,
                  (d / NS_PER_SEC) % 60, d % NS_PER_SEC);

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        size_t els = elements(i);
        if (els) {
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%zu/%zu", spaces, "", sizes(i), els);
            spaces -= string.length() - oldLength;
        }
        spaces += spaces_total;
    }

    if (dgram_qlen_statistics) {
        const unsigned short spaces_time = 6;
        const unsigned long long max_seconds = 100000;
        spaces = 0;
        string.append("\n\nMinimum time between log events per dgram_qlen:\n");
        for(unsigned short i = 0; dgram_qlen(i); ++i) {
            oldLength = string.length();
            if (spaces < 0) {
                spaces = 0;
            }
            string.appendFormat("%*s%u", spaces, "", dgram_qlen(i));
            spaces += spaces_time + oldLength - string.length();
        }
        string.append("\n");
        spaces = 0;
        unsigned short n;
        for(unsigned short i = 0; (n = dgram_qlen(i)); ++i) {
            unsigned long long duration = minimum(i);
            if (duration) {
                duration /= n;
                if (duration >= (NS_PER_SEC * max_seconds)) {
                    duration = NS_PER_SEC * (max_seconds - 1);
                }
                oldLength = string.length();
                if (spaces < 0) {
                    spaces = 0;
                }
                string.appendFormat("%*s", spaces, "");
                if (duration >= (NS_PER_SEC * 10)) {
                    string.appendFormat("%llu",
                        (duration + (NS_PER_SEC / 2))
                            / NS_PER_SEC);
                } else if (duration >= (NS_PER_SEC / (1000 / 10))) {
                    string.appendFormat("%llum",
                        (duration + (NS_PER_SEC / 2 / 1000))
                            / (NS_PER_SEC / 1000));
                } else if (duration >= (NS_PER_SEC / (1000000 / 10))) {
                    string.appendFormat("%lluu",
                         (duration + (NS_PER_SEC / 2 / 1000000))
                             / (NS_PER_SEC / 1000000));
                } else {
                    string.appendFormat("%llun", duration);
                }
                spaces -= string.length() - oldLength;
            }
            spaces += spaces_time;
        }
    }

    log_id_for_each(i) {
        if (!(logMask & (1 << i))) {
            continue;
        }

        bool header = false;
        bool first = true;

        UidStatisticsCollection::iterator ut;
        for(ut = id(i).begin(); ut != id(i).end(); ++ut) {
            UidStatistics *up = *ut;
            if ((uid != AID_ROOT) && (uid != up->getUid())) {
                continue;
            }

            PidStatisticsCollection::iterator pt = up->begin();
            if (pt == up->end()) {
                continue;
            }

            android::String8 intermediate;

            if (!header) {
                // header below tuned to match spaces_total and spaces_current
                spaces = 0;
                intermediate = string.format("%s: UID/PID Total size/num",
                                             android_log_id_to_name(i));
                string.appendFormat("\n\n%-31sNow          "
                                         "UID/PID[?]  Total              Now",
                                    intermediate.string());
                intermediate.clear();
                header = true;
            }

            bool oneline = ++pt == up->end();
            --pt;

            if (!oneline) {
                first = true;
            } else if (!first && (spaces > 0)) {
                string.appendFormat("%*s", spaces, "");
            }
            spaces = 0;

            uid_t u = up->getUid();
            pid_t p = (*pt)->getPid();

            intermediate = string.format(oneline
                                             ? ((p == PidStatistics::gone)
                                                 ? "%d/?"
                                                 : "%d/%d")
                                             : "%d",
                                         u, p);
            string.appendFormat((first) ? "\n%-12s" : "%-12s",
                                intermediate.string());
            intermediate.clear();

            size_t elsTotal = up->elementsTotal();
            oldLength = string.length();
            string.appendFormat("%zu/%zu", up->sizesTotal(), elsTotal);
            spaces += spaces_total + oldLength - string.length();

            size_t els = up->elements();
            if (els == elsTotal) {
                if (spaces < 0) {
                    spaces = 0;
                }
                string.appendFormat("%*s=", spaces, "");
                spaces = -1;
            } else if (els) {
                oldLength = string.length();
                if (spaces < 0) {
                    spaces = 0;
                }
                string.appendFormat("%*s%zu/%zu", spaces, "", up->sizes(), els);
                spaces -= string.length() - oldLength;
            }
            spaces += spaces_current;

            first = !first;

            if (oneline) {
                continue;
            }

            size_t gone_szs = 0;
            size_t gone_els = 0;

            for(; pt != up->end(); ++pt) {
                PidStatistics *pp = *pt;
                pid_t p = pp->getPid();

                // If a PID no longer has any current logs, and is not
                // active anymore, skip & report totals for gone.
                elsTotal = pp->elementsTotal();
                size_t szsTotal = pp->sizesTotal();
                if (p == pp->gone) {
                    gone_szs += szsTotal;
                    gone_els += elsTotal;
                    continue;
                }
                els = pp->elements();
                bool gone = kill(p, 0);
                if (gone && (els == 0)) {
                    // ToDo: garbage collection: move this statistical bucket
                    //       from its current UID/PID to UID/? (races and
                    //       wrap around are our achilles heel). Below is
                    //       merely lipservice to catch PIDs that were still
                    //       around when the stats were pruned to zero.
                    gone_szs += szsTotal;
                    gone_els += elsTotal;
                    continue;
                }

                if (!first && (spaces > 0)) {
                    string.appendFormat("%*s", spaces, "");
                }
                spaces = 0;

                intermediate = string.format((gone) ? "%d/%d?" : "%d/%d", u, p);
                string.appendFormat((first) ? "\n%-12s" : "%-12s",
                                    intermediate.string());
                intermediate.clear();

                oldLength = string.length();
                string.appendFormat("%zu/%zu", szsTotal, elsTotal);
                spaces += spaces_total + oldLength - string.length();

                if (els == elsTotal) {
                    if (spaces < 0) {
                        spaces = 0;
                    }
                    string.appendFormat("%*s=", spaces, "");
                    spaces = -1;
                } else if (els) {
                    oldLength = string.length();
                    if (spaces < 0) {
                        spaces = 0;
                    }
                    string.appendFormat("%*s%zu/%zu", spaces, "",
                                        pp->sizes(), els);
                    spaces -= string.length() - oldLength;
                }
                spaces += spaces_current;

                first = !first;
            }

            if (gone_els) {
                if (!first && (spaces > 0)) {
                    string.appendFormat("%*s", spaces, "");
                }

                intermediate = string.format("%d/?", u);
                string.appendFormat((first) ? "\n%-12s" : "%-12s",
                                    intermediate.string());
                intermediate.clear();

                spaces = spaces_total + spaces_current;

                oldLength = string.length();
                string.appendFormat("%zu/%zu", gone_szs, gone_els);
                spaces -= string.length() - oldLength;

                first = !first;
            }
        }
    }

    *buf = strdup(string.string());
}

uid_t LogStatistics::pidToUid(pid_t pid) {
    log_id_for_each(i) {
        LidStatistics &l = id(i);
        UidStatisticsCollection::iterator iu;
        for (iu = l.begin(); iu != l.end(); ++iu) {
            UidStatistics &u = *(*iu);
            PidStatisticsCollection::iterator ip;
            for (ip = u.begin(); ip != u.end(); ++ip) {
                if ((*ip)->getPid() == pid) {
                    return u.getUid();
                }
            }
        }
    }
    return getuid(); // associate this with the logger
}
