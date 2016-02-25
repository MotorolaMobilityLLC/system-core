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
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include <string>

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <log/log.h>
#include <log/logger.h>

#include "../LogReader.h" // pickup LOGD_SNDTIMEO

/*
 * returns statistics
 */
static void my_android_logger_get_statistics(char *buf, size_t len)
{
    snprintf(buf, len, "getStatistics 0 1 2 3 4");
    int sock = socket_local_client("logd",
                                   ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);
    if (sock >= 0) {
        if (write(sock, buf, strlen(buf) + 1) > 0) {
            ssize_t ret;
            while ((ret = read(sock, buf, len)) > 0) {
                if ((size_t)ret == len) {
                    break;
                }
                len -= ret;
                buf += ret;

                struct pollfd p = {
                    .fd = sock,
                    .events = POLLIN,
                    .revents = 0
                };

                ret = poll(&p, 1, 20);
                if ((ret <= 0) || !(p.revents & POLLIN)) {
                    break;
                }
            }
        }
        close(sock);
    }
}

static void alloc_statistics(char **buffer, size_t *length)
{
    size_t len = 8192;
    char *buf;

    for(int retry = 32; (retry >= 0); delete [] buf, --retry) {
        buf = new char [len];
        my_android_logger_get_statistics(buf, len);

        buf[len-1] = '\0';
        size_t ret = atol(buf) + 1;
        if (ret < 4) {
            delete [] buf;
            buf = NULL;
            break;
        }
        bool check = ret <= len;
        len = ret;
        if (check) {
            break;
        }
        len += len / 8; // allow for some slop
    }
    *buffer = buf;
    *length = len;
}

static char *find_benchmark_spam(char *cp)
{
    // liblog_benchmarks has been run designed to SPAM.  The signature of
    // a noisiest UID statistics is:
    //
    // Chattiest UIDs in main log buffer:                           Size Pruned
    // UID   PACKAGE                                                BYTES LINES
    // 0     root                                                  54164 147569
    //
    char *benchmark = NULL;
    do {
        static const char signature[] = "\n0     root ";

        benchmark = strstr(cp, signature);
        if (!benchmark) {
            break;
        }
        cp = benchmark + sizeof(signature);
        while (isspace(*cp)) {
            ++cp;
        }
        benchmark = cp;
#ifdef DEBUG
        char *end = strstr(benchmark, "\n");
        if (end == NULL) {
            end = benchmark + strlen(benchmark);
        }
        fprintf(stderr, "parse for spam counter in \"%.*s\"\n",
                (int)(end - benchmark), benchmark);
#endif
        // content
        while (isdigit(*cp)) {
            ++cp;
        }
        while (isspace(*cp)) {
            ++cp;
        }
        // optional +/- field?
        if ((*cp == '-') || (*cp == '+')) {
            while (isdigit(*++cp) ||
                   (*cp == '.') || (*cp == '%') || (*cp == 'X')) {
                ;
            }
            while (isspace(*cp)) {
                ++cp;
            }
        }
        // number of entries pruned
        unsigned long value = 0;
        while (isdigit(*cp)) {
            value = value * 10ULL + *cp - '0';
            ++cp;
        }
        if (value > 10UL) {
            break;
        }
        benchmark = NULL;
    } while (*cp);
    return benchmark;
}

TEST(logd, statistics) {
    size_t len;
    char *buf;

    alloc_statistics(&buf, &len);

    ASSERT_TRUE(NULL != buf);

    // remove trailing FF
    char *cp = buf + len - 1;
    *cp = '\0';
    bool truncated = *--cp != '\f';
    if (!truncated) {
        *cp = '\0';
    }

    // squash out the byte count
    cp = buf;
    if (!truncated) {
        while (isdigit(*cp) || (*cp == '\n')) {
            ++cp;
        }
    }

    fprintf(stderr, "%s", cp);

    EXPECT_LT((size_t)64, strlen(cp));

    EXPECT_EQ(0, truncated);

    char *main_logs = strstr(cp, "\nChattiest UIDs in main ");
    EXPECT_TRUE(NULL != main_logs);

    char *radio_logs = strstr(cp, "\nChattiest UIDs in radio ");
    EXPECT_TRUE(NULL != radio_logs);

    char *system_logs = strstr(cp, "\nChattiest UIDs in system ");
    EXPECT_TRUE(NULL != system_logs);

    char *events_logs = strstr(cp, "\nChattiest UIDs in events ");
    EXPECT_TRUE(NULL != events_logs);

    delete [] buf;
}

static void caught_signal(int /* signum */) { }

static void dump_log_msg(const char *prefix,
                         log_msg *msg, unsigned int version, int lid) {
    std::cout << std::flush;
    std::cerr << std::flush;
    fflush(stdout);
    fflush(stderr);
    switch(msg->entry.hdr_size) {
    case 0:
        version = 1;
        break;

    case sizeof(msg->entry_v2):
        if (version == 0) {
            version = 2;
        }
        break;
    }

    fprintf(stderr, "%s: v%u[%u] ", prefix, version, msg->len());
    if (version != 1) {
        fprintf(stderr, "hdr_size=%u ", msg->entry.hdr_size);
    }
    fprintf(stderr, "pid=%u tid=%u %u.%09u ",
            msg->entry.pid, msg->entry.tid, msg->entry.sec, msg->entry.nsec);
    switch(version) {
    case 1:
         break;
    case 2:
        fprintf(stderr, "euid=%u ", msg->entry_v2.euid);
        break;
    case 3:
    default:
        lid = msg->entry.lid;
        break;
    }

    switch(lid) {
    case 0:
        fprintf(stderr, "lid=main ");
        break;
    case 1:
        fprintf(stderr, "lid=radio ");
        break;
    case 2:
        fprintf(stderr, "lid=events ");
        break;
    case 3:
        fprintf(stderr, "lid=system ");
        break;
    case 4:
        fprintf(stderr, "lid=crash ");
        break;
    case 5:
        fprintf(stderr, "lid=security ");
        break;
    case 6:
        fprintf(stderr, "lid=kernel ");
        break;
    default:
        if (lid >= 0) {
            fprintf(stderr, "lid=%d ", lid);
        }
    }

    unsigned int len = msg->entry.len;
    fprintf(stderr, "msg[%u]={", len);
    unsigned char *cp = reinterpret_cast<unsigned char *>(msg->msg());
    while(len) {
        unsigned char *p = cp;
        while (*p && (((' ' <= *p) && (*p < 0x7F)) || (*p == '\n'))) {
            ++p;
        }
        if (((p - cp) > 3) && !*p && ((unsigned int)(p - cp) < len)) {
            fprintf(stderr, "\"");
            while (*cp) {
                if (*cp != '\n') {
                    fprintf(stderr, "%c", *cp);
                } else {
                    fprintf(stderr, "\\n");
                }
                ++cp;
                --len;
            }
            fprintf(stderr, "\"");
        } else {
            fprintf(stderr, "%02x", *cp);
        }
        ++cp;
        if (--len) {
            fprintf(stderr, ", ");
        }
    }
    fprintf(stderr, "}\n");
    fflush(stderr);
}

TEST(logd, both) {
    log_msg msg;

    // check if we can read any logs from logd
    bool user_logger_available = false;
    bool user_logger_content = false;

    int fd = socket_local_client("logdr",
                                 ANDROID_SOCKET_NAMESPACE_RESERVED,
                                 SOCK_SEQPACKET);
    if (fd >= 0) {
        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm = alarm(10);

        static const char ask[] = "dumpAndClose lids=0,1,2,3";
        user_logger_available = write(fd, ask, sizeof(ask)) == sizeof(ask);

        user_logger_content = recv(fd, msg.buf, sizeof(msg), 0) > 0;

        if (user_logger_content) {
            dump_log_msg("user", &msg, 3, -1);
        }

        alarm(old_alarm);
        sigaction(SIGALRM, &old_sigaction, NULL);

        close(fd);
    }

    // check if we can read any logs from kernel logger
    bool kernel_logger_available = false;
    bool kernel_logger_content = false;

    static const char *loggers[] = {
        "/dev/log/main",   "/dev/log_main",
        "/dev/log/radio",  "/dev/log_radio",
        "/dev/log/events", "/dev/log_events",
        "/dev/log/system", "/dev/log_system",
    };

    for (unsigned int i = 0; i < (sizeof(loggers) / sizeof(loggers[0])); ++i) {
        fd = open(loggers[i], O_RDONLY);
        if (fd < 0) {
            continue;
        }
        kernel_logger_available = true;
        fcntl(fd, F_SETFL, O_RDONLY | O_NONBLOCK);
        int result = TEMP_FAILURE_RETRY(read(fd, msg.buf, sizeof(msg)));
        if (result > 0) {
            kernel_logger_content = true;
            dump_log_msg("kernel", &msg, 0, i / 2);
        }
        close(fd);
    }

    static const char yes[] = "\xE2\x9C\x93";
    static const char no[] = "\xE2\x9c\x98";
    fprintf(stderr,
            "LOGGER  Available  Content\n"
            "user    %-13s%s\n"
            "kernel  %-13s%s\n"
            " status %-11s%s\n",
            (user_logger_available)   ? yes : no,
            (user_logger_content)     ? yes : no,
            (kernel_logger_available) ? yes : no,
            (kernel_logger_content)   ? yes : no,
            (user_logger_available && kernel_logger_available) ? "ERROR" : "ok",
            (user_logger_content && kernel_logger_content) ? "ERROR" : "ok");

    EXPECT_EQ(0, user_logger_available && kernel_logger_available);
    EXPECT_EQ(0, !user_logger_available && !kernel_logger_available);
    EXPECT_EQ(0, user_logger_content && kernel_logger_content);
    EXPECT_EQ(0, !user_logger_content && !kernel_logger_content);
}

// BAD ROBOT
//   Benchmark threshold are generally considered bad form unless there is
//   is some human love applied to the continued maintenance and whether the
//   thresholds are tuned on a per-target basis. Here we check if the values
//   are more than double what is expected. Doubling will not prevent failure
//   on busy or low-end systems that could have a tendency to stretch values.
//
//   The primary goal of this test is to simulate a spammy app (benchmark
//   being the worst) and check to make sure the logger can deal with it
//   appropriately by checking all the statistics are in an expected range.
//
TEST(logd, benchmark) {
    size_t len;
    char *buf;

    alloc_statistics(&buf, &len);
    bool benchmark_already_run = buf && find_benchmark_spam(buf);
    delete [] buf;

    if (benchmark_already_run) {
        fprintf(stderr, "WARNING: spam already present and too much history\n"
                        "         false OK for prune by worst UID check\n");
    }

    FILE *fp;

    // Introduce some extreme spam for the worst UID filter
    ASSERT_TRUE(NULL != (fp = popen(
        "/data/nativetest/liblog-benchmarks/liblog-benchmarks",
        "r")));

    char buffer[5120];

    static const char *benchmarks[] = {
        "BM_log_maximum_retry ",
        "BM_log_maximum ",
        "BM_clock_overhead ",
        "BM_log_overhead ",
        "BM_log_latency ",
        "BM_log_delay "
    };
    static const unsigned int log_maximum_retry = 0;
    static const unsigned int log_maximum = 1;
    static const unsigned int clock_overhead = 2;
    static const unsigned int log_overhead = 3;
    static const unsigned int log_latency = 4;
    static const unsigned int log_delay = 5;

    unsigned long ns[sizeof(benchmarks) / sizeof(benchmarks[0])];

    memset(ns, 0, sizeof(ns));

    while (fgets(buffer, sizeof(buffer), fp)) {
        for (unsigned i = 0; i < sizeof(ns) / sizeof(ns[0]); ++i) {
            char *cp = strstr(buffer, benchmarks[i]);
            if (!cp) {
                continue;
            }
            sscanf(cp, "%*s %lu %lu", &ns[i], &ns[i]);
            fprintf(stderr, "%-22s%8lu\n", benchmarks[i], ns[i]);
        }
    }
    int ret = pclose(fp);

    if (!WIFEXITED(ret) || (WEXITSTATUS(ret) == 127)) {
        fprintf(stderr,
                "WARNING: "
                "/data/nativetest/liblog-benchmarks/liblog-benchmarks missing\n"
                "         can not perform test\n");
        return;
    }

    EXPECT_GE(200000UL, ns[log_maximum_retry]); // 104734 user

    EXPECT_GE(90000UL, ns[log_maximum]); // 46913 user

    EXPECT_GE(4096UL, ns[clock_overhead]); // 4095

    EXPECT_GE(250000UL, ns[log_overhead]); // 126886 user

    EXPECT_GE(10000000UL, ns[log_latency]); // 1453559 user space (background cgroup)

    EXPECT_GE(20000000UL, ns[log_delay]); // 10500289 user

    for (unsigned i = 0; i < sizeof(ns) / sizeof(ns[0]); ++i) {
        EXPECT_NE(0UL, ns[i]);
    }

    alloc_statistics(&buf, &len);

    bool collected_statistics = !!buf;
    EXPECT_EQ(true, collected_statistics);

    ASSERT_TRUE(NULL != buf);

    char *benchmark_statistics_found = find_benchmark_spam(buf);
    ASSERT_TRUE(benchmark_statistics_found != NULL);

    // Check how effective the SPAM filter is, parse out Now size.
    // 0     root                      54164 147569
    //                                 ^-- benchmark_statistics_found

    unsigned long nowSpamSize = atol(benchmark_statistics_found);

    delete [] buf;

    ASSERT_NE(0UL, nowSpamSize);

    // Determine if we have the spam filter enabled
    int sock = socket_local_client("logd",
                                   ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);

    ASSERT_TRUE(sock >= 0);

    static const char getPruneList[] = "getPruneList";
    if (write(sock, getPruneList, sizeof(getPruneList)) > 0) {
        char buffer[80];
        memset(buffer, 0, sizeof(buffer));
        read(sock, buffer, sizeof(buffer));
        char *cp = strchr(buffer, '\n');
        if (!cp || (cp[1] != '~') || (cp[2] != '!')) {
            close(sock);
            fprintf(stderr,
                    "WARNING: "
                    "Logger has SPAM filtration turned off \"%s\"\n", buffer);
            return;
        }
    } else {
        int save_errno = errno;
        close(sock);
        FAIL() << "Can not send " << getPruneList << " to logger -- " << strerror(save_errno);
    }

    static const unsigned long expected_absolute_minimum_log_size = 65536UL;
    unsigned long totalSize = expected_absolute_minimum_log_size;
    static const char getSize[] = {
        'g', 'e', 't', 'L', 'o', 'g', 'S', 'i', 'z', 'e', ' ',
        LOG_ID_MAIN + '0', '\0'
    };
    if (write(sock, getSize, sizeof(getSize)) > 0) {
        char buffer[80];
        memset(buffer, 0, sizeof(buffer));
        read(sock, buffer, sizeof(buffer));
        totalSize = atol(buffer);
        if (totalSize < expected_absolute_minimum_log_size) {
            fprintf(stderr,
                    "WARNING: "
                    "Logger had unexpected referenced size \"%s\"\n", buffer);
            totalSize = expected_absolute_minimum_log_size;
        }
    }
    close(sock);

    // logd allows excursions to 110% of total size
    totalSize = (totalSize * 11 ) / 10;

    // 50% threshold for SPAM filter (<20% typical, lots of engineering margin)
    ASSERT_GT(totalSize, nowSpamSize * 2);
}

// b/26447386 confirm fixed
void timeout_negative(const char *command) {
    log_msg msg_wrap, msg_timeout;
    bool content_wrap = false, content_timeout = false, written = false;
    unsigned int alarm_wrap = 0, alarm_timeout = 0;
    // A few tries to get it right just in case wrap kicks in due to
    // content providers being active during the test.
    int i = 3;

    while (--i) {
        int fd = socket_local_client("logdr",
                                     ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_SEQPACKET);
        ASSERT_LT(0, fd);

        std::string ask(command);

        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm = alarm(3);

        size_t len = ask.length() + 1;
        written = write(fd, ask.c_str(), len) == (ssize_t)len;
        if (!written) {
            alarm(old_alarm);
            sigaction(SIGALRM, &old_sigaction, NULL);
            close(fd);
            continue;
        }

        content_wrap = recv(fd, msg_wrap.buf, sizeof(msg_wrap), 0) > 0;

        alarm_wrap = alarm(5);

        content_timeout = recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        if (!content_timeout) { // make sure we hit dumpAndClose
            content_timeout = recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        }

        alarm_timeout = alarm((old_alarm <= 0)
            ? old_alarm
            : (old_alarm > (1 + 3 - alarm_wrap))
                ? old_alarm - 3 + alarm_wrap
                : 2);
        sigaction(SIGALRM, &old_sigaction, NULL);

        close(fd);

        if (!content_wrap && !alarm_wrap && content_timeout && alarm_timeout) {
            break;
        }
    }

    if (content_wrap) {
        dump_log_msg("wrap", &msg_wrap, 3, -1);
    }

    if (content_timeout) {
        dump_log_msg("timeout", &msg_timeout, 3, -1);
    }

    EXPECT_TRUE(written);
    EXPECT_TRUE(content_wrap);
    EXPECT_NE(0U, alarm_wrap);
    EXPECT_TRUE(content_timeout);
    EXPECT_NE(0U, alarm_timeout);
}

TEST(logd, timeout_no_start) {
    timeout_negative("dumpAndClose lids=0,1,2,3,4,5 timeout=6");
}

TEST(logd, timeout_start_epoch) {
    timeout_negative("dumpAndClose lids=0,1,2,3,4,5 timeout=6 start=0.000000000");
}

// b/26447386 refined behavior
TEST(logd, timeout) {
    log_msg msg_wrap, msg_timeout;
    bool content_wrap = false, content_timeout = false, written = false;
    unsigned int alarm_wrap = 0, alarm_timeout = 0;
    // A few tries to get it right just in case wrap kicks in due to
    // content providers being active during the test
    int i = 5;
    log_time now(android_log_clockid());
    now.tv_sec -= 30; // reach back a moderate period of time

    while (--i) {
        int fd = socket_local_client("logdr",
                                     ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_SEQPACKET);
        ASSERT_LT(0, fd);

        std::string ask = android::base::StringPrintf(
            "dumpAndClose lids=0,1,2,3,4,5 timeout=6 start=%"
                PRIu32 ".%09" PRIu32,
            now.tv_sec, now.tv_nsec);

        struct sigaction ignore, old_sigaction;
        memset(&ignore, 0, sizeof(ignore));
        ignore.sa_handler = caught_signal;
        sigemptyset(&ignore.sa_mask);
        sigaction(SIGALRM, &ignore, &old_sigaction);
        unsigned int old_alarm = alarm(3);

        size_t len = ask.length() + 1;
        written = write(fd, ask.c_str(), len) == (ssize_t)len;
        if (!written) {
            alarm(old_alarm);
            sigaction(SIGALRM, &old_sigaction, NULL);
            close(fd);
            continue;
        }

        content_wrap = recv(fd, msg_wrap.buf, sizeof(msg_wrap), 0) > 0;

        alarm_wrap = alarm(5);

        content_timeout = recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        if (!content_timeout) { // make sure we hit dumpAndClose
            content_timeout = recv(fd, msg_timeout.buf, sizeof(msg_timeout), 0) > 0;
        }

        alarm_timeout = alarm((old_alarm <= 0)
            ? old_alarm
            : (old_alarm > (1 + 3 - alarm_wrap))
                ? old_alarm - 3 + alarm_wrap
                : 2);
        sigaction(SIGALRM, &old_sigaction, NULL);

        close(fd);

        if (!content_wrap && !alarm_wrap && content_timeout && alarm_timeout) {
            break;
        }

        // modify start time in case content providers are relatively
        // active _or_ inactive during the test.
        if (content_timeout) {
            log_time msg(msg_timeout.entry.sec, msg_timeout.entry.nsec);
            EXPECT_FALSE(msg < now);
            if (msg > now) {
                now = msg;
                now.tv_sec += 30;
                msg = log_time(android_log_clockid());
                if (now > msg) {
                    now = msg;
                    --now.tv_sec;
                }
            }
        } else {
            now.tv_sec -= 120; // inactive, reach further back!
        }
    }

    if (content_wrap) {
        dump_log_msg("wrap", &msg_wrap, 3, -1);
    }

    if (content_timeout) {
        dump_log_msg("timeout", &msg_timeout, 3, -1);
    }

    if (content_wrap || !content_timeout) {
        fprintf(stderr, "now=%" PRIu32 ".%09" PRIu32 "\n",
                now.tv_sec, now.tv_nsec);
    }

    EXPECT_TRUE(written);
    EXPECT_FALSE(content_wrap);
    EXPECT_EQ(0U, alarm_wrap);
    EXPECT_TRUE(content_timeout);
    EXPECT_NE(0U, alarm_timeout);
}

// b/27242723 confirmed fixed
TEST(logd, SNDTIMEO) {
    static const unsigned sndtimeo = LOGD_SNDTIMEO; // <sigh> it has to be done!
    static const unsigned sleep_time = sndtimeo + 3;
    static const unsigned alarm_time = sleep_time + 5;

    int fd;

    ASSERT_TRUE((fd = socket_local_client("logdr",
                                 ANDROID_SOCKET_NAMESPACE_RESERVED,
                                 SOCK_SEQPACKET)) > 0);

    struct sigaction ignore, old_sigaction;
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = caught_signal;
    sigemptyset(&ignore.sa_mask);
    sigaction(SIGALRM, &ignore, &old_sigaction);
    unsigned int old_alarm = alarm(alarm_time);

    static const char ask[] = "stream lids=0,1,2,3,4,5,6"; // all sources
    bool reader_requested = write(fd, ask, sizeof(ask)) == sizeof(ask);
    EXPECT_TRUE(reader_requested);

    log_msg msg;
    bool read_one = recv(fd, msg.buf, sizeof(msg), 0) > 0;

    EXPECT_TRUE(read_one);
    if (read_one) {
        dump_log_msg("user", &msg, 3, -1);
    }

    fprintf (stderr, "Sleep for >%d seconds logd SO_SNDTIMEO ...\n", sndtimeo);
    sleep(sleep_time);

    // flush will block if we did not trigger. if it did, last entry returns 0
    int recv_ret;
    do {
        recv_ret = recv(fd, msg.buf, sizeof(msg), 0);
    } while (recv_ret > 0);
    int save_errno = (recv_ret < 0) ? errno : 0;

    EXPECT_NE(0U, alarm(old_alarm));
    sigaction(SIGALRM, &old_sigaction, NULL);

    EXPECT_EQ(0, recv_ret);
    if (recv_ret > 0) {
        dump_log_msg("user", &msg, 3, -1);
    }
    EXPECT_EQ(0, save_errno);

    close(fd);
}
