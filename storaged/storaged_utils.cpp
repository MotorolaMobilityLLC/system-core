/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "storaged"

#include <dirent.h>
#include <fcntl.h>
#include <linux/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log_event_list.h>

#include <storaged.h>
#include <storaged_utils.h>

#define SECTOR_SIZE ( 512 )
#define SEC_TO_MSEC ( 1000 )
#define MSEC_TO_USEC ( 1000 )
#define USEC_TO_NSEC ( 1000 )

bool parse_disk_stats(const char* disk_stats_path, struct disk_stats* stats) {
    // Get time
    struct timespec ts;
    // Use monotonic to exclude suspend time so that we measure IO bytes/sec
    // when system is running.
    int ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        return false;
    }

    std::string buffer;
    if (!android::base::ReadFileToString(disk_stats_path, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << disk_stats_path << ": ReadFileToString failed.";
        return false;
    }

    // Regular diskstats entries
    std::stringstream ss(buffer);
    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        ss >> *((uint64_t*)stats + i);
    }
    // Other entries
    stats->start_time = 0;
    stats->end_time = (uint64_t)ts.tv_sec * SEC_TO_MSEC +
        ts.tv_nsec / (MSEC_TO_USEC * USEC_TO_NSEC);
    stats->counter = 1;
    stats->io_avg = (double)stats->io_in_flight;
    return true;
}

struct disk_perf get_disk_perf(struct disk_stats* stats) {
    struct disk_perf perf;
    memset(&perf, 0, sizeof(struct disk_perf));  // initialize

    if (stats->io_ticks) {
        if (stats->read_ticks) {
            unsigned long long divisor = stats->read_ticks * stats->io_ticks;
            perf.read_perf = ((unsigned long long)SECTOR_SIZE *
                                        stats->read_sectors *
                                        stats->io_in_queue +
                                        (divisor >> 1)) /
                                            divisor;
            perf.read_ios = ((unsigned long long)SEC_TO_MSEC *
                                        stats->read_ios *
                                        stats->io_in_queue +
                                        (divisor >> 1)) /
                                            divisor;
        }
        if (stats->write_ticks) {
            unsigned long long divisor = stats->write_ticks * stats->io_ticks;
                        perf.write_perf = ((unsigned long long)SECTOR_SIZE *
                                                    stats->write_sectors *
                                                    stats->io_in_queue +
                                                    (divisor >> 1)) /
                                                        divisor;
                        perf.write_ios = ((unsigned long long)SEC_TO_MSEC *
                                                    stats->write_ios *
                                                    stats->io_in_queue +
                                                    (divisor >> 1)) /
                                                        divisor;
        }
        perf.queue = (stats->io_in_queue + (stats->io_ticks >> 1)) /
                                stats->io_ticks;
    }
    return perf;
}

struct disk_stats get_inc_disk_stats(struct disk_stats* prev, struct disk_stats* curr) {
    struct disk_stats inc;
    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        if (i == DISK_STATS_IO_IN_FLIGHT_IDX) {
            continue;
        }

        *((uint64_t*)&inc + i) =
                *((uint64_t*)curr + i) - *((uint64_t*)prev + i);
    }
    // io_in_flight is exception
    inc.io_in_flight = curr->io_in_flight;

    inc.start_time = prev->end_time;
    inc.end_time = curr->end_time;
    inc.io_avg = curr->io_avg;
    inc.counter = 1;

    return inc;
}

// Add src to dst
void add_disk_stats(struct disk_stats* src, struct disk_stats* dst) {
    if (dst->end_time != 0 && dst->end_time != src->start_time) {
        LOG_TO(SYSTEM, WARNING) << "Two dis-continuous periods of diskstats"
            << " are added. dst end with " << dst->end_time
            << ", src start with " << src->start_time;
    }

    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        if (i == DISK_STATS_IO_IN_FLIGHT_IDX) {
            continue;
        }

        *((uint64_t*)dst + i) += *((uint64_t*)src + i);
    }

    dst->io_in_flight = src->io_in_flight;
    if (dst->counter + src->counter) {
        dst->io_avg = ((dst->io_avg * dst->counter) + (src->io_avg * src->counter)) /
                        (dst->counter + src->counter);
    }
    dst->counter += src->counter;
    dst->end_time = src->end_time;
    if (dst->start_time == 0) {
        dst->start_time = src->start_time;
    }
}

bool parse_emmc_ecsd(int ext_csd_fd, struct emmc_info* info) {
    CHECK(ext_csd_fd >= 0);
    struct hex {
        char str[2];
    };
    // List of interesting offsets
    static const size_t EXT_CSD_REV_IDX = 192 * sizeof(hex);
    static const size_t EXT_PRE_EOL_INFO_IDX = 267 * sizeof(hex);
    static const size_t EXT_DEVICE_LIFE_TIME_EST_A_IDX = 268 * sizeof(hex);
    static const size_t EXT_DEVICE_LIFE_TIME_EST_B_IDX = 269 * sizeof(hex);

    // Read file
    CHECK(lseek(ext_csd_fd, 0, SEEK_SET) == 0);
    std::string buffer;
    if (!android::base::ReadFdToString(ext_csd_fd, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << "ReadFdToString failed.";
        return false;
    }

    if (buffer.length() < EXT_CSD_FILE_MIN_SIZE) {
        LOG_TO(SYSTEM, ERROR) << "EMMC ext csd file has truncated content. "
            << "File length: " << buffer.length();
        return false;
    }

    std::string sub;
    std::stringstream ss;
    // Parse EXT_CSD_REV
    int ext_csd_rev = -1;
    sub = buffer.substr(EXT_CSD_REV_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> ext_csd_rev;
    if (ext_csd_rev < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_CSD_REV.";
        return false;
    }
    ss.clear();

    static const char* ver_str[] = {
        "4.0", "4.1", "4.2", "4.3", "Obsolete", "4.41", "4.5", "5.0"
    };

    strncpy(info->mmc_ver,
            (ext_csd_rev < (int)(sizeof(ver_str) / sizeof(ver_str[0]))) ?
                           ver_str[ext_csd_rev] :
                           "Unknown",
            MMC_VER_STR_LEN);

    if (ext_csd_rev < 7) {
        return 0;
    }

    // Parse EXT_PRE_EOL_INFO
    info->eol = -1;
    sub = buffer.substr(EXT_PRE_EOL_INFO_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> info->eol;
    if (info->eol < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_PRE_EOL_INFO.";
        return false;
    }
    ss.clear();

    // Parse DEVICE_LIFE_TIME_EST
    info->lifetime_a = -1;
    sub = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_A_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> info->lifetime_a;
    if (info->lifetime_a < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_DEVICE_LIFE_TIME_EST_TYP_A.";
        return false;
    }
    ss.clear();

    info->lifetime_b = -1;
    sub = buffer.substr(EXT_DEVICE_LIFE_TIME_EST_B_IDX, sizeof(hex));
    ss << sub;
    ss >> std::hex >> info->lifetime_b;
    if (info->lifetime_b < 0) {
        LOG_TO(SYSTEM, ERROR) << "Failure on parsing EXT_DEVICE_LIFE_TIME_EST_TYP_B.";
        return false;
    }
    ss.clear();

    return true;
}

#define PROC_DIR "/proc/"
#define PROC_STAT_STARTTIME_IDX ( 22 ) // This index is 1 based according to the linux proc man page
bool parse_task_info(uint32_t pid, struct task_info* info) {
    std::string buffer;
    std::string pid_str = std::to_string(pid);
    info->pid = pid;

    // Get task I/O
    std::string task_io_path = android::base::StringPrintf(PROC_DIR "%s/io", pid_str.c_str());
    if (!android::base::ReadFileToString(task_io_path, &buffer)) return false;

    std::stringstream ss(buffer);
    std::string title;

    ss >> title >> info->rchar
       >> title >> info->wchar
       >> title >> info->syscr
       >> title >> info->syscw
       >> title >> info->read_bytes
       >> title >> info->write_bytes
       >> title >> info->cancelled_write_bytes;
    ss.clear();

    // Get cmd string
    std::string task_cmdline_path = android::base::StringPrintf(PROC_DIR "%u/cmdline", pid);
    if (!android::base::ReadFileToString(task_cmdline_path, &buffer)) return false;
    strcpy(info->cmd, android::base::Trim(buffer).c_str());

    if (info->cmd[0] == '\0') {
        std::string task_comm_path = android::base::StringPrintf(PROC_DIR "%u/comm", pid);
        if (!android::base::ReadFileToString(task_comm_path, &buffer)) return false;
        strcpy(info->cmd, android::base::Trim(buffer).c_str());
    }

    // Get task start time
    std::string task_stat_path = android::base::StringPrintf(PROC_DIR "%u/stat", pid);
    if (!android::base::ReadFileToString(task_stat_path, &buffer)) return false;

    std::vector<std::string> stat_parts = android::base::Split(buffer, " ");
    info->starttime = atoll(stat_parts[PROC_STAT_STARTTIME_IDX - 1].c_str());

    return true;
}

static bool is_pid(char* d_name) {
    if (!d_name || d_name[0] == '\0') return false;
    char* c = d_name;
    while (*c) {
        if (!isdigit(*c)) return false;
        ++c;
    }
    return true;
}

static bool cmp_task_info(struct task_info i, struct task_info j) {
    if (i.write_bytes + i.read_bytes != j.write_bytes + j.read_bytes) {
        return i.write_bytes + i.read_bytes > j.write_bytes + j.read_bytes;
    }
    if (i.wchar + i.rchar != j.wchar + j.rchar) {
        return i.wchar + i.rchar > j.wchar + j.rchar;
    }
    if (i.syscw + i.syscr != j.syscw + j.syscr) {
        return i.syscw + i.syscr > j.syscw + j.syscr;
    }

    return strcmp(i.cmd, j.cmd) < 0;
}

std::unordered_map<uint32_t, struct task_info> tasks_t::get_running_tasks() {
    std::unordered_map<uint32_t, struct task_info> retval;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(PROC_DIR), closedir);
    CHECK(dir != NULL);
    struct dirent* dp;

    for (;;) {
        if ((dp = readdir(dir.get())) == NULL) break;
        if (!is_pid(dp->d_name)) continue;

        uint32_t pid = atol(dp->d_name);
        struct task_info info;
        if (parse_task_info(pid, &info)) {
            retval[pid] = info;
        }
    }
    return retval;
}

static void add_task_info(struct task_info* src, struct task_info* dst) {
    CHECK(strcmp(src->cmd, dst->cmd) == 0);

    dst->pid = 0;
    dst->rchar += src->rchar;
    dst->wchar += src->wchar;
    dst->syscr += src->syscr;
    dst->syscw += src->syscw;
    dst->read_bytes += src->read_bytes;
    dst->write_bytes += src->write_bytes;
    dst->cancelled_write_bytes += src->cancelled_write_bytes;
    dst->starttime = 0;
}

void tasks_t::update_running_tasks(void) {
    std::unordered_map<uint32_t, struct task_info> tasks_latest = get_running_tasks();
    std::unordered_map<std::string, struct task_info> tasks_old = mOld;

    for (auto t : mRunning) {
        uint32_t pid = t.first;
        // old task on mRunning still exist on tasks_latest
        if (tasks_latest.find(pid) != tasks_latest.end() &&
                tasks_latest[pid].starttime == t.second.starttime) {
            continue;
        } else {
            // This branch will handle 2 cases:
            // - Task get killed between the 2 samplings
            // - Task get killed and its pid is reused
            std::string cmd = t.second.cmd;
            struct task_info info = t.second;

            if (tasks_old.find(cmd) == tasks_old.end()) {
                tasks_old[cmd] = info;
            } else {
                add_task_info(&info, &tasks_old[cmd]);
            }
        }
    }
    {   // update critical area
        // this is really fast!
        std::unique_ptr<lock_t> lock(new lock_t(&mSem));
        mRunning = tasks_latest;
        mOld = tasks_old;
    }

}

std::vector<struct task_info> tasks_t::get_tasks(void) {
    std::unique_ptr<lock_t> lock(new lock_t(&mSem));
    std::unordered_map<std::string, struct task_info> tasks_map = mOld;

    for (auto i : mRunning) {
        std::string cmd = i.second.cmd;
        if (tasks_map.find(cmd) == tasks_map.end()) {
            tasks_map[cmd] = i.second;
        } else {
            add_task_info(&i.second, &tasks_map[cmd]);
        }
    }

    std::vector<struct task_info> retval(tasks_map.size());
    int idx = 0;
    for (auto i : tasks_map) {
        retval[idx++]  = i.second;
    }

    return retval;
}

void sort_running_tasks_info(std::vector<struct task_info> &tasks) {
    std::sort(tasks.begin(), tasks.end(), cmp_task_info);
}

/* Logging functions */
void log_console_running_tasks_info(std::vector<struct task_info> tasks) {
// Sample Output:
//       Application           Read          Write           Read          Write           Read          Write      Cancelled
//              Name     Characters     Characters       Syscalls       Syscalls          Bytes          Bytes     Writebytes
//        ----------     ----------     ----------     ----------     ----------     ----------     ----------     ----------
//          zygote64       37688308        3388467           7607           4363      314519552        5373952           8192
//     system_server       95874193        2216913          74613          52257      213078016        7237632          16384
//            zygote         506279        1726194            921            263      128114688        1765376              0
//  /vendor/bin/qcks       75415632       75154382          21672          25036       63627264       29974528       10485760
//             /init       86658523        5107871          82113           8633       91015168        1245184              0

    // Title
    printf("                                       Application           Read          Write           Read          Write           Read          Write      Cancelled\n"
           "                                              Name     Characters     Characters       Syscalls       Syscalls          Bytes          Bytes     Writebytes\n"
           "                                        ----------     ----------     ----------     ----------     ----------     ----------     ----------     ----------\n");

    for (struct task_info task : tasks) {
        printf("%50s%15ju%15ju%15ju%15ju%15ju%15ju%15ju\n",
            task.cmd, task.rchar, task.wchar, task.syscr, task.syscw,
            task.read_bytes, task.write_bytes, task.cancelled_write_bytes);
    }
    fflush(stdout);
}

void log_kernel_disk_stats(struct disk_stats* stats, const char* type) {
    // skip if the input structure are all zeros
    if (stats == NULL) return;
    struct disk_stats zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    if (memcmp(&zero_cmp, stats, sizeof(struct disk_stats)) == 0) return;

    LOG_TO(SYSTEM, INFO) << "diskstats " << type << ": "
              << stats->start_time << " " << stats->end_time << " "
              << stats->read_ios << " " << stats->read_merges << " "
              << stats->read_sectors << " " << stats->read_ticks << " "
              << stats->write_ios << " " << stats->write_merges << " "
              << stats->write_sectors << " " << stats->write_ticks << " "
              << std::setprecision(1) << std::fixed << stats->io_avg << " "
              << stats->io_ticks << " " << stats->io_in_queue;
}

void log_kernel_disk_perf(struct disk_perf* perf, const char* type) {
    // skip if the input structure are all zeros
    if (perf == NULL) return;
    struct disk_perf zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    if (memcmp(&zero_cmp, perf, sizeof(struct disk_perf)) == 0) return;

    LOG_TO(SYSTEM, INFO) << "perf(ios) " << type
              << " rd:" << perf->read_perf << "KB/s(" << perf->read_ios << "/s)"
              << " wr:" << perf->write_perf << "KB/s(" << perf->write_ios << "/s)"
              << " q:" << perf->queue;
}

void log_kernel_emmc_info(struct emmc_info* info) {
    // skip if the input structure are all zeros
    if (info == NULL) return;
    struct emmc_info zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    if (memcmp(&zero_cmp, info, sizeof(struct emmc_info)) == 0) return;

    LOG_TO(SYSTEM, INFO) << "MMC " << info->mmc_ver << " eol:" << info->eol << ", "
              << "lifetime typA:" << info->lifetime_a
              << ", typB:" << info->lifetime_b;
}

void log_event_disk_stats(struct disk_stats* stats, const char* type) {
    // skip if the input structure are all zeros
    if (stats == NULL) return;
    struct disk_stats zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    // skip event logging diskstats when it is zero increment (all first 11 entries are zero)
    if (memcmp(&zero_cmp, stats, sizeof(uint64_t) * DISK_STATS_SIZE) == 0) return;

    android_log_event_list(EVENTLOGTAG_DISKSTATS)
        << type << stats->start_time << stats->end_time
        << stats->read_ios << stats->read_merges
        << stats->read_sectors << stats->read_ticks
        << stats->write_ios << stats->write_merges
        << stats->write_sectors << stats->write_ticks
        << (uint64_t)stats->io_avg << stats->io_ticks << stats->io_in_queue
        << LOG_ID_EVENTS;
}

void log_event_emmc_info(struct emmc_info* info) {
    // skip if the input structure are all zeros
    if (info == NULL) return;
    struct emmc_info zero_cmp;
    memset(&zero_cmp, 0, sizeof(zero_cmp));
    if (memcmp(&zero_cmp, info, sizeof(struct emmc_info)) == 0) return;

    android_log_event_list(EVENTLOGTAG_EMMCINFO)
        << info->mmc_ver << info->eol << info->lifetime_a << info->lifetime_b
        << LOG_ID_EVENTS;
}
