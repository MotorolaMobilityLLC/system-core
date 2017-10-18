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

#include <stdint.h>
#include <time.h>

#include <string>
#include <unordered_map>

#include <android/content/pm/IPackageManagerNative.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <binder/IServiceManager.h>
#include <log/log_event_list.h>

#include "storaged.h"
#include "storaged_uid_monitor.h"

using namespace android;
using namespace android::base;
using namespace android::content::pm;
using namespace android::os::storaged;
using namespace storaged_proto;

namespace {

bool refresh_uid_names;
const char* UID_IO_STATS_PATH = "/proc/uid_io/stats";

} // namepsace

std::unordered_map<uint32_t, uid_info> uid_monitor::get_uid_io_stats()
{
    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));
    return get_uid_io_stats_locked();
};

/* return true on parse success and false on failure */
bool uid_info::parse_uid_io_stats(std::string&& s)
{
    std::vector<std::string> fields = Split(s, " ");
    if (fields.size() < 11 ||
        !ParseUint(fields[0],  &uid) ||
        !ParseUint(fields[1],  &io[FOREGROUND].rchar) ||
        !ParseUint(fields[2],  &io[FOREGROUND].wchar) ||
        !ParseUint(fields[3],  &io[FOREGROUND].read_bytes) ||
        !ParseUint(fields[4],  &io[FOREGROUND].write_bytes) ||
        !ParseUint(fields[5],  &io[BACKGROUND].rchar) ||
        !ParseUint(fields[6],  &io[BACKGROUND].wchar) ||
        !ParseUint(fields[7],  &io[BACKGROUND].read_bytes) ||
        !ParseUint(fields[8],  &io[BACKGROUND].write_bytes) ||
        !ParseUint(fields[9],  &io[FOREGROUND].fsync) ||
        !ParseUint(fields[10], &io[BACKGROUND].fsync)) {
        LOG_TO(SYSTEM, WARNING) << "Invalid uid I/O stats: \""
                                << s << "\"";
        return false;
    }
    return true;
}

/* return true on parse success and false on failure */
bool task_info::parse_task_io_stats(std::string&& s)
{
    std::vector<std::string> fields = Split(s, ",");
    size_t size = fields.size();
    if (size < 13 ||
        !ParseInt(fields[size - 11],  &pid) ||
        !ParseUint(fields[size - 10],  &io[FOREGROUND].rchar) ||
        !ParseUint(fields[size - 9],  &io[FOREGROUND].wchar) ||
        !ParseUint(fields[size - 8],  &io[FOREGROUND].read_bytes) ||
        !ParseUint(fields[size - 7],  &io[FOREGROUND].write_bytes) ||
        !ParseUint(fields[size - 6],  &io[BACKGROUND].rchar) ||
        !ParseUint(fields[size - 5],  &io[BACKGROUND].wchar) ||
        !ParseUint(fields[size - 4],  &io[BACKGROUND].read_bytes) ||
        !ParseUint(fields[size - 3], &io[BACKGROUND].write_bytes) ||
        !ParseUint(fields[size - 2], &io[FOREGROUND].fsync) ||
        !ParseUint(fields[size - 1], &io[BACKGROUND].fsync)) {
        LOG_TO(SYSTEM, WARNING) << "Invalid task I/O stats: \""
                                << s << "\"";
        return false;
    }
    comm = Join(std::vector<std::string>(
                fields.begin() + 1, fields.end() - 11), ',');
    return true;
}

bool io_usage::is_zero() const
{
    for (int i = 0; i < IO_TYPES; i++) {
        for (int j = 0; j < UID_STATS; j++) {
            for (int k = 0; k < CHARGER_STATS; k++) {
                if (bytes[i][j][k])
                    return false;
            }
        }
    }
    return true;
}

namespace {

void get_uid_names(const vector<int>& uids, const vector<std::string*>& uid_names)
{
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) {
        LOG_TO(SYSTEM, ERROR) << "defaultServiceManager failed";
        return;
    }

    sp<IBinder> binder = sm->getService(String16("package_native"));
    if (binder == NULL) {
        LOG_TO(SYSTEM, ERROR) << "getService package_native failed";
        return;
    }

    sp<IPackageManagerNative> package_mgr = interface_cast<IPackageManagerNative>(binder);
    std::vector<std::string> names;
    binder::Status status = package_mgr->getNamesForUids(uids, &names);
    if (!status.isOk()) {
        LOG_TO(SYSTEM, ERROR) << "package_native::getNamesForUids failed: "
                              << status.exceptionMessage();
        return;
    }

    for (uint32_t i = 0; i < uid_names.size(); i++) {
        if (!names[i].empty()) {
            *uid_names[i] = names[i];
        }
    }

    refresh_uid_names = false;
}

} // namespace

std::unordered_map<uint32_t, uid_info> uid_monitor::get_uid_io_stats_locked()
{
    std::unordered_map<uint32_t, uid_info> uid_io_stats;
    std::string buffer;
    if (!ReadFileToString(UID_IO_STATS_PATH, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << UID_IO_STATS_PATH << ": ReadFileToString failed";
        return uid_io_stats;
    }

    std::vector<std::string> io_stats = Split(std::move(buffer), "\n");
    uid_info u;
    vector<int> uids;
    vector<std::string*> uid_names;

    for (uint32_t i = 0; i < io_stats.size(); i++) {
        if (io_stats[i].empty()) {
            continue;
        }

        if (io_stats[i].compare(0, 4, "task")) {
            if (!u.parse_uid_io_stats(std::move(io_stats[i])))
                continue;
            uid_io_stats[u.uid] = u;
            uid_io_stats[u.uid].name = std::to_string(u.uid);
            uids.push_back(u.uid);
            uid_names.push_back(&uid_io_stats[u.uid].name);
            if (last_uid_io_stats.find(u.uid) == last_uid_io_stats.end()) {
                refresh_uid_names = true;
            } else {
                uid_io_stats[u.uid].name = last_uid_io_stats[u.uid].name;
            }
        } else {
            task_info t;
            if (!t.parse_task_io_stats(std::move(io_stats[i])))
                continue;
            uid_io_stats[u.uid].tasks[t.pid] = t;
        }
    }

    if (!uids.empty() && refresh_uid_names) {
        get_uid_names(uids, uid_names);
    }

    return uid_io_stats;
}

namespace {

const int MAX_UID_RECORDS_SIZE = 1000 * 48; // 1000 uids in 48 hours

inline size_t history_size(
    const std::map<uint64_t, struct uid_records>& history)
{
    size_t count = 0;
    for (auto const& it : history) {
        count += it.second.entries.size();
    }
    return count;
}

} // namespace

void uid_monitor::add_records_locked(uint64_t curr_ts)
{
    // remove records more than 5 days old
    if (curr_ts > 5 * DAY_TO_SEC) {
        auto it = io_history.lower_bound(curr_ts - 5 * DAY_TO_SEC);
        io_history.erase(io_history.begin(), it);
    }

    struct uid_records new_records;
    for (const auto& p : curr_io_stats) {
        struct uid_record record = {};
        record.name = p.first;
        if (!p.second.uid_ios.is_zero()) {
            record.ios.uid_ios = p.second.uid_ios;
            for (const auto& p_task : p.second.task_ios) {
                if (!p_task.second.is_zero())
                    record.ios.task_ios[p_task.first] = p_task.second;
            }
            new_records.entries.push_back(record);
        }
    }

    curr_io_stats.clear();
    new_records.start_ts = start_ts;
    start_ts = curr_ts;

    if (new_records.entries.empty())
      return;

    // make some room for new records
    ssize_t overflow = history_size(io_history) +
        new_records.entries.size() - MAX_UID_RECORDS_SIZE;
    while (overflow > 0 && io_history.size() > 0) {
        auto del_it = io_history.begin();
        overflow -= del_it->second.entries.size();
        io_history.erase(io_history.begin());
    }

    io_history[curr_ts] = new_records;
}

std::map<uint64_t, struct uid_records> uid_monitor::dump(
    double hours, uint64_t threshold, bool force_report, UidIOUsage* uid_io_proto)
{
    if (force_report) {
        report(uid_io_proto);
    }

    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));

    std::map<uint64_t, struct uid_records> dump_records;
    uint64_t first_ts = 0;

    if (hours != 0) {
        first_ts = time(NULL) - hours * HOUR_TO_SEC;
    }

    for (auto it = io_history.lower_bound(first_ts); it != io_history.end(); ++it) {
        const std::vector<struct uid_record>& recs = it->second.entries;
        struct uid_records filtered;

        for (const auto& rec : recs) {
            const io_usage& uid_usage = rec.ios.uid_ios;
            if (uid_usage.bytes[READ][FOREGROUND][CHARGER_ON] +
                uid_usage.bytes[READ][FOREGROUND][CHARGER_OFF] +
                uid_usage.bytes[READ][BACKGROUND][CHARGER_ON] +
                uid_usage.bytes[READ][BACKGROUND][CHARGER_OFF] +
                uid_usage.bytes[WRITE][FOREGROUND][CHARGER_ON] +
                uid_usage.bytes[WRITE][FOREGROUND][CHARGER_OFF] +
                uid_usage.bytes[WRITE][BACKGROUND][CHARGER_ON] +
                uid_usage.bytes[WRITE][BACKGROUND][CHARGER_OFF] > threshold) {
                filtered.entries.push_back(rec);
            }
        }

        if (filtered.entries.empty())
            continue;

        filtered.start_ts = it->second.start_ts;
        dump_records.insert(
            std::pair<uint64_t, struct uid_records>(it->first, filtered));
    }

    return dump_records;
}

void uid_monitor::update_curr_io_stats_locked()
{
    std::unordered_map<uint32_t, uid_info> uid_io_stats =
        get_uid_io_stats_locked();
    if (uid_io_stats.empty()) {
        return;
    }

    for (const auto& it : uid_io_stats) {
        const uid_info& uid = it.second;

        if (curr_io_stats.find(uid.name) == curr_io_stats.end()) {
          curr_io_stats[uid.name] = {};
        }

        struct uid_io_usage& usage = curr_io_stats[uid.name];
        int64_t fg_rd_delta = uid.io[FOREGROUND].read_bytes -
            last_uid_io_stats[uid.uid].io[FOREGROUND].read_bytes;
        int64_t bg_rd_delta = uid.io[BACKGROUND].read_bytes -
            last_uid_io_stats[uid.uid].io[BACKGROUND].read_bytes;
        int64_t fg_wr_delta = uid.io[FOREGROUND].write_bytes -
            last_uid_io_stats[uid.uid].io[FOREGROUND].write_bytes;
        int64_t bg_wr_delta = uid.io[BACKGROUND].write_bytes -
            last_uid_io_stats[uid.uid].io[BACKGROUND].write_bytes;

        usage.uid_ios.bytes[READ][FOREGROUND][charger_stat] +=
            (fg_rd_delta < 0) ? 0 : fg_rd_delta;
        usage.uid_ios.bytes[READ][BACKGROUND][charger_stat] +=
            (bg_rd_delta < 0) ? 0 : bg_rd_delta;
        usage.uid_ios.bytes[WRITE][FOREGROUND][charger_stat] +=
            (fg_wr_delta < 0) ? 0 : fg_wr_delta;
        usage.uid_ios.bytes[WRITE][BACKGROUND][charger_stat] +=
            (bg_wr_delta < 0) ? 0 : bg_wr_delta;

        for (const auto& task_it : uid.tasks) {
            const task_info& task = task_it.second;
            const pid_t pid = task_it.first;
            const std::string& comm = task_it.second.comm;
            int64_t task_fg_rd_delta = task.io[FOREGROUND].read_bytes -
                last_uid_io_stats[uid.uid].tasks[pid].io[FOREGROUND].read_bytes;
            int64_t task_bg_rd_delta = task.io[BACKGROUND].read_bytes -
                last_uid_io_stats[uid.uid].tasks[pid].io[BACKGROUND].read_bytes;
            int64_t task_fg_wr_delta = task.io[FOREGROUND].write_bytes -
                last_uid_io_stats[uid.uid].tasks[pid].io[FOREGROUND].write_bytes;
            int64_t task_bg_wr_delta = task.io[BACKGROUND].write_bytes -
                last_uid_io_stats[uid.uid].tasks[pid].io[BACKGROUND].write_bytes;

            struct io_usage& task_usage = usage.task_ios[comm];
            task_usage.bytes[READ][FOREGROUND][charger_stat] +=
                (task_fg_rd_delta < 0) ? 0 : task_fg_rd_delta;
            task_usage.bytes[READ][BACKGROUND][charger_stat] +=
                (task_bg_rd_delta < 0) ? 0 : task_bg_rd_delta;
            task_usage.bytes[WRITE][FOREGROUND][charger_stat] +=
                (task_fg_wr_delta < 0) ? 0 : task_fg_wr_delta;
            task_usage.bytes[WRITE][BACKGROUND][charger_stat] +=
                (task_bg_wr_delta < 0) ? 0 : task_bg_wr_delta;
        }
    }

    last_uid_io_stats = uid_io_stats;
}

void uid_monitor::report(UidIOUsage* proto)
{
    if (!enabled()) return;

    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));

    update_curr_io_stats_locked();
    add_records_locked(time(NULL));

    update_uid_io_proto(proto);
}

namespace {

void set_io_usage_proto(IOUsage* usage_proto, const struct io_usage& usage)
{
    usage_proto->set_rd_fg_chg_on(usage.bytes[READ][FOREGROUND][CHARGER_ON]);
    usage_proto->set_rd_fg_chg_off(usage.bytes[READ][FOREGROUND][CHARGER_OFF]);
    usage_proto->set_rd_bg_chg_on(usage.bytes[READ][BACKGROUND][CHARGER_ON]);
    usage_proto->set_rd_bg_chg_off(usage.bytes[READ][BACKGROUND][CHARGER_OFF]);
    usage_proto->set_wr_fg_chg_on(usage.bytes[WRITE][FOREGROUND][CHARGER_ON]);
    usage_proto->set_wr_fg_chg_off(usage.bytes[WRITE][FOREGROUND][CHARGER_OFF]);
    usage_proto->set_wr_bg_chg_on(usage.bytes[WRITE][BACKGROUND][CHARGER_ON]);
    usage_proto->set_wr_bg_chg_off(usage.bytes[WRITE][BACKGROUND][CHARGER_OFF]);
}

void get_io_usage_proto(struct io_usage* usage, const IOUsage& io_proto)
{
    usage->bytes[READ][FOREGROUND][CHARGER_ON] = io_proto.rd_fg_chg_on();
    usage->bytes[READ][FOREGROUND][CHARGER_OFF] = io_proto.rd_fg_chg_off();
    usage->bytes[READ][BACKGROUND][CHARGER_ON] = io_proto.rd_bg_chg_on();
    usage->bytes[READ][BACKGROUND][CHARGER_OFF] = io_proto.rd_bg_chg_off();
    usage->bytes[WRITE][FOREGROUND][CHARGER_ON] = io_proto.wr_fg_chg_on();
    usage->bytes[WRITE][FOREGROUND][CHARGER_OFF] = io_proto.wr_fg_chg_off();
    usage->bytes[WRITE][BACKGROUND][CHARGER_ON] = io_proto.wr_bg_chg_on();
    usage->bytes[WRITE][BACKGROUND][CHARGER_OFF] = io_proto.wr_bg_chg_off();
}

} // namespace

void uid_monitor::update_uid_io_proto(UidIOUsage* uid_io_proto)
{
    uid_io_proto->Clear();

    for (const auto& item : io_history) {
        const uint64_t& end_ts = item.first;
        const struct uid_records& recs = item.second;

        UidIOItem* item_proto = uid_io_proto->add_uid_io_items();
        item_proto->set_end_ts(end_ts);

        UidIORecords* recs_proto = item_proto->mutable_records();
        recs_proto->set_start_ts(recs.start_ts);

        for (const auto& entry : recs.entries) {
            UidRecord* rec_proto = recs_proto->add_entries();
            rec_proto->set_uid_name(entry.name);

            IOUsage* uid_io_proto = rec_proto->mutable_uid_io();
            const struct io_usage& uio_ios = entry.ios.uid_ios;
            set_io_usage_proto(uid_io_proto, uio_ios);

            for (const auto& task_io : entry.ios.task_ios) {
                const std::string& task_name = task_io.first;
                const struct io_usage& task_ios = task_io.second;

                TaskIOUsage* task_io_proto = rec_proto->add_task_io();
                task_io_proto->set_task_name(task_name);
                set_io_usage_proto(task_io_proto->mutable_ios(), task_ios);
            }
        }
    }
}

void uid_monitor::load_uid_io_proto(const UidIOUsage& uid_io_proto)
{
    if (!enabled()) return;

    for (const auto& item_proto : uid_io_proto.uid_io_items()) {
        const UidIORecords& records_proto = item_proto.records();
        struct uid_records* recs = &io_history[item_proto.end_ts()];

        recs->start_ts = records_proto.start_ts();
        for (const auto& rec_proto : records_proto.entries()) {
            struct uid_record record;
            record.name = rec_proto.uid_name();
            get_io_usage_proto(&record.ios.uid_ios, rec_proto.uid_io());

            for (const auto& task_io_proto : rec_proto.task_io()) {
                get_io_usage_proto(
                    &record.ios.task_ios[task_io_proto.task_name()],
                    task_io_proto.ios());
            }
            recs->entries.push_back(record);
        }
    }
}

void uid_monitor::set_charger_state(charger_stat_t stat)
{
    std::unique_ptr<lock_t> lock(new lock_t(&um_lock));

    if (charger_stat == stat) {
        return;
    }

    update_curr_io_stats_locked();
    charger_stat = stat;
}

void uid_monitor::init(charger_stat_t stat)
{
    charger_stat = stat;

    start_ts = time(NULL);
    last_uid_io_stats = get_uid_io_stats();
}

uid_monitor::uid_monitor()
    : enable(!access(UID_IO_STATS_PATH, R_OK))
{
    sem_init(&um_lock, 0, 1);
}

uid_monitor::~uid_monitor()
{
    sem_destroy(&um_lock);
}
