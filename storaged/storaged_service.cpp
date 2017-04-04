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

#include <stdint.h>

#include <vector>

#include <android-base/parseint.h>
#include <android-base/parsedouble.h>
#include <binder/IBinder.h>
#include <binder/IInterface.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <private/android_filesystem_config.h>

#include <storaged.h>
#include <storaged_service.h>

using namespace android::base;

extern sp<storaged_t> storaged;

std::vector<struct uid_info> BpStoraged::dump_uids(const char* /*option*/) {
    Parcel data, reply;
    data.writeInterfaceToken(IStoraged::getInterfaceDescriptor());

    remote()->transact(DUMPUIDS, data, &reply);

    uint32_t res_size = reply.readInt32();
    std::vector<struct uid_info> res(res_size);
    for (auto&& uid : res) {
        uid.uid = reply.readInt32();
        uid.name = reply.readCString();
        reply.read(&uid.io, sizeof(uid.io));
    }
    return res;
}
IMPLEMENT_META_INTERFACE(Storaged, "Storaged");

status_t BnStoraged::onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    switch(code) {
        case DUMPUIDS: {
                if (!data.checkInterface(this))
                    return BAD_TYPE;
                std::vector<struct uid_info> res = dump_uids(NULL);
                reply->writeInt32(res.size());
                for (auto uid : res) {
                    reply->writeInt32(uid.uid);
                    reply->writeCString(uid.name.c_str());
                    reply->write(&uid.io, sizeof(uid.io));
                }
                return NO_ERROR;
            }
            break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

std::vector<struct uid_info> Storaged::dump_uids(const char* /* option */) {
    std::vector<struct uid_info> uids_v;
    std::unordered_map<uint32_t, struct uid_info> uids_m = storaged->get_uids();

    for (const auto& it : uids_m) {
        uids_v.push_back(it.second);
    }
    return uids_v;
}

status_t Storaged::dump(int fd, const Vector<String16>& args) {
    IPCThreadState* self = IPCThreadState::self();
    const int pid = self->getCallingPid();
    const int uid = self->getCallingUid();
    if ((uid != AID_SHELL) &&
        !PermissionCache::checkPermission(
                String16("android.permission.DUMP"), pid, uid)) {
        return PERMISSION_DENIED;
    }

    double hours = 0;
    int time_window = 0;
    uint64_t threshold = 0;
    bool force_report = false;
    for (size_t i = 0; i < args.size(); i++) {
        const auto& arg = args[i];
        if (arg == String16("--hours")) {
            if (++i >= args.size())
                break;
            if(!ParseDouble(String8(args[i]).c_str(), &hours))
                return BAD_VALUE;
            continue;
        }
        if (arg == String16("--time_window")) {
            if (++i >= args.size())
                break;
            if(!ParseInt(String8(args[i]).c_str(), &time_window))
                return BAD_VALUE;
            continue;
        }
        if (arg == String16("--threshold")) {
            if (++i >= args.size())
                break;
            if(!ParseUint(String8(args[i]).c_str(), &threshold))
                return BAD_VALUE;
            continue;
        }
        if (arg == String16("--force")) {
            force_report = true;
            continue;
        }
    }

    uint64_t last_ts = 0;
    const std::map<uint64_t, struct uid_records>& records =
                storaged->get_uid_records(hours, threshold, force_report);
    for (const auto& it : records) {
        if (last_ts != it.second.start_ts) {
            dprintf(fd, "%llu", (unsigned long long)it.second.start_ts);
        }
        dprintf(fd, ",%llu\n", (unsigned long long)it.first);
        last_ts = it.first;

        for (const auto& record : it.second.entries) {
            dprintf(fd, "%s %ju %ju %ju %ju %ju %ju %ju %ju\n",
                record.name.c_str(),
                record.ios.bytes[READ][FOREGROUND][CHARGER_OFF],
                record.ios.bytes[WRITE][FOREGROUND][CHARGER_OFF],
                record.ios.bytes[READ][BACKGROUND][CHARGER_OFF],
                record.ios.bytes[WRITE][BACKGROUND][CHARGER_OFF],
                record.ios.bytes[READ][FOREGROUND][CHARGER_ON],
                record.ios.bytes[WRITE][FOREGROUND][CHARGER_ON],
                record.ios.bytes[READ][BACKGROUND][CHARGER_ON],
                record.ios.bytes[WRITE][BACKGROUND][CHARGER_ON]);
        }
    }

    if (time_window) {
        storaged->update_uid_io_interval(time_window);
    }

    return NO_ERROR;
}

sp<IStoraged> get_storaged_service() {
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) return NULL;

    sp<IBinder> binder = sm->getService(String16("storaged"));
    if (binder == NULL) return NULL;

    sp<IStoraged> storaged = interface_cast<IStoraged>(binder);

    return storaged;
}
