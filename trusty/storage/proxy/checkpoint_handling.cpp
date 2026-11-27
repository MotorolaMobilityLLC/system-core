/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include "checkpoint_handling.h"
#include "ipc.h"
#include "log.h"

#include <fstab/fstab.h>
#include <unistd.h>
#include <cstring>
#include <string>

#include <aidl/android/system/vold/BnVoldCheckpointListener.h>
#include <aidl/android/system/vold/IVold.h>
#include <android/binder_auto_utils.h>
#include <android/binder_interface_utils.h>
#include <android/binder_manager.h>
#include <libgsi/libgsi.h>

namespace {

using ::aidl::android::system::vold::BnVoldCheckpointListener;
using ::aidl::android::system::vold::CheckpointingState;
using ::aidl::android::system::vold::IVold;
using ::aidl::android::system::vold::toString;
using ::ndk::ScopedAStatus;
using ::ndk::SharedRefBase;

const char kVoldService[] = "android.system.vold.IVold/default";

/* Written once from main thread before any checkpointing_get_state
 * calls could be reading it. */
bool voldConnected = false;
std::atomic<bool> voldPossibleCheckpointing = true;

class VoldListener : public BnVoldCheckpointListener {
  public:
    ScopedAStatus onCheckpointingComplete() final {
        voldPossibleCheckpointing.store(false);
        ALOGD("VoldCheckpointListener reported checkpointing complete\n");
        return ScopedAStatus::ok();
    }
};

int is_data_checkpoint_active_legacy(bool* active) {
    *active = false;

    static bool checkpointingDoneForever = false;
    if (checkpointingDoneForever) {
        return 0;
    }

    android::fs_mgr::Fstab procMounts;
    bool success = android::fs_mgr::ReadFstabFromFile("/proc/mounts", &procMounts);
    if (!success) {
        ALOGE("Could not parse /proc/mounts\n");
        /* Really bad. Tell the caller to abort the write. */
        return -1;
    }

    android::fs_mgr::FstabEntry* dataEntry =
            android::fs_mgr::GetEntryForMountPoint(&procMounts, "/data");
    if (dataEntry == NULL) {
        ALOGE("/data is not mounted yet\n");
        return 0;
    }

    /* We can't handle e.g., ext4. Nothing we can do about it for now. */
    if (dataEntry->fs_type != "f2fs") {
        ALOGW("Checkpoint status not supported for filesystem %s\n", dataEntry->fs_type.c_str());
        if (voldConnected) {
            *active = voldPossibleCheckpointing.load();
        } else {
            checkpointingDoneForever = true;
        }
        return 0;
    }

    /*
     * The data entry looks like "... blah,checkpoint=disable:0,blah ...".
     * checkpoint=disable means checkpointing is on (yes, arguably reversed).
     */
    size_t checkpointPos = dataEntry->fs_options.find("checkpoint=disable");
    if (checkpointPos == std::string::npos) {
        /* Assumption is that once checkpointing turns off, it stays off */
        checkpointingDoneForever = true;
    } else {
        *active = true;
    }

    return 0;
}

}  // namespace

int is_data_checkpoint_active(bool* active) {
    if (!active) {
        ALOGE("active out parameter is null");
        return 0;
    }

    if (!voldConnected) {
        return is_data_checkpoint_active_legacy(active);
    }

    bool legacy;
    int rc = is_data_checkpoint_active_legacy(&legacy);

    bool vold = voldPossibleCheckpointing.load();
    if (rc == 0) {
        if (!vold && legacy) {
            ALOGE("Vold reports checkpointing done but Fstab says it's ongoing. Using Fstab "
                  "state.\n");
            *active = legacy;
            return 0;
        }
        if (vold && !legacy) {
            ALOGI("Vold reports possible checkpointing done but Fstab says it's done.\n");
        }
    }

    *active = vold;
    return 0;
}

/**
 * is_gsi_running() - Check if a GSI image is running via DSU.
 *
 * This function is equivalent to android::gsi::IsGsiRunning(), but this API is
 * not yet vendor-accessible although the underlying metadata file is.
 *
 */
bool is_gsi_running() {
    /* TODO(b/210501710): Expose GSI image running state to vendor storageproxyd */
    return !access(android::gsi::kGsiBootedIndicatorFile, F_OK);
}

int vold_connect() {
    auto binder = ndk::SpAIBinder(AServiceManager_waitForService(kVoldService));
    if (binder == nullptr) {
        ALOGE("Got null binder for %s (was %sdeclared)\n", kVoldService,
              AServiceManager_isDeclared(kVoldService) ? "" : "not ");
        return 0;
    }

    auto vold = IVold::fromBinder(binder);
    if (vold == nullptr) {
        ALOGE("Could not convert binder to android::system::vold::IVold\n");
        return 0;
    }

    CheckpointingState state;
    ScopedAStatus ret =
            vold->registerCheckpointListener(SharedRefBase::make<VoldListener>(), &state);
    if (!ret.isOk()) {
        ALOGE("Could not register VoldCheckpointListener: %s\n", ret.getDescription().c_str());
        return 0;
    }
    ALOGD("Registered VoldCheckpointListener in %s\n", toString(state).c_str());

    if (state == CheckpointingState::CHECKPOINTING_COMPLETE) {
        voldPossibleCheckpointing.store(false);
    }

    voldConnected = true;
    return 0;
}

int checkpointing_get_state(struct storage_msg* msg, const void*, size_t req_len, struct watcher*) {
    if (req_len != 0) {
        ALOGE("%s: invalid request length (%zu != %d)\n", __func__, req_len, 0);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    if (!voldConnected) {
        ALOGE("Checkpointing state requested but no connection to vold.\n");
        msg->result = STORAGE_ERR_UNIMPLEMENTED;
        goto err_response;
    }

    msg->result = STORAGE_NO_ERROR;
    struct storage_checkpointing_state_resp resp;
    resp.state = voldPossibleCheckpointing.load() ? STORAGE_CHECKPOINT_STATE_POSSIBLE
                                                  : STORAGE_CHECKPOINT_STATE_DONE;

    /*
     * TODO: Get the real boot slot so that when storage boots with an on-disk checkpoint, it can
     * tell whether it should be used or discarded.
     */
    resp.boot_slot = -1;
    ALOGD("Read checkpointing state %d\n", resp.state);
    return ipc_respond(msg, &resp, sizeof(resp));

err_response:
    return ipc_respond(msg, NULL, 0);
}
