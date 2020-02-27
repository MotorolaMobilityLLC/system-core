/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "gatekeeperd"

#include <android/service/gatekeeper/BnGateKeeperService.h>
#include <gatekeeper/GateKeeperResponse.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <memory>

#include <android/security/keystore/IKeystoreService.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <gatekeeper/password_handle.h> // for password_handle_t
#include <hardware/gatekeeper.h>
#include <hardware/hw_auth_token.h>
#include <keystore/keystore.h> // For error code
#include <keystore/keystore_return_types.h>
#include <libgsi/libgsi.h>
#include <log/log.h>
#include <utils/Log.h>
#include <utils/String16.h>

#include <hidl/HidlSupport.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

using android::sp;
using android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;
using android::hardware::Return;

using ::android::binder::Status;
using ::android::service::gatekeeper::BnGateKeeperService;
using GKResponse = ::android::service::gatekeeper::GateKeeperResponse;
using GKResponseCode = ::android::service::gatekeeper::ResponseCode;

namespace android {

static const String16 KEYGUARD_PERMISSION("android.permission.ACCESS_KEYGUARD_SECURE_STORAGE");
static const String16 DUMP_PERMISSION("android.permission.DUMP");

class GateKeeperProxy : public BnGateKeeperService {
public:
    GateKeeperProxy() {
        clear_state_if_needed_done = false;
        hw_device = IGatekeeper::getService();
        is_running_gsi = android::base::GetBoolProperty(android::gsi::kGsiBootedProp, false);

        if (!hw_device) {
            LOG(ERROR) << "Could not find Gatekeeper device, which makes me very sad.";
        }
    }

    virtual ~GateKeeperProxy() {
    }

    void store_sid(uint32_t uid, uint64_t sid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", uid);
        int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            ALOGE("could not open file: %s: %s", filename, strerror(errno));
            return;
        }
        write(fd, &sid, sizeof(sid));
        close(fd);
    }

    void clear_state_if_needed() {
        if (clear_state_if_needed_done) {
            return;
        }

        if (mark_cold_boot() && !is_running_gsi) {
            ALOGI("cold boot: clearing state");
            if (hw_device) {
                hw_device->deleteAllUsers([](const GatekeeperResponse &){});
            }
        }

        clear_state_if_needed_done = true;
    }

    bool mark_cold_boot() {
        const char *filename = ".coldboot";
        if (access(filename, F_OK) == -1) {
            int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
            if (fd < 0) {
                ALOGE("could not open file: %s : %s", filename, strerror(errno));
                return false;
            }
            close(fd);
            return true;
        }
        return false;
    }

    void maybe_store_sid(uint32_t uid, uint64_t sid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", uid);
        if (access(filename, F_OK) == -1) {
            store_sid(uid, sid);
        }
    }

    uint64_t read_sid(uint32_t uid) {
        char filename[21];
        uint64_t sid;
        snprintf(filename, sizeof(filename), "%u", uid);
        int fd = open(filename, O_RDONLY);
        if (fd < 0) return 0;
        read(fd, &sid, sizeof(sid));
        close(fd);
        return sid;
    }

    void clear_sid(uint32_t uid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", uid);
        if (remove(filename) < 0) {
            ALOGE("%s: could not remove file [%s], attempting 0 write", __func__, strerror(errno));
            store_sid(uid, 0);
        }
    }

    // This should only be called on uids being passed to the GateKeeper HAL. It ensures that
    // secure storage shared across a GSI image and a host image will not overlap.
    uint32_t adjust_uid(uint32_t uid) {
        static constexpr uint32_t kGsiOffset = 1000000;
        CHECK(uid < kGsiOffset);
        CHECK(hw_device != nullptr);
        if (is_running_gsi) {
            return uid + kGsiOffset;
        }
        return uid;
    }

#define GK_ERROR *gkResponse = GKResponse::error(), Status::ok()

    Status enroll(int32_t uid, const std::optional<std::vector<uint8_t>>& currentPasswordHandle,
                  const std::optional<std::vector<uint8_t>>& currentPassword,
                  const std::vector<uint8_t>& desiredPassword, GKResponse* gkResponse) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return GK_ERROR;
        }

        // Make sure to clear any state from before factory reset as soon as a credential is
        // enrolled (which may happen during device setup).
        clear_state_if_needed();

        // need a desired password to enroll
        if (desiredPassword.size() == 0) return GK_ERROR;

        if (!hw_device) {
            LOG(ERROR) << "has no HAL to talk to";
            return GK_ERROR;
        }

        android::hardware::hidl_vec<uint8_t> curPwdHandle;
        android::hardware::hidl_vec<uint8_t> curPwd;

        if (currentPasswordHandle && currentPassword) {
            if (currentPasswordHandle->size() != sizeof(gatekeeper::password_handle_t)) {
                LOG(INFO) << "Password handle has wrong length";
                return GK_ERROR;
            }
            curPwdHandle.setToExternal(const_cast<uint8_t*>(currentPasswordHandle->data()),
                                       currentPasswordHandle->size());
            curPwd.setToExternal(const_cast<uint8_t*>(currentPassword->data()),
                                 currentPassword->size());
        }

        android::hardware::hidl_vec<uint8_t> newPwd;
        newPwd.setToExternal(const_cast<uint8_t*>(desiredPassword.data()), desiredPassword.size());

        uint32_t hw_uid = adjust_uid(uid);
        Return<void> hwRes = hw_device->enroll(
                hw_uid, curPwdHandle, curPwd, newPwd, [&gkResponse](const GatekeeperResponse& rsp) {
                    if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                        *gkResponse = GKResponse::ok({rsp.data.begin(), rsp.data.end()});
                    } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT &&
                               rsp.timeout > 0) {
                        *gkResponse = GKResponse::retry(rsp.timeout);
                    } else {
                        *gkResponse = GKResponse::error();
                    }
                });
        if (!hwRes.isOk()) {
            LOG(ERROR) << "enroll transaction failed";
            return GK_ERROR;
        }

        if (gkResponse->response_code() == GKResponseCode::OK && !gkResponse->should_reenroll()) {
            if (gkResponse->payload().size() != sizeof(gatekeeper::password_handle_t)) {
                LOG(ERROR) << "HAL returned password handle of invalid length "
                           << gkResponse->payload().size();
                return GK_ERROR;
            }

            const gatekeeper::password_handle_t* handle =
                    reinterpret_cast<const gatekeeper::password_handle_t*>(
                            gkResponse->payload().data());
            store_sid(uid, handle->user_id);

            GKResponse verifyResponse;
            // immediately verify this password so we don't ask the user to enter it again
            // if they just created it.
            auto status = verify(uid, gkResponse->payload(), desiredPassword, &verifyResponse);
            if (!status.isOk() || verifyResponse.response_code() != GKResponseCode::OK) {
                LOG(ERROR) << "Failed to verify password after enrolling";
            }
        }

        return Status::ok();
    }

    Status verify(int32_t uid, const ::std::vector<uint8_t>& enrolledPasswordHandle,
                  const ::std::vector<uint8_t>& providedPassword, GKResponse* gkResponse) override {
        return verifyChallenge(uid, 0 /* challenge */, enrolledPasswordHandle, providedPassword,
                               gkResponse);
    }

    Status verifyChallenge(int32_t uid, int64_t challenge,
                           const std::vector<uint8_t>& enrolledPasswordHandle,
                           const std::vector<uint8_t>& providedPassword,
                           GKResponse* gkResponse) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return GK_ERROR;
        }

        // can't verify if we're missing either param
        if (enrolledPasswordHandle.size() == 0 || providedPassword.size() == 0) return GK_ERROR;

        if (!hw_device) return GK_ERROR;

        if (enrolledPasswordHandle.size() != sizeof(gatekeeper::password_handle_t)) {
            LOG(INFO) << "Password handle has wrong length";
            return GK_ERROR;
        }
        const gatekeeper::password_handle_t* handle =
                reinterpret_cast<const gatekeeper::password_handle_t*>(
                        enrolledPasswordHandle.data());

        uint32_t hw_uid = adjust_uid(uid);
        android::hardware::hidl_vec<uint8_t> curPwdHandle;
        curPwdHandle.setToExternal(const_cast<uint8_t*>(enrolledPasswordHandle.data()),
                                   enrolledPasswordHandle.size());
        android::hardware::hidl_vec<uint8_t> enteredPwd;
        enteredPwd.setToExternal(const_cast<uint8_t*>(providedPassword.data()),
                                 providedPassword.size());

        Return<void> hwRes = hw_device->verify(
                hw_uid, challenge, curPwdHandle, enteredPwd,
                [&gkResponse](const GatekeeperResponse& rsp) {
                    if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                        *gkResponse = GKResponse::ok(
                                {rsp.data.begin(), rsp.data.end()},
                                rsp.code == GatekeeperStatusCode::STATUS_REENROLL /* reenroll */);
                    } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT) {
                        *gkResponse = GKResponse::retry(rsp.timeout);
                    } else {
                        *gkResponse = GKResponse::error();
                    }
                });

        if (!hwRes.isOk()) {
            LOG(ERROR) << "verify transaction failed";
            return GK_ERROR;
        }

        if (gkResponse->response_code() == GKResponseCode::OK) {
            if (gkResponse->payload().size() != 0) {
                sp<IServiceManager> sm = defaultServiceManager();
                sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
                sp<security::keystore::IKeystoreService> service =
                        interface_cast<security::keystore::IKeystoreService>(binder);

                if (service) {
                    int result = 0;
                    auto binder_result = service->addAuthToken(gkResponse->payload(), &result);
                    if (!binder_result.isOk() ||
                        !keystore::KeyStoreServiceReturnCode(result).isOk()) {
                        LOG(ERROR) << "Failure sending auth token to KeyStore: " << result;
                    }
                } else {
                    LOG(ERROR) << "Cannot deliver auth token. Unable to communicate with Keystore.";
                }
            }

            maybe_store_sid(uid, handle->user_id);
        }

        return Status::ok();
    }

    Status getSecureUserId(int32_t uid, int64_t* sid) override {
        *sid = read_sid(uid);
        return Status::ok();
    }

    Status clearSecureUserId(int32_t uid) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            ALOGE("%s: permission denied for [%d:%d]", __func__, calling_pid, calling_uid);
            return Status::ok();
        }
        clear_sid(uid);

        if (hw_device) {
            uint32_t hw_uid = adjust_uid(uid);
            hw_device->deleteUser(hw_uid, [] (const GatekeeperResponse &){});
        }
        return Status::ok();
    }

    Status reportDeviceSetupComplete() override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            ALOGE("%s: permission denied for [%d:%d]", __func__, calling_pid, calling_uid);
            return Status::ok();
        }

        clear_state_if_needed();
        return Status::ok();
    }

    status_t dump(int fd, const Vector<String16>&) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int pid = ipc->getCallingPid();
        const int uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(DUMP_PERMISSION, pid, uid)) {
            return PERMISSION_DENIED;
        }

        if (hw_device == NULL) {
            const char *result = "Device not available";
            write(fd, result, strlen(result) + 1);
        } else {
            const char *result = "OK";
            write(fd, result, strlen(result) + 1);
        }

        return OK;
    }

private:
    sp<IGatekeeper> hw_device;

    bool clear_state_if_needed_done;
    bool is_running_gsi;
};
}// namespace android

int main(int argc, char* argv[]) {
    ALOGI("Starting gatekeeperd...");
    if (argc < 2) {
        ALOGE("A directory must be specified!");
        return 1;
    }
    if (chdir(argv[1]) == -1) {
        ALOGE("chdir: %s: %s", argv[1], strerror(errno));
        return 1;
    }

    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<android::GateKeeperProxy> proxy = new android::GateKeeperProxy();
    android::status_t ret = sm->addService(
            android::String16("android.service.gatekeeper.IGateKeeperService"), proxy);
    if (ret != android::OK) {
        ALOGE("Couldn't register binder service!");
        return -1;
    }

    /*
     * We're the only thread in existence, so we're just going to process
     * Binder transaction as a single-threaded program.
     */
    android::IPCThreadState::self()->joinThreadPool();
    return 0;
}
