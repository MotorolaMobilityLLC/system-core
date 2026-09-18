/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "usbd"

#include <string>

#include <aidl/android/hardware/usb/gadget/GadgetFunction.h>
#include <aidl/android/hardware/usb/gadget/IUsbGadget.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <android/hardware/usb/gadget/1.0/IUsbGadget.h>
#include <android_hardware_usb_flags.h>

namespace usb_flags = android::hardware::usb::flags;

using aidl::android::hardware::usb::gadget::GadgetFunction;
using android::base::GetProperty;
using android::base::GetBoolProperty;
using android::base::SetProperty;
using android::hardware::Return;
using ndk::ScopedAStatus;
using std::shared_ptr;

std::atomic<int> sUsbOperationCount{};

int main(int /*argc*/, char** /*argv*/) {
    if (GetProperty("ro.bootmode", "") == "charger") exit(0);
    int operationId = sUsbOperationCount++;

    ABinderProcess_setThreadPoolMaxThreadCount(1);
    ABinderProcess_startThreadPool();
    const std::string service_name =
            std::string(aidl::android::hardware::usb::gadget::IUsbGadget::descriptor)
                    .append("/default");

    std::string function = GetProperty("persist.sys.usb.config", "");
    uint64_t functions;

    if (function == "adb") {
        LOG(INFO) << "persistent prop is adb";
        SetProperty("ctl.start", "adbd");
        functions = static_cast<uint64_t>(GadgetFunction::ADB);
    } else {
        LOG(INFO) << "Signal MTP to enable default functions";
        functions = static_cast<uint64_t>(GadgetFunction::MTP);
    }

    if (usb_flags::enable_aoa_userspace_implementation() &&
        GetBoolProperty("ro.usb.userspace.aoa.enabled", false)) {
        functions |= static_cast<uint64_t>(GadgetFunction::CTRL);
    }

    if (AServiceManager_isDeclared(service_name.c_str())) {
        shared_ptr<aidl::android::hardware::usb::gadget::IUsbGadget> gadget_aidl =
                aidl::android::hardware::usb::gadget::IUsbGadget::fromBinder(
                        ndk::SpAIBinder(AServiceManager_waitForService(service_name.c_str())));
        ScopedAStatus ret;
        if (gadget_aidl != nullptr) {
            LOG(INFO) << "Usb AIDL HAL found.";
            ret = gadget_aidl->setCurrentUsbFunctions(functions, nullptr, 0, operationId);

            if (!ret.isOk()) LOG(ERROR) << "Error while invoking usb hal";
        } else {
            LOG(INFO) << "Usb AIDL HAL not found";
        }
    } else {
        android::sp<android::hardware::usb::gadget::V1_0::IUsbGadget> gadget =
                android::hardware::usb::gadget::V1_0::IUsbGadget::getService();
        Return<void> ret;
        if (gadget != nullptr) {
            LOG(INFO) << "Usb HAL found.";
            ret = gadget->setCurrentUsbFunctions(functions, nullptr, 0);

            if (!ret.isOk()) LOG(ERROR) << "Error while invoking usb hal";
        } else {
            LOG(INFO) << "Usb HAL not found";
        }
    }
    exit(0);
}
