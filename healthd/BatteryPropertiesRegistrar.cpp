/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include "BatteryPropertiesRegistrar.h"
#include <batteryservice/BatteryService.h>
#include <batteryservice/IBatteryPropertiesListener.h>
#include <batteryservice/IBatteryPropertiesRegistrar.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <private/android_filesystem_config.h>
#include <utils/Errors.h>
#include <utils/Mutex.h>
#include <utils/String16.h>

#include <healthd/healthd.h>
// BEGIN motorola, chenym7, 1/26/2018, IKSWO-35619
// STOPSHIP : print the debug log
#include <cutils/klog.h>
// END motorola, IKSWO-35619

namespace android {

void BatteryPropertiesRegistrar::publish(
    const sp<BatteryPropertiesRegistrar>& service) {
    defaultServiceManager()->addService(String16("batteryproperties"), service);
    // BEGIN motorola, chenym7, 1/26/2018, IKSWO-35619
    // STOPSHIP : print the debug log
    KLOG_WARNING("BatteryPropertiesRegistrar", "publish service: batteryproperties \n");
    // END motorola, IKSWO-35619
}

void BatteryPropertiesRegistrar::notifyListeners(const struct BatteryProperties& props) {
    Vector<sp<IBatteryPropertiesListener> > listenersCopy;

    // Binder currently may service an incoming oneway transaction whenever an
    // outbound oneway call is made (if there is already a pending incoming
    // oneway call waiting).  This is considered a bug and may change in the
    // future.  For now, avoid recursive mutex lock while making outbound
    // calls by making a local copy of the current list of listeners.
    {
        Mutex::Autolock _l(mRegistrationLock);
        listenersCopy = mListeners;
    }
    for (size_t i = 0; i < listenersCopy.size(); i++) {
        listenersCopy[i]->batteryPropertiesChanged(props);
    }
}

void BatteryPropertiesRegistrar::registerListener(const sp<IBatteryPropertiesListener>& listener) {
    {
        if (listener == NULL)
            return;
        Mutex::Autolock _l(mRegistrationLock);
        // check whether this is a duplicate
        for (size_t i = 0; i < mListeners.size(); i++) {
            if (IInterface::asBinder(mListeners[i]) == IInterface::asBinder(listener)) {
                return;
            }
        }

        mListeners.add(listener);
        IInterface::asBinder(listener)->linkToDeath(this);
    }
    healthd_battery_update();
}

void BatteryPropertiesRegistrar::unregisterListener(const sp<IBatteryPropertiesListener>& listener) {
    if (listener == NULL)
        return;
    Mutex::Autolock _l(mRegistrationLock);
    for (size_t i = 0; i < mListeners.size(); i++) {
        if (IInterface::asBinder(mListeners[i]) == IInterface::asBinder(listener)) {
            IInterface::asBinder(mListeners[i])->unlinkToDeath(this);
            mListeners.removeAt(i);
            break;
        }
    }
}

status_t BatteryPropertiesRegistrar::getProperty(int id, struct BatteryProperty *val) {
    return healthd_get_property(id, val);
}

void BatteryPropertiesRegistrar::scheduleUpdate() {
    healthd_battery_update();
}

status_t BatteryPropertiesRegistrar::dump(int fd, const Vector<String16>& /*args*/) {
    IPCThreadState* self = IPCThreadState::self();
    const int pid = self->getCallingPid();
    const int uid = self->getCallingUid();
    if ((uid != AID_SHELL) &&
        !PermissionCache::checkPermission(
                String16("android.permission.DUMP"), pid, uid))
        return PERMISSION_DENIED;

    healthd_dump_battery_state(fd);
    return OK;
}

void BatteryPropertiesRegistrar::binderDied(const wp<IBinder>& who) {
    Mutex::Autolock _l(mRegistrationLock);

    for (size_t i = 0; i < mListeners.size(); i++) {
        if (IInterface::asBinder(mListeners[i]) == who) {
            mListeners.removeAt(i);
            break;
        }
    }
}

}  // namespace android
