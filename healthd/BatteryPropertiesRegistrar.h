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

#ifndef HEALTHD_BATTERYPROPERTIES_REGISTRAR_H
#define HEALTHD_BATTERYPROPERTIES_REGISTRAR_H

#include <binder/IBinder.h>
#include <utils/Mutex.h>
#include <utils/String16.h>
#include <utils/Vector.h>
#include <batteryservice/BatteryService.h>
#include <batteryservice/IBatteryPropertiesListener.h>
#include <batteryservice/IBatteryPropertiesRegistrar.h>

namespace android {

class BatteryPropertiesRegistrar : public BnBatteryPropertiesRegistrar,
                                   public IBinder::DeathRecipient {
public:
    void publish(const sp<BatteryPropertiesRegistrar>& service);
    void notifyListeners(const struct BatteryProperties& props);

private:
    Mutex mRegistrationLock;
    Vector<sp<IBatteryPropertiesListener> > mListeners;

    void registerListener(const sp<IBatteryPropertiesListener>& listener);
    void unregisterListener(const sp<IBatteryPropertiesListener>& listener);
    status_t getProperty(int id, struct BatteryProperty *val);
    status_t dump(int fd, const Vector<String16>& args);
    void binderDied(const wp<IBinder>& who);
};

};  // namespace android

#endif // HEALTHD_BATTERYPROPERTIES_REGISTRAR_H
