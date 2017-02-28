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

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_

#include "android-base/properties.h"

#include <sys/system_properties.h>
#include <sys/_system_properties.h>

#include <algorithm>
#include <chrono>
#include <string>

#include <android-base/parseint.h>

using namespace std::chrono_literals;

namespace android {
namespace base {

std::string GetProperty(const std::string& key, const std::string& default_value) {
  const prop_info* pi = __system_property_find(key.c_str());
  if (pi == nullptr) return default_value;

  char buf[PROP_VALUE_MAX];
  if (__system_property_read(pi, nullptr, buf) > 0) return buf;

  // If the property exists but is empty, also return the default value.
  // Since we can't remove system properties, "empty" is traditionally
  // the same as "missing" (this was true for cutils' property_get).
  return default_value;
}

bool GetBoolProperty(const std::string& key, bool default_value) {
  std::string value = GetProperty(key, "");
  if (value == "1" || value == "y" || value == "yes" || value == "on" || value == "true") {
    return true;
  } else if (value == "0" || value == "n" || value == "no" || value == "off" || value == "false") {
    return false;
  }
  return default_value;
}

template <typename T>
T GetIntProperty(const std::string& key, T default_value, T min, T max) {
  T result;
  std::string value = GetProperty(key, "");
  if (!value.empty() && android::base::ParseInt(value, &result, min, max)) return result;
  return default_value;
}

template <typename T>
T GetUintProperty(const std::string& key, T default_value, T max) {
  T result;
  std::string value = GetProperty(key, "");
  if (!value.empty() && android::base::ParseUint(value, &result, max)) return result;
  return default_value;
}

template int8_t GetIntProperty(const std::string&, int8_t, int8_t, int8_t);
template int16_t GetIntProperty(const std::string&, int16_t, int16_t, int16_t);
template int32_t GetIntProperty(const std::string&, int32_t, int32_t, int32_t);
template int64_t GetIntProperty(const std::string&, int64_t, int64_t, int64_t);

template uint8_t GetUintProperty(const std::string&, uint8_t, uint8_t);
template uint16_t GetUintProperty(const std::string&, uint16_t, uint16_t);
template uint32_t GetUintProperty(const std::string&, uint32_t, uint32_t);
template uint64_t GetUintProperty(const std::string&, uint64_t, uint64_t);

bool SetProperty(const std::string& key, const std::string& value) {
  return (__system_property_set(key.c_str(), value.c_str()) == 0);
}

struct WaitForPropertyData {
  bool done;
  const std::string* expected_value;
  unsigned last_read_serial;
};

static void WaitForPropertyCallback(void* data_ptr, const char*, const char* value, unsigned serial) {
  WaitForPropertyData* data = reinterpret_cast<WaitForPropertyData*>(data_ptr);
  if (*data->expected_value == value) {
    data->done = true;
  } else {
    data->last_read_serial = serial;
  }
}

// TODO: chrono_utils?
static void DurationToTimeSpec(timespec& ts, std::chrono::nanoseconds d) {
  auto s = std::chrono::duration_cast<std::chrono::seconds>(d);
  auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(d - s);
  ts.tv_sec = s.count();
  ts.tv_nsec = ns.count();
}

using AbsTime = std::chrono::time_point<std::chrono::steady_clock>;

static void UpdateTimeSpec(timespec& ts,
                           const AbsTime& timeout) {
  auto now = std::chrono::steady_clock::now();
  auto remaining_timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(timeout - now);
  if (remaining_timeout < 0ns) {
    ts = { 0, 0 };
  } else {
    DurationToTimeSpec(ts, remaining_timeout);
  }
}

// Waits for the system property `key` to be created.
// Times out after `relative_timeout`.
// Sets absolute_timeout which represents absolute time for the timeout.
// Returns nullptr on timeout.
static const prop_info* WaitForPropertyCreation(const std::string& key,
                                                const std::chrono::milliseconds& relative_timeout,
                                                AbsTime& absolute_timeout) {
  // TODO: boot_clock?
  auto now = std::chrono::steady_clock::now();
  absolute_timeout = now + relative_timeout;

  // Find the property's prop_info*.
  const prop_info* pi;
  unsigned global_serial = 0;
  while ((pi = __system_property_find(key.c_str())) == nullptr) {
    // The property doesn't even exist yet.
    // Wait for a global change and then look again.
    timespec ts;
    UpdateTimeSpec(ts, absolute_timeout);
    if (!__system_property_wait(nullptr, global_serial, &global_serial, &ts)) return nullptr;
  }
  return pi;
}

bool WaitForProperty(const std::string& key,
                     const std::string& expected_value,
                     std::chrono::milliseconds relative_timeout) {
  AbsTime absolute_timeout;
  const prop_info* pi = WaitForPropertyCreation(key, relative_timeout, absolute_timeout);
  if (pi == nullptr) return false;

  WaitForPropertyData data;
  data.expected_value = &expected_value;
  data.done = false;
  while (true) {
    timespec ts;
    // Check whether the property has the value we're looking for?
    __system_property_read_callback(pi, WaitForPropertyCallback, &data);
    if (data.done) return true;

    // It didn't, so wait for the property to change before checking again.
    UpdateTimeSpec(ts, absolute_timeout);
    uint32_t unused;
    if (!__system_property_wait(pi, data.last_read_serial, &unused, &ts)) return false;
  }
}

bool WaitForPropertyCreation(const std::string& key,
                             std::chrono::milliseconds relative_timeout) {
  AbsTime absolute_timeout;
  return (WaitForPropertyCreation(key, relative_timeout, absolute_timeout) != nullptr);
}

}  // namespace base
}  // namespace android
