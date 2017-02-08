/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef ANDROID_BASE_CHRONO_UTILS_H
#define ANDROID_BASE_CHRONO_UTILS_H

#include <chrono>

namespace android {
namespace base {

// A std::chrono clock based on CLOCK_BOOTTIME.
class boot_clock {
 public:
  typedef std::chrono::nanoseconds duration;
  typedef std::chrono::time_point<boot_clock, duration> time_point;

  static time_point now();
};

}  // namespace base
}  // namespace android

#endif  // ANDROID_BASE_CHRONO_UTILS_H
