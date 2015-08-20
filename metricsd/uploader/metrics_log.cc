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

#include "uploader/metrics_log.h"

#include <string>

#include "uploader/proto/system_profile.pb.h"
#include "uploader/system_profile_setter.h"

// We use default values for the MetricsLogBase constructor as the setter will
// override them.
MetricsLog::MetricsLog()
    : MetricsLogBase("", 0, metrics::MetricsLogBase::ONGOING_LOG, "") {
}

void MetricsLog::IncrementUserCrashCount() {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->other_user_crash_count();
  stability->set_other_user_crash_count(current + 1);
}

void MetricsLog::IncrementKernelCrashCount() {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->kernel_crash_count();
  stability->set_kernel_crash_count(current + 1);
}

void MetricsLog::IncrementUncleanShutdownCount() {
  metrics::SystemProfileProto::Stability* stability(
      uma_proto()->mutable_system_profile()->mutable_stability());
  int current = stability->unclean_system_shutdown_count();
  stability->set_unclean_system_shutdown_count(current + 1);
}

bool MetricsLog::PopulateSystemProfile(SystemProfileSetter* profile_setter) {
  return profile_setter->Populate(uma_proto());
}
