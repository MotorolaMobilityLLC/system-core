// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "uploader/system_profile_cache.h"

#include <glib.h>
#include <string>
#include <vector>

#include "base/file_util.h"
#include "base/guid.h"
#include "base/logging.h"
#include "base/sys_info.h"
#include "components/metrics/metrics_log_base.h"
#include "components/metrics/proto/chrome_user_metrics_extension.pb.h"
#include "metrics/persistent_integer.h"
#include "vboot/crossystem.h"

const char* SystemProfileCache::kPersistentGUIDFile =
    "/var/lib/metrics/Sysinfo.GUID";
const char* SystemProfileCache::kPersistentSessionIdFilename =
    "Sysinfo.SessionId";

SystemProfileCache::SystemProfileCache()
    : initialized_(false),
      is_testing_(false),
      session_id_(new chromeos_metrics::PersistentInteger(
          kPersistentSessionIdFilename)) {
}

bool SystemProfileCache::Initialize() {
  CHECK(!initialized_)
      << "this should be called only once in the metrics_daemon lifetime.";

  if (!base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_NAME",
                                         &profile_.os_name) ||
      !base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION",
                                         &profile_.os_version) ||
      !base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_DESCRIPTION",
                                         &profile_.app_version) ||
      !GetHardwareId(&profile_.hardware_class)) {
    DLOG(ERROR) << "failing to initialize profile cache";
    return false;
  }

  std::string channel_string;
  base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_TRACK", &channel_string);
  profile_.channel = ProtoChannelFromString(channel_string);

  profile_.client_id =
      is_testing_ ? "client_id_test" : GetPersistentGUID(kPersistentGUIDFile);

  // Increment the session_id everytime we initialize this. If metrics_daemon
  // does not crash, this should correspond to the number of reboots of the
  // system.
  // TODO(bsimonnet): Change this to map to the number of time system-services
  // is started.
  session_id_->Add(1);
  profile_.session_id = static_cast<int32>(session_id_->Get());

  initialized_ = true;
  return initialized_;
}

bool SystemProfileCache::InitializeOrCheck() {
  return initialized_ || Initialize();
}

void SystemProfileCache::Populate(
    metrics::ChromeUserMetricsExtension* metrics_proto) {
  CHECK(metrics_proto);
  CHECK(InitializeOrCheck())
      << "failed to initialize system information.";

  // The client id is hashed before being sent.
  metrics_proto->set_client_id(
      metrics::MetricsLogBase::Hash(profile_.client_id));
  metrics_proto->set_session_id(profile_.session_id);

  metrics::SystemProfileProto* profile_proto =
      metrics_proto->mutable_system_profile();
  profile_proto->mutable_hardware()->set_hardware_class(
      profile_.hardware_class);
  profile_proto->set_app_version(profile_.app_version);
  profile_proto->set_channel(profile_.channel);

  metrics::SystemProfileProto_OS* os = profile_proto->mutable_os();
  os->set_name(profile_.os_name);
  os->set_version(profile_.os_version);
}

std::string SystemProfileCache::GetPersistentGUID(const std::string& filename) {
  std::string guid;
  base::FilePath filepath(filename);
  if (!base::ReadFileToString(filepath, &guid)) {
    guid = base::GenerateGUID();
    // If we can't read or write the file, the guid will not be preserved during
    // the next reboot. Crash.
    CHECK(base::WriteFile(filepath, guid.c_str(), guid.size()));
  }
  return guid;
}

bool SystemProfileCache::GetHardwareId(std::string* hwid) {
  CHECK(hwid);

  if (is_testing_) {
    // if we are in test mode, we do not call crossystem directly.
    DLOG(INFO) << "skipping hardware id";
    *hwid = "";
    return true;
  }

  char buffer[128];
  if (buffer != VbGetSystemPropertyString("hwid", buffer, sizeof(buffer))) {
    LOG(ERROR) << "error getting hwid";
    return false;
  }

  *hwid = std::string(buffer);
  return true;
}

metrics::SystemProfileProto_Channel SystemProfileCache::ProtoChannelFromString(
    const std::string& channel) {

  if (channel == "stable-channel") {
    return metrics::SystemProfileProto::CHANNEL_STABLE;
  } else if (channel == "dev-channel") {
    return metrics::SystemProfileProto::CHANNEL_DEV;
  } else if (channel == "beta-channel") {
    return metrics::SystemProfileProto::CHANNEL_BETA;
  } else if (channel == "canary-channel") {
    return metrics::SystemProfileProto::CHANNEL_CANARY;
  }

  DLOG(INFO) << "unknown channel: " << channel;
  return metrics::SystemProfileProto::CHANNEL_UNKNOWN;
}
