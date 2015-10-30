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

#ifndef METRICS_UPLOADER_UPLOAD_SERVICE_H_
#define METRICS_UPLOADER_UPLOAD_SERVICE_H_

#include <string>

#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_flattener.h"
#include "base/metrics/histogram_snapshot_manager.h"

#include "metrics/metrics_library.h"
#include "persistent_integer.h"
#include "uploader/metrics_log.h"
#include "uploader/sender.h"
#include "uploader/system_profile_cache.h"

namespace metrics {
class ChromeUserMetricsExtension;
class CrashSample;
class HistogramSample;
class LinearHistogramSample;
class MetricSample;
class SparseHistogramSample;
class UserActionSample;
}

class SystemProfileSetter;

// Service responsible for uploading the metrics periodically to the server.
// This service works as a simple 2-state state-machine.
//
// The two states are the presence or not of a staged log.
// A staged log is a compressed protobuffer containing both the aggregated
// metrics and event and information about the client. (product,
// model_manifest_id, etc...).
//
// At regular intervals, the upload event will be triggered and the following
// will happen:
// * if a staged log is present:
//    The previous upload may have failed for various reason. We then retry to
//    upload the same log.
//    - if the upload is successful, we discard the log (therefore
//      transitioning back to no staged log)
//    - if the upload fails, we keep the log to try again later.
//    We do not try to read the metrics that are stored on
//    the disk as we want to avoid storing the metrics in memory.
//
// * if no staged logs are present:
//    Read all metrics from the disk, aggregate them and try to send them.
//    - if the upload succeeds, we discard the staged log (transitioning back
//      to the no staged log state)
//    - if the upload fails, we keep the staged log in memory to retry
//      uploading later.
//
class UploadService : public base::HistogramFlattener {
 public:
  explicit UploadService(SystemProfileSetter* setter,
                         MetricsLibraryInterface* metrics_lib,
                         const std::string& server);

  void Init(const base::TimeDelta& upload_interval,
            const base::FilePath& metrics_directory);

  // Starts a new log. The log needs to be regenerated after each successful
  // launch as it is destroyed when staging the log.
  void StartNewLog();

  // Event callback for handling MessageLoop events.
  void UploadEventCallback(const base::TimeDelta& interval);

  // Triggers an upload event.
  void UploadEvent();

  // Sends the staged log.
  void SendStagedLog();

  // Implements inconsistency detection to match HistogramFlattener's
  // interface.
  void InconsistencyDetected(
      base::HistogramBase::Inconsistency problem) override {}
  void UniqueInconsistencyDetected(
      base::HistogramBase::Inconsistency problem) override {}
  void InconsistencyDetectedInLoggedCount(int amount) override {}

 private:
  friend class UploadServiceTest;

  FRIEND_TEST(UploadServiceTest, CanSendMultipleTimes);
  FRIEND_TEST(UploadServiceTest, DiscardLogsAfterTooManyFailedUpload);
  FRIEND_TEST(UploadServiceTest, EmptyLogsAreNotSent);
  FRIEND_TEST(UploadServiceTest, FailedSendAreRetried);
  FRIEND_TEST(UploadServiceTest, LogContainsAggregatedValues);
  FRIEND_TEST(UploadServiceTest, LogEmptyAfterUpload);
  FRIEND_TEST(UploadServiceTest, LogEmptyByDefault);
  FRIEND_TEST(UploadServiceTest, LogFromTheMetricsLibrary);
  FRIEND_TEST(UploadServiceTest, LogKernelCrash);
  FRIEND_TEST(UploadServiceTest, LogUncleanShutdown);
  FRIEND_TEST(UploadServiceTest, LogUserCrash);
  FRIEND_TEST(UploadServiceTest, UnknownCrashIgnored);
  FRIEND_TEST(UploadServiceTest, ValuesInConfigFileAreSent);

  // Private constructor for use in unit testing.
  UploadService(SystemProfileSetter* setter,
                MetricsLibraryInterface* metrics_lib,
                const std::string& server,
                bool testing);

  // If a staged log fails to upload more than kMaxFailedUpload times, it
  // will be discarded.
  static const int kMaxFailedUpload;

  // Resets the internal state.
  void Reset();

  // Reads all the metrics from the disk.
  void ReadMetrics();

  // Adds a generic sample to the current log.
  void AddSample(const metrics::MetricSample& sample);

  // Adds a crash to the current log.
  void AddCrash(const std::string& crash_name);

  // Aggregates all histogram available in memory and store them in the current
  // log.
  void GatherHistograms();

  // Callback for HistogramSnapshotManager to store the histograms.
  void RecordDelta(const base::HistogramBase& histogram,
                   const base::HistogramSamples& snapshot) override;

  // Compiles all the samples received into a single protobuf and adds all
  // system information.
  void StageCurrentLog();

  // Returns true iff a log is staged.
  bool HasStagedLog();

  // Remove the staged log iff the upload failed more than |kMaxFailedUpload|.
  void RemoveFailedLog();

  // Returns the current log. If there is no current log, creates it first.
  MetricsLog* GetOrCreateCurrentLog();

  scoped_ptr<SystemProfileSetter> system_profile_setter_;
  MetricsLibraryInterface* metrics_lib_;
  base::HistogramSnapshotManager histogram_snapshot_manager_;
  scoped_ptr<Sender> sender_;
  chromeos_metrics::PersistentInteger failed_upload_count_;
  scoped_ptr<MetricsLog> current_log_;

  base::FilePath metrics_file_;
  base::FilePath staged_log_path_;

  bool testing_;
};

#endif  // METRICS_UPLOADER_UPLOAD_SERVICE_H_
