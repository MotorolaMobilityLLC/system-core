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

#include "serialization/serialization_utils.h"

#include <sys/file.h>

#include <string>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "base/memory/scoped_vector.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "serialization/metric_sample.h"

#define READ_WRITE_ALL_FILE_FLAGS \
  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

namespace metrics {
namespace {

// Reads the next message from |file_descriptor| into |message|.
//
// |message| will be set to the empty string if no message could be read (EOF)
// or the message was badly constructed.
//
// Returns false if no message can be read from this file anymore (EOF or
// unrecoverable error).
bool ReadMessage(int fd, std::string* message) {
  CHECK(message);

  int result;
  int32_t message_size;
  const int32_t message_hdr_size = sizeof(message_size);
  // The file containing the metrics do not leave the device so the writer and
  // the reader will always have the same endianness.
  result = HANDLE_EINTR(read(fd, &message_size, sizeof(message_size)));
  if (result < 0) {
    DPLOG(ERROR) << "reading metrics message header";
    return false;
  }
  if (result == 0) {
    // This indicates a normal EOF.
    return false;
  }
  if (result < message_hdr_size) {
    DLOG(ERROR) << "bad read size " << result << ", expecting "
                << sizeof(message_size);
    return false;
  }

  // kMessageMaxLength applies to the entire message: the 4-byte
  // length field and the content.
  if (message_size > SerializationUtils::kMessageMaxLength) {
    DLOG(ERROR) << "message too long : " << message_size;
    if (HANDLE_EINTR(lseek(fd, message_size - 4, SEEK_CUR)) == -1) {
      DLOG(ERROR) << "error while skipping message. abort";
      return false;
    }
    // Badly formatted message was skipped. Treat the badly formatted sample as
    // an empty sample.
    message->clear();
    return true;
  }

  if (message_size < message_hdr_size) {
    DLOG(ERROR) << "message too short : " << message_size;
    return false;
  }

  message_size -= message_hdr_size;  // The message size includes itself.
  char buffer[SerializationUtils::kMessageMaxLength];
  if (!base::ReadFromFD(fd, buffer, message_size)) {
    DPLOG(ERROR) << "reading metrics message body";
    return false;
  }
  *message = std::string(buffer, message_size);
  return true;
}

}  // namespace

scoped_ptr<MetricSample> SerializationUtils::ParseSample(
    const std::string& sample) {
  if (sample.empty())
    return scoped_ptr<MetricSample>();

  std::vector<std::string> parts;
  base::SplitString(sample, '\0', &parts);
  // We should have two null terminated strings so split should produce
  // three chunks.
  if (parts.size() != 3) {
    DLOG(ERROR) << "splitting message on \\0 produced " << parts.size()
                << " parts (expected 3)";
    return scoped_ptr<MetricSample>();
  }
  const std::string& name = parts[0];
  const std::string& value = parts[1];

  if (base::LowerCaseEqualsASCII(name, "crash")) {
    return MetricSample::CrashSample(value);
  } else if (base::LowerCaseEqualsASCII(name, "histogram")) {
    return MetricSample::ParseHistogram(value);
  } else if (base::LowerCaseEqualsASCII(name, "linearhistogram")) {
    return MetricSample::ParseLinearHistogram(value);
  } else if (base::LowerCaseEqualsASCII(name, "sparsehistogram")) {
    return MetricSample::ParseSparseHistogram(value);
  } else if (base::LowerCaseEqualsASCII(name, "useraction")) {
    return MetricSample::UserActionSample(value);
  } else {
    DLOG(ERROR) << "invalid event type: " << name << ", value: " << value;
  }
  return scoped_ptr<MetricSample>();
}

void SerializationUtils::ReadAndTruncateMetricsFromFile(
    const std::string& filename,
    ScopedVector<MetricSample>* metrics) {
  struct stat stat_buf;
  int result;

  result = stat(filename.c_str(), &stat_buf);
  if (result < 0) {
    if (errno != ENOENT)
      DPLOG(ERROR) << filename << ": bad metrics file stat";

    // Nothing to collect---try later.
    return;
  }
  if (stat_buf.st_size == 0) {
    // Also nothing to collect.
    return;
  }
  base::ScopedFD fd(open(filename.c_str(), O_RDWR));
  if (fd.get() < 0) {
    DPLOG(ERROR) << filename << ": cannot open";
    return;
  }
  result = flock(fd.get(), LOCK_EX);
  if (result < 0) {
    DPLOG(ERROR) << filename << ": cannot lock";
    return;
  }

  // This processes all messages in the log. When all messages are
  // read and processed, or an error occurs, truncate the file to zero size.
  for (;;) {
    std::string message;

    if (!ReadMessage(fd.get(), &message))
      break;

    scoped_ptr<MetricSample> sample = ParseSample(message);
    if (sample)
      metrics->push_back(sample.release());
  }

  result = ftruncate(fd.get(), 0);
  if (result < 0)
    DPLOG(ERROR) << "truncate metrics log";

  result = flock(fd.get(), LOCK_UN);
  if (result < 0)
    DPLOG(ERROR) << "unlock metrics log";
}

bool SerializationUtils::WriteMetricToFile(const MetricSample& sample,
                                           const std::string& filename) {
  if (!sample.IsValid())
    return false;

  base::ScopedFD file_descriptor(open(filename.c_str(),
                                      O_WRONLY | O_APPEND | O_CREAT,
                                      READ_WRITE_ALL_FILE_FLAGS));

  if (file_descriptor.get() < 0) {
    DPLOG(ERROR) << filename << ": cannot open";
    return false;
  }

  fchmod(file_descriptor.get(), READ_WRITE_ALL_FILE_FLAGS);
  // Grab a lock to avoid chrome truncating the file
  // underneath us. Keep the file locked as briefly as possible.
  // Freeing file_descriptor will close the file and and remove the lock.
  if (HANDLE_EINTR(flock(file_descriptor.get(), LOCK_EX)) < 0) {
    DPLOG(ERROR) << filename << ": cannot lock";
    return false;
  }

  std::string msg = sample.ToString();
  int32 size = msg.length() + sizeof(int32);
  if (size > kMessageMaxLength) {
    DLOG(ERROR) << "cannot write message: too long";
    return false;
  }

  // The file containing the metrics samples will only be read by programs on
  // the same device so we do not check endianness.
  if (!base::WriteFileDescriptor(file_descriptor.get(),
                                 reinterpret_cast<char*>(&size),
                                 sizeof(size))) {
    DPLOG(ERROR) << "error writing message length";
    return false;
  }

  if (!base::WriteFileDescriptor(
          file_descriptor.get(), msg.c_str(), msg.size())) {
    DPLOG(ERROR) << "error writing message";
    return false;
  }

  return true;
}

}  // namespace metrics
