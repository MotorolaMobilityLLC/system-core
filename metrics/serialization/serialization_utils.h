// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_SERIALIZATION_SERIALIZATION_UTILS_H_
#define METRICS_SERIALIZATION_SERIALIZATION_UTILS_H_

#include <string>

#include "base/memory/scoped_ptr.h"
#include "base/memory/scoped_vector.h"

namespace metrics {

class MetricSample;

// Metrics helpers to serialize and deserialize metrics collected by
// ChromeOS.
namespace SerializationUtils {

// Deserializes a sample passed as a string and return a sample.
// The return value will either be a scoped_ptr to a Metric sample (if the
// deserialization was successful) or a NULL scoped_ptr.
scoped_ptr<MetricSample> ParseSample(const std::string& sample);

// Reads all samples from a file and truncate the file when done.
void ReadAndTruncateMetricsFromFile(const std::string& filename,
                                    ScopedVector<MetricSample>* metrics);

// Serializes a sample and write it to filename.
// The format for the message is:
//  message_size, serialized_message
// where
//  * message_size is the total length of the message (message_size +
//    serialized_message) on 4 bytes
//  * serialized_message is the serialized version of sample (using ToString)
//
//  NB: the file will never leave the device so message_size will be written
//  with the architecture's endianness.
bool WriteMetricToFile(const MetricSample& sample, const std::string& filename);

// Maximum length of a serialized message
static const int kMessageMaxLength = 1024;

}  // namespace SerializationUtils
}  // namespace metrics

#endif  // METRICS_SERIALIZATION_SERIALIZATION_UTILS_H_
