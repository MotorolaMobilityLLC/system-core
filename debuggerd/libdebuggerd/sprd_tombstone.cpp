/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#define LOG_TAG "DEBUG"

#include "libdebuggerd/utility.h"
#include "libdebuggerd/sprd_tombstone.h"

static int64_t elapsedRealtime()
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int64_t when = seconds_to_nanoseconds(ts.tv_sec) + ts.tv_nsec;
  return (int64_t) nanoseconds_to_milliseconds(when);
}

void dump_elapsedRealtime(log_t *log)
{
  _LOG(log, logtype::HEADER,
       "Native Crash TIME: %lld\n", (long long)elapsedRealtime());
  _LOG(log, logtype::HEADER,
       "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
}

