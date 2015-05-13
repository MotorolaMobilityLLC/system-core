/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef _LOGD_LOG_KLOG_H__
#define _LOGD_LOG_KLOG_H__

#include <sysutils/SocketListener.h>
#include <log/log_read.h>
#include "LogReader.h"

class LogKlog : public SocketListener {
    LogBuffer *logbuf;
    LogReader *reader;
    const log_time signature;
    const int fdWrite; // /dev/kmsg
    const int fdRead;  // /proc/kmsg
    // Set once thread is started, separates KLOG_ACTION_READ_ALL
    // and KLOG_ACTION_READ phases.
    bool initialized;
    // Used during each of the above phases to control logging.
    bool enableLogging;
    // set if we are also running auditd, to filter out audit reports from
    // our copy of the kernel log
    bool auditd;

    static log_time correction;

public:
    LogKlog(LogBuffer *buf, LogReader *reader, int fdWrite, int fdRead, bool auditd);
    int log(const char *buf);
    void synchronize(const char *buf);

    static void convertMonotonicToReal(log_time &real) { real += correction; }

protected:
    void sniffTime(log_time &now, const char **buf, bool reverse);
    void calculateCorrection(const log_time &monotonic, const char *real_string);
    virtual bool onDataAvailable(SocketClient *cli);

};

#endif
