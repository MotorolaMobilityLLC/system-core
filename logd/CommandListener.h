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

#ifndef _COMMANDLISTENER_H__
#define _COMMANDLISTENER_H__

#include <sysutils/FrameworkListener.h>
#include "LogCommand.h"
#include "LogBuffer.h"
#include "LogReader.h"
#include "LogListener.h"

class CommandListener : public FrameworkListener {
    LogBuffer &mBuf;

public:
    CommandListener(LogBuffer *buf, LogReader *reader, LogListener *swl);
    virtual ~CommandListener() {}

private:
    class ShutdownCmd : public LogCommand {
        LogBuffer &mBuf;
        LogReader &mReader;
        LogListener &mSwl;

    public:
        ShutdownCmd(LogBuffer *buf, LogReader *reader, LogListener *swl);
        virtual ~ShutdownCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

#define LogBufferCmd(name)                                       \
    class name##Cmd : public LogCommand {                        \
        LogBuffer &mBuf;                                         \
    public:                                                      \
        name##Cmd(LogBuffer *buf);                               \
        virtual ~name##Cmd() {}                                  \
        int runCommand(SocketClient *c, int argc, char ** argv); \
    };

    LogBufferCmd(Clear)
    LogBufferCmd(GetBufSize)
    LogBufferCmd(GetBufSizeUsed)
    LogBufferCmd(GetStatistics)
};

#endif
