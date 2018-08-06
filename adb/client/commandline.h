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

#ifndef COMMANDLINE_H
#define COMMANDLINE_H

#include "adb.h"

// Callback used to handle the standard streams (stdout and stderr) sent by the
// device's upon receiving a command.
//
class StandardStreamsCallbackInterface {
  public:
    StandardStreamsCallbackInterface() {
    }
    // Handles the stdout output from devices supporting the Shell protocol.
    virtual void OnStdout(const char* buffer, int length) = 0;

    // Handles the stderr output from devices supporting the Shell protocol.
    virtual void OnStderr(const char* buffer, int length) = 0;

    // Indicates the communication is finished and returns the appropriate error
    // code.
    //
    // |status| has the status code returning by the underlying communication
    // channels
    virtual int Done(int status) = 0;

  protected:
    static void OnStream(std::string* string, FILE* stream, const char* buffer, int length) {
        if (string != nullptr) {
            string->append(buffer, length);
        } else {
            fwrite(buffer, 1, length, stream);
            fflush(stream);
        }
    }

  private:
    DISALLOW_COPY_AND_ASSIGN(StandardStreamsCallbackInterface);
};

// Default implementation that redirects the streams to the equilavent host
// stream or to a string
// passed to the constructor.
class DefaultStandardStreamsCallback : public StandardStreamsCallbackInterface {
  public:
    // If |stdout_str| is non-null, OnStdout will append to it.
    // If |stderr_str| is non-null, OnStderr will append to it.
    DefaultStandardStreamsCallback(std::string* stdout_str, std::string* stderr_str)
        : stdout_str_(stdout_str), stderr_str_(stderr_str) {
    }

    void OnStdout(const char* buffer, int length) {
        OnStream(stdout_str_, stdout, buffer, length);
    }

    void OnStderr(const char* buffer, int length) {
        OnStream(stderr_str_, stderr, buffer, length);
    }

    int Done(int status) {
        return status;
    }

  private:
    std::string* stdout_str_;
    std::string* stderr_str_;

    DISALLOW_COPY_AND_ASSIGN(DefaultStandardStreamsCallback);
};

class SilentStandardStreamsCallbackInterface : public StandardStreamsCallbackInterface {
  public:
    SilentStandardStreamsCallbackInterface() = default;
    void OnStdout(const char*, int) override final {}
    void OnStderr(const char*, int) override final {}
    int Done(int status) override final { return status; }
};

// Singleton.
extern DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK;

int adb_commandline(int argc, const char** argv);

void copy_to_file(int inFd, int outFd);

// Connects to the device "shell" service with |command| and prints the
// resulting output.
// if |callback| is non-null, stdout/stderr output will be handled by it.
int send_shell_command(
        const std::string& command, bool disable_shell_protocol = false,
        StandardStreamsCallbackInterface* callback = &DEFAULT_STANDARD_STREAMS_CALLBACK);

#endif  // COMMANDLINE_H
