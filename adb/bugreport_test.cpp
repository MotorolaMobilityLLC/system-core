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

#include "bugreport.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::Action;
using ::testing::ActionInterface;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::MakeAction;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::WithArg;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

// Empty function so tests don't need to be linked against file_sync_service.cpp, which requires
// SELinux and its transitive dependencies...
bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  const char* name) {
    ADD_FAILURE() << "do_sync_pull() should have been mocked";
    return false;
}

// Empty functions so tests don't need to be linked against commandline.cpp
DefaultStandardStreamsCallback DEFAULT_STANDARD_STREAMS_CALLBACK(nullptr, nullptr);
int usage() {
    return -42;
}
int send_shell_command(TransportType transport_type, const char* serial, const std::string& command,
                       bool disable_shell_protocol, StandardStreamsCallbackInterface* callback) {
    ADD_FAILURE() << "send_shell_command() should have been mocked";
    return -42;
}

enum StreamType {
    kStreamStdout,
    kStreamStderr,
};

// gmock black magic to provide a WithArg<4>(WriteOnStdout(output)) matcher
typedef void OnStandardStreamsCallbackFunction(StandardStreamsCallbackInterface*);

class OnStandardStreamsCallbackAction : public ActionInterface<OnStandardStreamsCallbackFunction> {
  public:
    explicit OnStandardStreamsCallbackAction(StreamType type, const std::string& output)
        : type_(type), output_(output) {
    }
    virtual Result Perform(const ArgumentTuple& args) {
        if (type_ == kStreamStdout) {
            ::std::tr1::get<0>(args)->OnStdout(output_.c_str(), output_.size());
        }
        if (type_ == kStreamStderr) {
            ::std::tr1::get<0>(args)->OnStderr(output_.c_str(), output_.size());
        }
    }

  private:
    StreamType type_;
    std::string output_;
};

// Matcher used to emulated StandardStreamsCallbackInterface.OnStdout(buffer,
// length)
Action<OnStandardStreamsCallbackFunction> WriteOnStdout(const std::string& output) {
    return MakeAction(new OnStandardStreamsCallbackAction(kStreamStdout, output));
}

// Matcher used to emulated StandardStreamsCallbackInterface.OnStderr(buffer,
// length)
Action<OnStandardStreamsCallbackFunction> WriteOnStderr(const std::string& output) {
    return MakeAction(new OnStandardStreamsCallbackAction(kStreamStderr, output));
}

typedef int CallbackDoneFunction(StandardStreamsCallbackInterface*);

class CallbackDoneAction : public ActionInterface<CallbackDoneFunction> {
  public:
    explicit CallbackDoneAction(int status) : status_(status) {
    }
    virtual Result Perform(const ArgumentTuple& args) {
        int status = ::std::tr1::get<0>(args)->Done(status_);
        return status;
    }

  private:
    int status_;
};

// Matcher used to emulated StandardStreamsCallbackInterface.Done(status)
Action<CallbackDoneFunction> ReturnCallbackDone(int status = -1337) {
    return MakeAction(new CallbackDoneAction(status));
}

class BugreportMock : public Bugreport {
  public:
    MOCK_METHOD5(SendShellCommand,
                 int(TransportType transport_type, const char* serial, const std::string& command,
                     bool disable_shell_protocol, StandardStreamsCallbackInterface* callback));
    MOCK_METHOD4(DoSyncPull, bool(const std::vector<const char*>& srcs, const char* dst,
                                  bool copy_attrs, const char* name));
    MOCK_METHOD3(UpdateProgress, void(const std::string&, int, int));
};

class BugreportTest : public ::testing::Test {
  public:
    void SetBugreportzVersion(const std::string& version) {
        EXPECT_CALL(br_,
                    SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -v", false, _))
            .WillOnce(DoAll(WithArg<4>(WriteOnStderr(version.c_str())),
                            WithArg<4>(ReturnCallbackDone(0))));
    }

    void ExpectProgress(int progress, int total) {
        EXPECT_CALL(br_, UpdateProgress(HasSubstr("file.zip"), progress, total));
    }

    BugreportMock br_;
};

// Tests when called with invalid number of argumnts
TEST_F(BugreportTest, InvalidNumberArgs) {
    const char* args[1024] = {"bugreport", "to", "principal"};
    ASSERT_EQ(-42, br_.DoIt(kTransportLocal, "HannibalLecter", 3, args));
}

// Tests the legacy 'adb bugreport' option
TEST_F(BugreportTest, FlatFileFormat) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreport", false, _))
        .WillOnce(Return(0));

    const char* args[1024] = {"bugreport"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 1, args));
}

// Tests 'adb bugreport file.zip' when it succeeds and device does not support
// progress.
TEST_F(BugreportTest, OkLegacy) {
    SetBugreportzVersion("1.0");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, HasSubstr("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds but response was sent in
// multiple buffer writers and without progress updates.
TEST_F(BugreportTest, OkLegacySplitBuffer) {
    SetBugreportzVersion("1.0");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device")),
                        WithArg<4>(WriteOnStdout("/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, HasSubstr("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when it succeeds and displays progress.
TEST_F(BugreportTest, Ok) {
    SetBugreportzVersion("1.1");
    ExpectProgress(1, 100);
    ExpectProgress(10, 100);
    ExpectProgress(50, 100);
    ExpectProgress(99, 100);
    // clang-format off
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        // NOTE: DoAll accepts at most 10 arguments, and we have reached that limit...
        .WillOnce(DoAll(
            // Progress line in one write
            WithArg<4>(WriteOnStdout("PROGRESS:1/100\n")),
            // Add some bogus lines
            WithArg<4>(WriteOnStdout("\nDUDE:SWEET\n\nBLA\n\nBLA\nBLA\n\n")),
            // Multiple progress lines in one write
            WithArg<4>(WriteOnStdout("PROGRESS:10/100\nPROGRESS:50/100\n")),
            // Progress line in multiple writes
            WithArg<4>(WriteOnStdout("PROG")),
            WithArg<4>(WriteOnStdout("RESS:99")),
            WithArg<4>(WriteOnStdout("/100\n")),
            // Split last message as well, just in case
            WithArg<4>(WriteOnStdout("OK:/device/bugreport")),
            WithArg<4>(WriteOnStdout(".zip")),
            WithArg<4>(ReturnCallbackDone())));
    // clang-format on
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, HasSubstr("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file' when it succeeds
TEST_F(BugreportTest, OkNoExtension) {
    SetBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device/bugreport.zip\n")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, HasSubstr("file.zip")))
        .WillOnce(Return(true));

    const char* args[1024] = {"bugreport", "file"};
    ASSERT_EQ(0, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed
TEST_F(BugreportTest, BugreportzReturnedFail) {
    SetBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        .WillOnce(
            DoAll(WithArg<4>(WriteOnStdout("FAIL:D'OH!\n")), WithArg<4>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH!"));
}

// Tests 'adb bugreport file.zip' when the bugreport itself failed but response
// was sent in
// multiple buffer writes
TEST_F(BugreportTest, BugreportzReturnedFailSplitBuffer) {
    SetBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("FAIL")), WithArg<4>(WriteOnStdout(":D'OH!\n")),
                        WithArg<4>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("D'OH!"));
}

// Tests 'adb bugreport file.zip' when the bugreportz returned an unsupported
// response.
TEST_F(BugreportTest, BugreportzReturnedUnsupported) {
    SetBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("bugreportz? What am I, a zombie?")),
                        WithArg<4>(ReturnCallbackDone())));

    CaptureStderr();
    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
    ASSERT_THAT(GetCapturedStderr(), HasSubstr("bugreportz? What am I, a zombie?"));
}

// Tests 'adb bugreport file.zip' when the bugreportz -v command failed
TEST_F(BugreportTest, BugreportzVersionFailed) {
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -v", false, _))
        .WillOnce(Return(666));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(666, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreportz -v returns status 0 but with no output.
TEST_F(BugreportTest, BugreportzVersionEmpty) {
    SetBugreportzVersion("");

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(-1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the main bugreportz command failed
TEST_F(BugreportTest, BugreportzFailed) {
    SetBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        .WillOnce(Return(666));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(666, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}

// Tests 'adb bugreport file.zip' when the bugreport could not be pulled
TEST_F(BugreportTest, PullFails) {
    SetBugreportzVersion("1.1");
    EXPECT_CALL(br_, SendShellCommand(kTransportLocal, "HannibalLecter", "bugreportz -p", false, _))
        .WillOnce(DoAll(WithArg<4>(WriteOnStdout("OK:/device/bugreport.zip")),
                        WithArg<4>(ReturnCallbackDone())));
    EXPECT_CALL(br_, DoSyncPull(ElementsAre(StrEq("/device/bugreport.zip")), StrEq("file.zip"),
                                true, HasSubstr("file.zip")))
        .WillOnce(Return(false));

    const char* args[1024] = {"bugreport", "file.zip"};
    ASSERT_EQ(1, br_.DoIt(kTransportLocal, "HannibalLecter", 2, args));
}
