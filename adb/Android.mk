# Copyright 2005 The Android Open Source Project
#
# Android.mk for adb
#

LOCAL_PATH:= $(call my-dir)

adb_host_sanitize :=
adb_target_sanitize :=

adb_version := $(shell git -C $(LOCAL_PATH) rev-parse --short=12 HEAD 2>/dev/null)-android

ADB_COMMON_CFLAGS := \
    -Wall -Wextra -Werror \
    -Wno-unused-parameter \
    -Wno-missing-field-initializers \
    -DADB_REVISION='"$(adb_version)"' \

# Define windows.h and tchar.h Unicode preprocessor symbols so that
# CreateFile(), _tfopen(), etc. map to versions that take wchar_t*, breaking the
# build if you accidentally pass char*. Fix by calling like:
# CreateFileW(widen(utf8).c_str()).
ADB_COMMON_windows_CFLAGS := \
    -DUNICODE=1 -D_UNICODE=1 \

# libadb
# =========================================================

# Much of adb is duplicated in bootable/recovery/minadb and fastboot. Changes
# made to adb rarely get ported to the other two, so the trees have diverged a
# bit. We'd like to stop this because it is a maintenance nightmare, but the
# divergence makes this difficult to do all at once. For now, we will start
# small by moving common files into a static library. Hopefully some day we can
# get enough of adb in here that we no longer need minadb. https://b/17626262
LIBADB_SRC_FILES := \
    adb.cpp \
    adb_auth.cpp \
    adb_io.cpp \
    adb_listeners.cpp \
    adb_utils.cpp \
    sockets.cpp \
    transport.cpp \
    transport_local.cpp \
    transport_usb.cpp \

LIBADB_TEST_SRCS := \
    adb_io_test.cpp \
    adb_utils_test.cpp \
    transport_test.cpp \

LIBADB_CFLAGS := \
    $(ADB_COMMON_CFLAGS) \
    -fvisibility=hidden \

LIBADB_linux_CFLAGS := \
    -std=c++14 \

LIBADB_windows_CFLAGS := \
    $(ADB_COMMON_windows_CFLAGS) \

LIBADB_darwin_SRC_FILES := \
    fdevent.cpp \
    get_my_path_darwin.cpp \
    usb_osx.cpp \

LIBADB_linux_SRC_FILES := \
    fdevent.cpp \
    get_my_path_linux.cpp \
    usb_linux.cpp \

LIBADB_windows_SRC_FILES := \
    sysdeps_win32.cpp \
    usb_windows.cpp \

LIBADB_TEST_linux_SRCS := \
    fdevent_test.cpp \

LIBADB_TEST_darwin_SRCS := \
    fdevent_test.cpp \

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := libadbd
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=0
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    adb_auth_client.cpp \
    fdevent.cpp \
    jdwp_service.cpp \
    usb_linux_client.cpp \

LOCAL_SANITIZE := $(adb_target_sanitize)

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libbase

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libadb
LOCAL_MODULE_HOST_OS := darwin linux windows
LOCAL_CFLAGS := $(LIBADB_CFLAGS) -DADB_HOST=1
LOCAL_CFLAGS_windows := $(LIBADB_windows_CFLAGS)
LOCAL_CFLAGS_linux := $(LIBADB_linux_CFLAGS)
LOCAL_SRC_FILES := \
    $(LIBADB_SRC_FILES) \
    adb_auth_host.cpp \

LOCAL_SRC_FILES_darwin := $(LIBADB_darwin_SRC_FILES)
LOCAL_SRC_FILES_linux := $(LIBADB_linux_SRC_FILES)
LOCAL_SRC_FILES_windows := $(LIBADB_windows_SRC_FILES)

LOCAL_SANITIZE := $(adb_host_sanitize)

# Even though we're building a static library (and thus there's no link step for
# this to take effect), this adds the includes to our path.
LOCAL_STATIC_LIBRARIES := libcrypto_static libbase

LOCAL_C_INCLUDES_windows := development/host/windows/usb/api/
ifneq ($(HOST_OS),windows)
    LOCAL_MULTILIB := 64
endif

include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CLANG := true
LOCAL_MODULE := adbd_test
LOCAL_CFLAGS := -DADB_HOST=0 $(LIBADB_CFLAGS)
LOCAL_SRC_FILES := \
    $(LIBADB_TEST_SRCS) \
    $(LIBADB_TEST_linux_SRCS) \

LOCAL_SANITIZE := $(adb_target_sanitize)
LOCAL_STATIC_LIBRARIES := libadbd
LOCAL_SHARED_LIBRARIES := libbase libcutils
include $(BUILD_NATIVE_TEST)

# adb_test
# =========================================================

include $(CLEAR_VARS)
LOCAL_MODULE := adb_test
LOCAL_CFLAGS := -DADB_HOST=1 $(LIBADB_CFLAGS)
LOCAL_CFLAGS_windows := $(LIBADB_windows_CFLAGS)
LOCAL_CFLAGS_linux := $(LIBADB_linux_CFLAGS)
LOCAL_SRC_FILES := $(LIBADB_TEST_SRCS) services.cpp
LOCAL_SRC_FILES_linux := $(LIBADB_TEST_linux_SRCS)
LOCAL_SRC_FILES_darwin := $(LIBADB_TEST_darwin_SRCS)
LOCAL_SANITIZE := $(adb_host_sanitize)
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_STATIC_LIBRARIES := \
    libadb \
    libcrypto_static \
    libcutils \

LOCAL_LDLIBS_linux := -lrt -ldl -lpthread
LOCAL_LDLIBS_darwin := -framework CoreFoundation -framework IOKit
LOCAL_LDLIBS_windows := -lws2_32 -luserenv
LOCAL_STATIC_LIBRARIES_windows := AdbWinApi

include $(BUILD_HOST_NATIVE_TEST)

# adb device tracker (used by ddms) test tool
# =========================================================

ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_MODULE := adb_device_tracker_test
LOCAL_CFLAGS := -DADB_HOST=1 $(LIBADB_CFLAGS)
LOCAL_CFLAGS_windows := $(LIBADB_windows_CFLAGS)
LOCAL_CFLAGS_linux := $(LIBADB_linux_CFLAGS)
LOCAL_SRC_FILES := test_track_devices.cpp
LOCAL_SANITIZE := $(adb_host_sanitize)
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_STATIC_LIBRARIES := libadb libcrypto_static libcutils
LOCAL_LDLIBS += -lrt -ldl -lpthread
include $(BUILD_HOST_EXECUTABLE)
endif

# adb host tool
# =========================================================
include $(CLEAR_VARS)

LOCAL_LDLIBS_linux := -lrt -ldl -lpthread

LOCAL_LDLIBS_darwin := -lpthread -framework CoreFoundation -framework IOKit -framework Carbon
LOCAL_CFLAGS_darwin := -Wno-sizeof-pointer-memaccess -Wno-unused-parameter

# Use wmain instead of main
LOCAL_LDFLAGS_windows := -municode
LOCAL_LDLIBS_windows := -lws2_32 -lgdi32
LOCAL_STATIC_LIBRARIES_windows := AdbWinApi
LOCAL_REQUIRED_MODULES_windows := AdbWinApi AdbWinUsbApi

LOCAL_SRC_FILES := \
    client/main.cpp \
    console.cpp \
    commandline.cpp \
    adb_client.cpp \
    services.cpp \
    file_sync_client.cpp \

LOCAL_CFLAGS += \
    $(ADB_COMMON_CFLAGS) \
    -D_GNU_SOURCE \
    -DADB_HOST=1 \

LOCAL_CFLAGS_windows := \
    $(ADB_COMMON_windows_CFLAGS)

LOCAL_MODULE := adb
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_HOST_OS := darwin linux windows

LOCAL_SANITIZE := $(adb_host_sanitize)
LOCAL_STATIC_LIBRARIES := \
    libadb \
    libbase \
    libcrypto_static \
    libcutils \
    liblog \

LOCAL_CXX_STL := libc++_static

# Don't add anything here, we don't want additional shared dependencies
# on the host adb tool, and shared libraries that link against libc++
# will violate ODR
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_HOST_EXECUTABLE)

$(call dist-for-goals,dist_files sdk,$(LOCAL_BUILT_MODULE))


# adbd device daemon
# =========================================================

include $(CLEAR_VARS)

LOCAL_CLANG := true

LOCAL_SRC_FILES := \
    daemon/main.cpp \
    services.cpp \
    file_sync_service.cpp \
    framebuffer_service.cpp \
    remount_service.cpp \
    set_verity_enable_state_service.cpp \
    shell_service.cpp \

LOCAL_CFLAGS := \
    $(ADB_COMMON_CFLAGS) \
    -DADB_HOST=0 \
    -D_GNU_SOURCE \
    -Wno-deprecated-declarations \

LOCAL_CFLAGS += -DALLOW_ADBD_NO_AUTH=$(if $(filter userdebug eng,$(TARGET_BUILD_VARIANT)),1,0)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DALLOW_ADBD_DISABLE_VERITY=1
LOCAL_CFLAGS += -DALLOW_ADBD_ROOT=1
endif

LOCAL_MODULE := adbd

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)
LOCAL_C_INCLUDES += system/extras/ext4_utils

LOCAL_SANITIZE := $(adb_target_sanitize)
LOCAL_STATIC_LIBRARIES := \
    libadbd \
    libbase \
    libfs_mgr \
    liblog \
    libmincrypt \
    libselinux \
    libext4_utils_static \
    libcutils \
    libbase \

include $(BUILD_EXECUTABLE)
