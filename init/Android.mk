# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# --

ifeq ($(strip $(INIT_BOOTCHART)),true)
LOCAL_CPPFLAGS  += -DBOOTCHART=1
else
LOCAL_CPPFLAGS  += -DBOOTCHART=0
endif

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CPPFLAGS += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_DISABLE_SELINUX=1
else
LOCAL_CPPFLAGS += -DALLOW_LOCAL_PROP_OVERRIDE=0 -DALLOW_DISABLE_SELINUX=0
endif

LOCAL_CPPFLAGS += -DLOG_UEVENTS=0

# --

LOCAL_SRC_FILES:= \
    bootchart.cpp \
    builtins.cpp \
    devices.cpp \
    init.cpp \
    init_parser.cpp \
    keychords.cpp \
    parser.cpp \
    property_service.cpp \
    signal_handler.cpp \
    ueventd.cpp \
    ueventd_parser.cpp \
    util.cpp \
    watchdogd.cpp \

#LOCAL_CLANG := true

LOCAL_CPPFLAGS += \
    -Wall -Wextra \
    -Werror -Wno-error=deprecated-declarations \
    -Wno-unused-parameter \

LOCAL_MODULE:= init

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
	libfs_mgr \
	liblogwrap \
	libcutils \
	liblog \
	libc \
	libselinux \
	libmincrypt \
	libext4_utils_static

# Create symlinks
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

include $(BUILD_EXECUTABLE)
