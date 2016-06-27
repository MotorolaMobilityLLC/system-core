# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_DISABLE_SELINUX=1
init_options += -DINIT_ENG_BUILD
else
ifeq ($(strip $(MTK_BUILD_ROOT)),yes)
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_DISABLE_SELINUX=1 -DBOOT_TRACE
else
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=0 -DALLOW_DISABLE_SELINUX=0
endif
endif

# add mtk fstab flags support
init_options += -DMTK_FSTAB_FLAGS
# end

# add for mtk init
ifneq ($(BUILD_MTK_LDVT), yes)
init_options += -DMTK_INIT
endif
# end

ifeq ($(strip $(MTK_NAND_UBIFS_SUPPORT)),yes)
init_options += -DMTK_UBIFS_SUPPORT
endif

init_options += -DLOG_UEVENTS=0

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \

init_clang := true

# --

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    init_parser.cpp \
    log.cpp \
    parser.cpp \
    util.cpp \


LOCAL_STATIC_LIBRARIES := libbase
LOCAL_MODULE := libinit
LOCAL_CLANG := $(init_clang)
ifeq ($(LENOVO_EASYIMAGE_ON),yes)
LOCAL_CFLAGS    += -DLENOVO_EASYIMAGE_SUPPORT
endif
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    bootchart.cpp \
    builtins.cpp \
    devices.cpp \
    init.cpp \
    keychords.cpp \
    property_service.cpp \
    signal_handler.cpp \
    ueventd.cpp \
    ueventd_parser.cpp \
    watchdogd.cpp \

ifeq ($(strip $(MTK_NAND_UBIFS_SUPPORT)),yes)
LOCAL_CFLAGS += -DMTK_UBIFS_SUPPORT
endif

LOCAL_MODULE:= init
LOCAL_C_INCLUDES += \
    system/extras/ext4_utils \
    system/core/mkbootimg

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libfs_mgr \
    libsquashfs_utils \
    liblogwrap \
    libbase \
    libext4_utils_static \
    libcutils \
    libutils \
    liblog \
    libc \
    libselinux \
    libmincrypt \
    libc++_static \
    libdl \
    libsparse_static \
    libz

# Create symlinks
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

LOCAL_CLANG := $(init_clang)

ifeq ($(LENOVO_EASYIMAGE_ON),yes)
LOCAL_CFLAGS    += -DLENOVO_EASYIMAGE_SUPPORT
endif

include $(BUILD_EXECUTABLE)




include $(CLEAR_VARS)
LOCAL_MODULE := init_tests
LOCAL_SRC_FILES := \
    init_parser_test.cpp \
    util_test.cpp \

LOCAL_SHARED_LIBRARIES += \
    libcutils \
    libbase \

LOCAL_STATIC_LIBRARIES := libinit
LOCAL_CLANG := $(init_clang)


ifeq ($(LENOVO_EASYIMAGE_ON),yes)
LOCAL_CFLAGS    += -DLENOVO_EASYIMAGE_SUPPORT
endif

include $(BUILD_NATIVE_TEST)
