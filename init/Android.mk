# Copyright 2005 The Android Open Source Project

LOCAL_PATH:= $(call my-dir)

# --

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_PERMISSIVE_SELINUX=1
init_options += -DINIT_ENG_BUILD
else
ifeq ($(strip $(MTK_BUILD_ROOT)),yes)
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=1 -DALLOW_PERMISSIVE_SELINUX=1 -DBOOT_TRACE
else
init_options += -DALLOW_LOCAL_PROP_OVERRIDE=0 -DALLOW_PERMISSIVE_SELINUX=0
endif
endif

# add for mtk init
init_options += -DMTK_INIT
# end

#add by yangchao for single sim &dual sim,start
ifeq ($(strip $(LCT_SIM_SINGLE_CHECK_SUPPORT)),yes)
init_options += -DLCT_SIM_SINGLE_CHECK
endif
#add by yangchao for single sim &dual sim,end

init_options += -DPRODUCT_DEVICE=$(TARGET_PRODUCT)


ifeq ($(strip $(MTK_NAND_UBIFS_SUPPORT)),yes)
init_options += -DMTK_UBIFS_SUPPORT
endif

ifeq ($(strip $(MTK_NAND_MTK_FTL_SUPPORT)),yes)
init_options += -DMTK_FTL_SUPPORT
endif

# add for BoardVersion --sunsiyuan@wind-mobi.com 20170301 begin
ifeq ($(strip $(WIND_DEF_BOARD_VERSION)),yes)
init_options += -DWIND_DEF_BOARD_VERSION
endif
# add for BoardVersion --sunsiyuan@wind-mobi.com 20170301 end

init_options += -DLOG_UEVENTS=0

# IKVOICE-4341 - Extend firmware loading folder list if XMCS codec is used for AOV
ifeq ($(BOARD_HAS_AUDIO_DSP_XMCS),true)
init_options    += -DMOTO_AOV_WITH_XMCS
endif

init_cflags += \
    $(init_options) \
    -Wall -Wextra \
    -Wno-unused-parameter \
    -Werror \

# --

# If building on Linux, then build unit test for the host.
ifeq ($(HOST_OS),linux)
include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    parser/tokenizer.cpp \

LOCAL_MODULE := libinit_parser
LOCAL_CLANG := true
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := init_parser_tests
LOCAL_SRC_FILES := \
    parser/tokenizer_test.cpp \

LOCAL_STATIC_LIBRARIES := libinit_parser
LOCAL_CLANG := true
include $(BUILD_HOST_NATIVE_TEST)
endif

include $(CLEAR_VARS)
LOCAL_CPPFLAGS := $(init_cflags)
LOCAL_SRC_FILES:= \
    action.cpp \
    import_parser.cpp \
    init_parser.cpp \
    log.cpp \
    parser.cpp \
    service.cpp \
    util.cpp \

LOCAL_STATIC_LIBRARIES := libbase libselinux
LOCAL_MODULE := libinit
LOCAL_SANITIZE := integer
LOCAL_CLANG := true
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

LOCAL_MODULE:= init
LOCAL_C_INCLUDES += \
    system/extras/ext4_utils \
    system/core/mkbootimg

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)

LOCAL_STATIC_LIBRARIES := \
    libinit \
    libbootloader_message \
    libfs_mgr \
    libfec \
    libfec_rs \
    libsquashfs_utils \
    liblogwrap \
    libcutils \
    libext4_utils_static \
    libbase \
    libutils \
    libc \
    libselinux \
    liblog \
    libmincrypt \
    libcrypto_static \
    libc++_static \
    libdl \
    libsparse_static \
    libz

# Create symlinks
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT)/sbin; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/ueventd; \
    ln -sf ../init $(TARGET_ROOT_OUT)/sbin/watchdogd

ifneq ($(strip $(TARGET_PLATFORM_DEVICE_BASE)),)
LOCAL_CFLAGS += -D_PLATFORM_BASE="\"$(TARGET_PLATFORM_DEVICE_BASE)\""
endif

LOCAL_SANITIZE := integer
LOCAL_CLANG := true
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
LOCAL_SANITIZE := integer
LOCAL_CLANG := true
include $(BUILD_NATIVE_TEST)
