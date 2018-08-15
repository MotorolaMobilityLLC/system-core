LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= logd

LOCAL_INIT_RC := logd.rc

LOCAL_SRC_FILES := \
    main.cpp \
    LogMuchControl.cpp \
    LogCommand.cpp \
    CommandListener.cpp \
    LogListener.cpp \
    LogReader.cpp \
    FlushCommand.cpp \
    LogBuffer.cpp \
    LogBufferElement.cpp \
    LogBufferInterface.cpp \
    LogTimes.cpp \
    LogStatistics.cpp \
    LogWhiteBlackList.cpp \
    libaudit.c \
    LogAudit.cpp \
    LogKlog.cpp \
    LogTags.cpp \
    event.logtags

LOCAL_SHARED_LIBRARIES := \
    libsysutils \
    liblog \
    libcutils \
    libbase \
    libpackagelistparser \
    libcap

# This is what we want to do:
#  event_logtags = $(shell \
#    sed -n \
#        "s/^\([0-9]*\)[ \t]*$1[ \t].*/-D`echo $1 | tr a-z A-Z`_LOG_TAG=\1/p" \
#        $(LOCAL_PATH)/$2/event.logtags)
#  event_flag := $(call event_logtags,auditd)
#  event_flag += $(call event_logtags,logd)
#  event_flag += $(call event_logtags,tag_def)
# so make sure we do not regret hard-coding it as follows:
event_flag := -DAUDITD_LOG_TAG=1003 -DCHATTY_LOG_TAG=1004 -DTAG_DEF_LOG_TAG=1005
event_flag += -DLIBLOG_LOG_TAG=1006

LOCAL_CFLAGS := -Werror $(event_flag)

ifneq ($(MTK_LOGD_ENHANCE_DISABLE),yes)
LOCAL_CFLAGS += -DMTK_LOGD_ENHANCE

ifneq ($(MTK_LOGDW_SOCK_BLOCK_DISABLE),yes)
LOCAL_CFLAGS += -DMTK_LOGDW_SOCK_BLOCK
endif

ifneq ($(MTK_KLOG_PREFIX_DISABLE),yes)
LOCAL_CFLAGS += -DMTK_KLOG_PREFIX
endif

ifneq ($(MTK_LOGD_FILTER_DISABLE),yes)
LOCAL_CFLAGS += -DMTK_LOGD_FILTER
endif

ifeq ($(HAVE_AEE_FEATURE), yes)
    LOCAL_SHARED_LIBRARIES += libaed
    LOCAL_CFLAGS += -DHAVE_AEE_FEATURE
    LOCAL_C_INCLUDES += $(MTK_ROOT)/external/aee/binary/inc
endif

ifneq ($(wildcard vendor/mediatek/internal/mtklog_enable),)
ifneq ($(MTK_ANDROID_LOG_MUCH_COUNT), )
ifeq ($(TARGET_BUILD_VARIANT),eng)
    LOCAL_CFLAGS += -DANDROID_LOG_MUCH_COUNT=$(MTK_ANDROID_LOG_MUCH_COUNT)
else
    LOCAL_CFLAGS += -DANDROID_LOG_MUCH_COUNT=500
endif
    LOCAL_INIT_RC := logd_e.rc
endif
endif

ifneq (,$(filter eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DLOGD_MEM_CONTROL
endif

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DCONFIG_MT_DEBUG_BUILD
LOCAL_CFLAGS += -DLOGD_FORCE_DIRECTCOREDUMP
endif

endif

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := logtagd.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/init

include $(BUILD_PREBUILT)

include $(call first-makefiles-under,$(LOCAL_PATH))
