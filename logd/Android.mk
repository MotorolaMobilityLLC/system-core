LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE:= logd

LOCAL_INIT_RC := logd.rc

LOCAL_SRC_FILES := \
    main.cpp \
    LogCommand.cpp \
    CommandListener.cpp \
    LogListener.cpp \
    LogReader.cpp \
    FlushCommand.cpp \
    LogBuffer.cpp \
    LogBufferElement.cpp \
    LogTimes.cpp \
    LogStatistics.cpp \
    LogWhiteBlackList.cpp \
    libaudit.c \
    LogAudit.cpp \
    LogKlog.cpp \
    event.logtags

LOCAL_SHARED_LIBRARIES := \
    libsysutils \
    liblog \
    libcutils \
    libbase \
    libpackagelistparser

# This is what we want to do:
#  event_logtags = $(shell \
#    sed -n \
#        "s/^\([0-9]*\)[ \t]*$1[ \t].*/-D`echo $1 | tr a-z A-Z`_LOG_TAG=\1/p" \
#        $(LOCAL_PATH)/$2/event.logtags)
#  event_flag := $(call event_logtags,auditd)
#  event_flag += $(call event_logtags,logd)
# so make sure we do not regret hard-coding it as follows:
event_flag := -DAUDITD_LOG_TAG=1003 -DLOGD_LOG_TAG=1004

LOCAL_CFLAGS := -Werror $(event_flag)

ifeq ($(HAVE_AEE_FEATURE), yes)
    LOCAL_SHARED_LIBRARIES += libaed
    LOCAL_CFLAGS += -DHAVE_AEE_FEATURE
    LOCAL_C_INCLUDES += $(MTK_ROOT)/external/aee/binary/inc
endif

ifeq ($(MTK_INTERNAL),yes)
ifneq ($(ANDROID_LOG_MUCH_COUNT), )
ifeq ($(TARGET_BUILD_VARIANT),eng)
    LOCAL_CFLAGS += -DANDROID_LOG_MUCH_COUNT=$(ANDROID_LOG_MUCH_COUNT)
else
    LOCAL_CFLAGS += -DANDROID_LOG_MUCH_COUNT=1000
endif
    LOCAL_INIT_RC := logd_e.rc
endif
endif

LOCAL_CFLAGS += -DMTK_LOGD_FILTER

ifeq ($(TARGET_BUILD_VARIANT),eng)
LOCAL_CFLAGS += -DMTK_LOGD_DEBUG
endif


include $(BUILD_EXECUTABLE)

include $(call first-makefiles-under,$(LOCAL_PATH))
