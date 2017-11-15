LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        dhcpclient.c \
        dhcpmsg.c \
        ifc_utils.c \
        dhcp_utils.c \
        packet.c \
		pppoe_utils.c

LOCAL_SHARED_LIBRARIES := \
        libcutils \
        liblog

LOCAL_MODULE := libnetutils

# workaround: disable it to avoid build fail. MUST enable it again
#LOCAL_CFLAGS := -Werror

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := dhcptool.c
LOCAL_SHARED_LIBRARIES := libnetutils
LOCAL_MODULE := dhcptool
LOCAL_MODULE_TAGS := debug
include $(BUILD_EXECUTABLE)
