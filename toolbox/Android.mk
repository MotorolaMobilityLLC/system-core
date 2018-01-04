LOCAL_PATH:= $(call my-dir)

common_cflags := \
    -Werror -Wno-unused-parameter -Wno-unused-const-variable \
    -include bsd-compatibility.h \

include $(CLEAR_VARS)

BSD_TOOLS := \
    dd \

OUR_TOOLS := \
    getevent \
    newfs_msdos \

ALL_TOOLS = $(BSD_TOOLS) $(OUR_TOOLS)
# Motorola - BEGIN - IKAPP-606 - wqnt78 - 3/10/2010 - apython enabler

# Note: sendevent2 is in toolbox instead of motobox to avoid GPL issues

TOOLS += sendevent2

# Motorola - END - IKAPP-606 - wqnt78 - 3/10/2010 - apython enabler


# Motorola, rknize2, 2013-Apr-16, IKJBXLINE-3829
TOOLS += setfattr

LOCAL_SRC_FILES := \
    toolbox.c \
    $(patsubst %,%.c,$(OUR_TOOLS)) \

LOCAL_CFLAGS += $(common_cflags)
LOCAL_C_INCLUDES += $(LOCAL_PATH)/upstream-netbsd/include/

LOCAL_SHARED_LIBRARIES := \
    libcutils \

LOCAL_WHOLE_STATIC_LIBRARIES := $(patsubst %,libtoolbox_%,$(BSD_TOOLS))

LOCAL_MODULE := toolbox

# Install the symlinks.
LOCAL_POST_INSTALL_CMD := $(hide) $(foreach t,$(ALL_TOOLS),ln -sf toolbox $(TARGET_OUT)/bin/$(t);)

# Including this will define $(intermediates).
#
include $(BUILD_EXECUTABLE)

$(LOCAL_PATH)/toolbox.c: $(intermediates)/tools.h

TOOLS_H := $(intermediates)/tools.h
$(TOOLS_H): PRIVATE_TOOLS := toolbox $(ALL_TOOLS)
$(TOOLS_H): PRIVATE_CUSTOM_TOOL = echo "/* file generated automatically */" > $@ ; for t in $(PRIVATE_TOOLS) ; do echo "TOOL($$t)" >> $@ ; done
$(TOOLS_H): $(LOCAL_PATH)/Android.mk
$(TOOLS_H):
	$(transform-generated-source)

$(LOCAL_PATH)/getevent.c: $(intermediates)/input.h-labels.h

UAPI_INPUT_EVENT_CODES_H := bionic/libc/kernel/uapi/linux/input.h bionic/libc/kernel/uapi/linux/input-event-codes.h
INPUT_H_LABELS_H := $(intermediates)/input.h-labels.h
$(INPUT_H_LABELS_H): PRIVATE_LOCAL_PATH := $(LOCAL_PATH)
# The PRIVATE_CUSTOM_TOOL line uses = to evaluate the output path late.
# We copy the input path so it can't be accidentally modified later.
$(INPUT_H_LABELS_H): PRIVATE_UAPI_INPUT_EVENT_CODES_H := $(UAPI_INPUT_EVENT_CODES_H)
$(INPUT_H_LABELS_H): PRIVATE_CUSTOM_TOOL = $(PRIVATE_LOCAL_PATH)/generate-input.h-labels.py $(PRIVATE_UAPI_INPUT_EVENT_CODES_H) > $@
# The dependency line though gets evaluated now, so the PRIVATE_ copy doesn't exist yet,
# and the original can't yet have been modified, so this is both sufficient and necessary.
$(INPUT_H_LABELS_H): $(LOCAL_PATH)/Android.mk $(LOCAL_PATH)/generate-input.h-labels.py $(UAPI_INPUT_EVENT_CODES_H)
$(INPUT_H_LABELS_H):
	$(transform-generated-source)
