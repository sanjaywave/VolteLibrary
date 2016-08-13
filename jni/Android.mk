LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := libVoLTELib
LOCAL_SRC_FILES := src/errors.c src/phone_capture.c src/phone_capture_event_handler.c src/phone_capture_rtp_handler.c 
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libpcap/platform_external_libpcap-master
LOCAL_C_INCLUDES += $(LOCAL_PATH)/inc
LOCAL_STATIC_LIBRARIES := libpcap
LOCAL_LDLIBS := -ldl -llog
LOCAL_CFLAGS = -g -DRTP_LITTLE_ENDIAN -DDEBUG
include $(BUILD_EXECUTABLE)
include $(LOCAL_PATH)/libpcap/platform_external_libpcap-master/Android.mk
