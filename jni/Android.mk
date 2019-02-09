LOCAL_PATH := $(call my-dir)

# 清除变量
include $(CLEAR_VARS)

# 链接的库
LOCAL_LDLIBS += -llog -lutils -lbinder -landroid_runtime -lcutils

# 编译后生成的模块的名称
LOCAL_MODULE    := hook

# 参与编译的源码文件
LOCAL_SRC_FILES := f:/android/Libhook/jni/ioctlhook.c

# 编译生成共享库
include $(BUILD_SHARED_LIBRARY)