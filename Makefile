TARGET = iphone:clang:latest:14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = CardGate
CardGate_FILES = CardGate.m
CardGate_FRAMEWORKS = UIKit Foundation
CardGate_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/library.mk
