TARGET = iphone:clang:latest:5.1
ARCHS = armv7
SYSROOT = $(HOME)/theos/sdks/iPhoneOS5.1.sdk

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = TLS1.3Browser
TLS1.3Browser_FILES = main.m TLS13AppDelegate.m TLS13URLProtocol.m
TLS1.3Browser_FRAMEWORKS = UIKit CoreGraphics
TLS1.3Browser_RESOURCE_FILES = Info.plist appicon-57.png appicon-114.png

TLS1.3Browser_CFLAGS = -I./libs/include -I$(SYSROOT)/usr/include -I.
TLS1.3Browser_LDFLAGS = -L./libs -lmbedtls -lmbedcrypto -lmbedx509

# DYNAMIC STEP: Call our robust helper script to generate the cert header safely
before-all::
	@echo "Generating certificate bundle..."
	@python3 generate_certs.py

include $(THEOS_MAKE_PATH)/application.mk
