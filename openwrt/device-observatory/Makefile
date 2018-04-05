#
# This file is licensed under the CC0-1.0 license.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=device-observatory
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_REV:=c4d79ffbf5053e44be4b64da22b1b7fb6a51daf2

PKG_LICENSE:=GPL-3.0+

#PKG_BUILD_DIR:=$(BUILD_DIR)/device-observatory-$(PKG_VERSION)
#PKG_SOURCE:=v$(PKG_VERSION).tar.gz
#PKG_SOURCE_URL:=https://github.com/mwarning/device-observatory/archive/
#PKG_HASH:=1b3ccaa01cbb7548ef268d8b562059452826dc774529303c494418d1a450ca97

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/mwarning/device-observatory.git
PKG_SOURCE_VERSION:=$(PKG_REV)
#PKG_REV:=c4d79ffbf5053e44be4b64da22b1b7fb6a51daf2
#PKG_MIRROR_HASH:=

PKG_SOURCE_VERSION:=$(PKG_REV)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_REV).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)


include $(INCLUDE_DIR)/package.mk

define Package/device-observatory
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=device-observatory
	MAINTAINER:=Moritz Warning <moritzwarning@web.de>
	DEPENDS:=+libpcap +libmicrohttpd-no-ssl
endef

define Package/device-observatory/description
	The Device Observatory shows information about the devices connected to the WLAN to height security awareness.
endef

#define Build/Prepare
#	mkdir -p $(PKG_BUILD_DIR)
#	$(CP) ./src/* $(PKG_BUILD_DIR)/
#endef

define Package/device-observatory/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/device-observatory.init $(1)/etc/init.d/device-observatory
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/device-observatory $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/share/device-observatory
	$(INSTALL_DATA) ./files/macdb.txt $(1)/usr/share/device-observatory/macdb.txt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) files/device-observatory.config $(1)/etc/config/device-observatory
endef

$(eval $(call BuildPackage,device-observatory))
