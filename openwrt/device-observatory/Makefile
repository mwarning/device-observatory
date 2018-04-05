#
# This file is licensed under the CC0-1.0 license.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=device-observatory
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_LICENSE:=GPL-3.0+

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_URL:=https://github.com/mwarning/device-observatory
PKG_SOURCE_VERSION:=master

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
