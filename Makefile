#
# This software is licensed under the CC0-1.0 license.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=device-observatory
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-3.0+

include $(INCLUDE_DIR)/package.mk

define Package/device-observatory
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=device-observatory
	MAINTAINER:=Moritz Warning <moritzwarning@web.de>
	DEPENDS:=+libpcap +uhttpd #+libmicrohttpd-no-ssl
endef

define Package/device-observatory/description
	The Device Observatory shows information about the devices connected to the WLAN to height security awareness.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/device-observatory/install
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/device-observatory.init $(1)/etc/init.d/device-observatory
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/device-observatory $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/share/macdb
	$(INSTALL_DATA) ./files/macdb.txt $(1)/usr/share/macdb/db.txt
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_BIN) files/device-observatory.config $(1)/etc/config/device-observatory
	$(INSTALL_DIR) $(1)/www
	$(INSTALL_DATA) ./files/index.html $(1)/www/index.html
	$(LN) /tmp/device-observatory.json $(1)/www/device-observatory.json
endef

$(eval $(call BuildPackage,device-observatory))
