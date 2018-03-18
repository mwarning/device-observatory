# Device Observatory

The Device Observatory shows a website of what your device is doing on a network. Does your phone access mysterious sites on the Internet? Does it expose private Information? Find out! 

This is an package for the WiFi router operating system OpenWrt. The package will create an WiFi Access Point for your device to connect to. You can track your device via a website on the WiFi router.

Pull Requests are welcome!

![logo](observatory.png)

State: Beta

Usage:
 1. install package
 2. enable wifi on the router
 3. "/etc/init.d/device-observatory enable"
 4. reboot and access 192.168.1.1 via WLAN

Features:
 * Shows MAC address, DHCP device host name, device manufacturer
 * Show accessed IP addresses and ports
 * Show various times (first/last accessed)

TODO:
 * nicer index.html style
 * count download traffic
 * show information about special ports
 * parse DNS requests to show hostname of IP address

## How to build

For building OpenWrt on Debian Linux, you need to install these packages:
```
apt install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
```

Here is how you build a OpenWrt package of the device opservatory and image:

```
git clone https://github.com/openwrt/openwrt
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a

git clone https://github.com/mwarning/device-observatory.git
cp -rf device-observatory/openwrt/device-observatory package/
rm -rf device-observatory/

make menuconfig
make
```

In the `make menuconfig` menu, select your device and the device-observatory package ("Utlilities" => "Device Observatory"). Exit and save. Then call `make`.
The \*.ipk package and the complete image that includes the package can be found in folder bin/.

## Update macdb.txt

Console command to load the official database and create a stripped down database that is more usable:

```
curl http://standards-oui.ieee.org/oui/oui.txt | awk -F'[[:space:]]+' '/^[A-F0-9]{6}/{ printf("%s", $1); for(i=4; i < NF; i++) printf(" %s", $i); printf("\n"); }' > macdb.txt
```
