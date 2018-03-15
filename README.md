# Device Observatory

The Device Observatory shows a website of what your device is doing on a network. Does your phone access mysterious sites on the Internet? Does it expose private Information? Find out! 

This is an package for the WiFi router operating system OpenWrt. The package will create an WiFi Access Point for your device to connect to. You can track your device via a website on the WiFi router.

State: pre-alpha

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
The *.ipk package and the complete image that includes the package can be found in folder bin/.
