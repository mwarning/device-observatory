

# Install On OpenWrt

This project is already part of the official OpenWrt package feed. On your device running OpenWrt, do:
```
opkg update
opkg install device-observatory
```

The configuration file can be found in `/etc/config/device-observatory`.

## Building and Packaging for OpenWrt

These steps are for building an [OpenWrt](https://openwrt.org) package (equivalent to Debian Linux .deb files) yourself.

For building OpenWrt on Debian Linux, you need to install these packages:
```
apt install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
```

Now download OpenWrt and the package files:
```
git clone https://github.com/openwrt/openwrt
cd openwrt

./scripts/feeds update -a
./scripts/feeds install -a

git clone https://github.com/mwarning/device-observatory.git
cp -rf device-observatory/openwrt/device-repository package/
rm -rf device-observatory/

make menuconfig
```

At this point select the appropiate "Target System" and "Target Profile"
depending on what target chipset/router you want to build for.
Also mark the new package under "Utils" => "device-observatory".

Now build the tools/toolchain and device-repository:

```
make
```

After a successful build, the images and all \*.ipk packages are now inside the bin/ folder.
You can install the \*.ipk file using "opkg install /tmp/\<ipkg-file\>" on the router.

For details please check the OpenWrt documentation.
