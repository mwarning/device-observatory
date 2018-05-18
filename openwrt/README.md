# Building and Packaging for OpenWrt

These steps are for building an [OpenWrt](https://openwrt.org) package (equivalent to Debian Linux .deb files).

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

## Build With Local Changes

You might want to use your own source location and not the remote respository.
To do this you need to checkout the repository yourself and commit your changes locally:

```
git clone https://github.com/mwarning/device-repository.git
cd device-repository
... apply your changes
git commit -am "my change"
```

Now create a symbolic link in the device-repository package folder using the abolute path:

```
ln -s /my/own/project/folder/device-repository/.git openwrt/package/device-repository/git-src
```

Also make sure to enable

```
"Advanced configuration options (for developers)" => "Enable package source tree override"
```

In the menu when you do `make menuconfig` and use the "git add" command
to add your local changes. Then build the entire image using `make` or just the package:

```
make package/device-repository/{clean,compile} V=s
```
