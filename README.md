# Device Observatory

The Device Observatory shows the activities of WiFi devices on a network on a local website. It is meant to raise the awareness for private data leaking from devices such as smartphones.

This also includes a package for [OpenWrt](http://openwrt.org). The package will create an WiFi Access Point for your phone to connect to. You can track your devices activity on a website on the router. External devices will only see their own data for privacy.

Pull Requests are welcome!

![logo](www/logo.png)

Features:
 * Devices accessing the info page only see own data (except for the local host)
 * Shows MAC address, DHCP device host name, device manufacturer
 * Shows accessed domains, IP addresses and ports
 * Shows first/last time accessed
 * Show SSIDs from active scanning
 * Show traffic by destination

## Usage

  * `--dev` *device*  
    Device to parse war ethernet packets from.  
    This option may occur multiple times.  
    E.g. `wlan0`  

  * `--mdev` *device*  
    Device to parse raw wifi packets from.  
    This option may occur multiple times.  
    E.g. `mon0`  

  * `--mac-db` *file*  
    MAC to manufacturer database.  
    E.g. `macdb.txt`  
    Default: disabled

  * `--port-db` *file*  
    File to map port numbers to human readable names.  
    E.g. `/etc/services`  
    Default: disabled

  * `--json-output` *file*  
    Ouput all data as JSON file.  
    Default: disabled

  * `--device-timeout` *seconds*  
    Timeout device data after last ethernet activity.  
    Default: never

  * `--track-localhost` *[1|0]*  
    Track localhost as an device.  
    Default: on

  * `--webserver-port` *port*  
    Port of the build-in webserver. Set to 0 to disable webserver.  
    Default: 8080

  * `--webserver-path` *path*  
    Root folder for the build-in webserver. Usually not needed as all files are included into the binary.  
    Default: internal

  * `--help`  
    Show these options and help text.

## Build for Linux base Operating Systems

Install dependencies for compiling:
```
apt get libpcap-dev libmicrohttpd-dev
```

Get source code:
```
git clone https://github.com/mwarning/device-observatory.git
cd device-observatory
```

Compile:
```
make
```

Start program:
```
./device-repository --dev eth0
```

Here, eth0 is an example interface.
Normally you would create an Access Point WiFi interface (e.g. --dev wlan0) and an optional monitoring interface (e.g. --mdev mon0).

To see the data captured by the program, go to [localhost:8080](http://localhost:8080) or [192.168.1.1:8080](http://192.168.1.1:8080) if the program runs your router.

## Create WiFi Access Point

```
TODO
```

## Create monitor mode interface

A monitor mode interface can be used to get all raw packets from the air on a specific channel. This is useful to detect active SSID scanning by phones/devices.
Do `iw dev` to get a list of physical wireless devices.

```
iw phy phy0 interface add mon0 type monitor
ip link set dev mon0 up
```

On OpenWrt, this can also be done via the create_monitor setting in /etc/config/device-observatory.
The mon0 device will be appended as `--mdev mon0`.

## Build for OpenWrt

For building OpenWrt on Debian Linux, you need to install these packages:
```
apt install git subversion g++ libncurses5-dev gawk zlib1g-dev build-essential
```

Here is how you build a OpenWrt package of the device observatory and image:

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

To install the package manually on an existing OpenWrt system, copy the package onto the target device and install it:

```
opkg install /tmp/*.ipk
```

## Update macdb.txt

Console command to load the official database and create a stripped down database that is more usable:

```
curl http://standards-oui.ieee.org/oui/oui.txt | awk -F'[[:space:]]+' '/^[A-F0-9]{6}/{ printf("%s", $1); for(i=4; i < NF; i++) printf(" %s", $i); printf("\n"); }' > macdb.txt
```
