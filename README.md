# Device Observatory

The Device Observatory shows a website of what your device is doing on a network. Does your phone access mysterious sites on the Internet? Does it expose private Information? Find out! 

This is a package for the WiFi router operating system [OpenWrt](http://openwrt.org). The package will create an WiFi Access Point for your device to connect to. You can track your device via a website on the WiFi router.

Pull Requests are welcome!

![logo](observatory.png)

Usage:
 1. install package
 2. enable WLAN on the router
 3. `/etc/init.d/device-observatory enable`
 4. reboot and access 192.168.1.1 via WLAN

Features:
 * Shows MAC address, DHCP device host name, device manufacturer
 * Show accessed IP addresses and ports
 * Show various times (first/last accessed)

How does it work?
 * All pakets are captured using libpcap.
 * List SSIDs a devices does active wifi scanning for
   * e.g. devices reveal the name of networks at home
   * needs an optional monitoring wifi device
 * MAC addresses are looked up in the OUI database
   * This allows to find out the device manufactuers name
 * DHCP leases requests are analysed
   * This allows to show the hostname, if transmitted
   * DHCP is the way a IPv4 address is assigned to a device
 * All target IP addresses and used ports are recorded
   * The ports likely use is shown via a port database
   * e.g port 443 is commonly used for HTTPS
 * HTTP GET requests resources are logged and displayed
 * DNS and Multicast DNS packets are parsed
   * This helps to put a better name on an accessed IP address
 * All data is shown on a website

 TODO/Ideas:
 * fix HTTP request first line parsing
 * make the project usable for other operating systems
 * only show users own information as a privacy setting
 * nicer index.html style
 * display SSIDs devices [scan](https://security.stackexchange.com/questions/62124/phones-broadcast-the-ssids-of-all-networks-they-have-ever-connected-to-how-can) for

## How to build

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

To install the package manually on an existing OpenWrt system:

```
opkg install /tmp/*.ipk
```

## Update macdb.txt

Console command to load the official database and create a stripped down database that is more usable:

```
curl http://standards-oui.ieee.org/oui/oui.txt | awk -F'[[:space:]]+' '/^[A-F0-9]{6}/{ printf("%s", $1); for(i=4; i < NF; i++) printf(" %s", $i); printf("\n"); }' > macdb.txt
```
