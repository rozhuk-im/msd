# msd

[![Build-macOS-latest Actions Status](https://github.com/rozhuk-im/msd/workflows/build-macos-latest/badge.svg)](https://github.com/rozhuk-im/msd/actions)
[![Build-Ubuntu-latest Actions Status](https://github.com/rozhuk-im/msd/workflows/build-ubuntu-latest/badge.svg)](https://github.com/rozhuk-im/msd/actions)


Rozhuk Ivan <rozhuk.im@gmail.com> 2011-2025

msd - Multi stream daemon.
Program for organizing IP TV streaming on the network via HTTP.


## Licence
BSD licence.
Website: http://www.netlab.linkpc.net/wiki/en:software:msd:index


## Donate
Support the author
* **GitHub Sponsors:** [!["GitHub Sponsors"](https://camo.githubusercontent.com/220b7d46014daa72a2ab6b0fcf4b8bf5c4be7289ad4b02f355d5aa8407eb952c/68747470733a2f2f696d672e736869656c64732e696f2f62616467652f2d53706f6e736f722d6661666266633f6c6f676f3d47697448756225323053706f6e736f7273)](https://github.com/sponsors/rozhuk-im) <br/>
* **Buy Me A Coffee:** [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/rojuc) <br/>
* **PayPal:** [![PayPal](https://srv-cdn.himpfen.io/badges/paypal/paypal-flat.svg)](https://paypal.me/rojuc) <br/>
* **Bitcoin (BTC):** `1AxYyMWek5vhoWWRTWKQpWUqKxyfLarCuz` <br/>


## Features
* support for IPv4 and IPv6
* Zero Copy on Send (ZCoS) - reduces the overhead of service connected clients, all the work of sending the data to the client assumes the OS kernel 
* support half closed http clients
* receiving udp-multicast, including rtp, simultaneously with different interfaces
* the use of various TCP Congestion Control algorithms depending on the port to which the client came and the URL the client's request
* instantaneous sending new client data from the ring buffer in order to minimize waiting times start playback
* sending any additional http headers in requests and responses
* detailed statistics for each TCP connection, to help you find problems at the network level



## Compilation and Installation
```
sudo apt-get install build-essential git cmake fakeroot
git clone --recursive https://github.com/rozhuk-im/msd.git
cd msd
mkdir build
cd build
cmake ..
make -j 8
```


## Run tests
```
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=1 ..
cmake --build . --config Release -j 16
ctest -C Release --output-on-failure -j 16
```


## Usage
```
msd [-d] [-v] [-c file]
       [-p PID file] [-u uid|usr -g gid|grp]
 -h           usage (this screen)
 -d           become daemon
 -c file      config file
 -p PID file  file name to store PID
 -u uid|user  change uid
 -g gid|group change gid
 -v           verboce
```


## Setup

### msd
Copy %%ETCDIR%%/msd.conf.sample to %%ETCDIR%%/msd.conf
then replace lan0 with your network interface name.
Add more sections if needed.
Remove IPv4/IPv6 lines if not needed.

Add to /etc/rc.conf:
```
msd_enable="YES"
```

Run:
```
service msd restart
```

