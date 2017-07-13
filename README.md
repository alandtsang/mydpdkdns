mydpdkdns
============

[![License](https://img.shields.io/badge/license-Apache%202-4EB1BA.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)


dns server with high performance, based on dpdk.


Documentation
=============
Please refer to [http://dpdk.org/doc](http://dpdk.org/doc).


Install dpdk
=============
```
tar xf dpdk-17.02.1.tar.xz -C /root
cd /root
mv dpdk-17.02.1 dpdk
cd dpdk

make config T=x86_64-native-linuxapp-gcc
make
make install T=x86_64-native-linuxapp-gcc
```


Set environment
=============
edit `.profile` or `.bashrc`, add the following:
```
export RTE_SDK=/root/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc
```


Usage
=============
```
git clone https://github.com/alandtsang/mydpdkdns.git
cd mydpdkdns/tools
```

### insert modules and mount hugetlbfs
```
./preparedpdk.sh
```

### start program
```
./start.sh
/root/mydpdkdns
-- RTE_SDK path：/root/dpdk
-- RTE_TARGET path：x86_64-native-linuxapp-gcc
-- RTE_SDK include path：/root/dpdk/include
-- RTE_SDK include path：/root/dpdk/lib
-- Configuring done
-- Generating done
-- Build files have been written to: /home/mydpdkdns/build
Scanning dependencies of target dserver
[100%] Built target dserver
EAL: Detected 4 lcore(s)
EAL: No free hugepages reported in hugepages-1048576kB
EAL: Probing VFIO support...
EAL: PCI device 0000:02:01.0 on NUMA socket -1
EAL:   probe driver: 8086:100f net_e1000_em
EAL: PCI device 0000:02:06.0 on NUMA socket -1
EAL:   probe driver: 8086:100f net_e1000_em
EAL: PCI device 0000:02:07.0 on NUMA socket -1
EAL:   probe driver: 8086:100f net_e1000_em
before Initialise each port
APP: Initialising port 0 ...
KNI: pci: 02:06:00 	 8086:100f
after Initialise each port

Checking link status
done
Port 0 Link Up - speed 1000 Mbps - full-duplex
APP: Lcore 1 is writing to port 0
APP: Lcore 2 is working to port 0
APP: Lcore 3 is sending to port 0
APP: Lcore 0 is reading from port 0
```

### configure IP and MAC addresses
```
./upeth.sh
APP: Configure network interface of 0 up
```

Now, you can test the dns server.


### stop program
```
./stop.sh
```

### unbind dpdk
```
./unbind.sh
```


Get Help
============
The fastest way to get response is to send email to my mail:
- <zengxianglong0@gmail.com>

License
============
Please refer to [LICENSE](https://github.com/alandtsang/mydpdkdns/blob/master/LICENSE) file.
