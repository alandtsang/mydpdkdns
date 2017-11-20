#!/bin/bash

dev=$1

bind_nic() {
    ifconfig $dev down
    ${RTE_SDK}/usertools/dpdk-devbind.py --bind=igb_uio $dev
}

record_eth() {
    inetinfo=`ifconfig $dev | grep -w inet`
    macinfo=`ifconfig $dev | grep ether`

    ipaddr=`echo $inetinfo | awk '/inet/{print $2}'`
    netmask=`echo $inetinfo | awk '/inet/{print $4}'`
    mac=`echo $macinfo | awk '/ether/{print $2}'`
    gateway=`route -n | awk '/UG/{print $2}'`

    basepath=$(cd `dirname $0`; pwd)
    nicinfo="$basepath/nicinfo.log"
    rm -f $nicinfo

    if [ -z "$ipaddr" -o -z "$netmask" -o -z "$mac" -o -z "$gateway" ]; then
        echo "Get Eth Info Failed" && exit 1
    fi

    if [ ! -f $nicinfo ]; then
        echo -e "DEV=$dev\nIPADDR=$ipaddr\nNETMASK=$netmask\nMAC=$mac\nGATEWAY=$gateway" > $nicinfo
    fi
}

# Insert Module
modprobe uio

# insert igb_uio
lsmod | grep igb_uio >& /dev/null
if [ $? -ne 0 ]; then
    insmod ${RTE_SDK}/${RTE_TARGET}/kmod/igb_uio.ko
fi

# insert rte_kni
lsmod | grep rte_kni >& /dev/null
if [ $? -ne 0 ]; then
    insmod ${RTE_SDK}/${RTE_TARGET}/kmod/rte_kni.ko kthread_mode=multiple
fi

if [ ! -d /mnt/huge ]; then
    mkdir -p /mnt/huge
fi

mount -t hugetlbfs nodev /mnt/huge
echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

record_eth $dev
bind_nic $dev
