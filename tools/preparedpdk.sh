#!/bin/bash

bind_nic(){
    ifconfig $1 down
    ${RTE_SDK}/usertools/dpdk-devbind.py --bind=igb_uio $1
}

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

bind_nic ens38
