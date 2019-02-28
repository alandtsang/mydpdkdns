#!/bin/bash

basepath=$(cd `dirname $0`; pwd)
nicinfo="$basepath/ethinfo"
dev="vEth0"

if [ ! -f "$nicinfo" ]; then
   echo "Get Network Config Failed" && exit 1
else
    IPADDR=`grep 'IPADDR' $nicinfo | cut -d "=" -f2`
    NETMASK=`grep 'NETMASK' $nicinfo | cut -d "=" -f2`
    MAC=`grep 'MAC' $nicinfo | cut -d "=" -f2`
    GATEWAY=`grep 'GATEWAY' $nicinfo | cut -d "=" -f2`
fi

ifconfig $dev $IPADDR netmask $NETMASK
ifconfig $dev hw ether $MAC
#route add default gw $GATEWAY
