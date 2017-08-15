#!/bin/bash

dev=$1

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

record_eth $dev

