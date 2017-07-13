#!/bin/bash

get_first_row() {
    ${RTE_SDK}/usertools/dpdk-devbind.py --status | grep "0000:" | awk 'NR==1{print}'
}

get_nic_name() {
    ${RTE_SDK}/usertools/dpdk-devbind.py --status | grep $1 | awk -F"=" '{print $2}' | awk -F" " '{print $1}'
}

FIRST_ROW=`get_first_row`
NIC_STRING=`echo $FIRST_ROW | awk -F" " '{print $1}'`
${RTE_SDK}/usertools/dpdk-devbind.py --bind=e1000 $NIC_STRING | awk -F"=" '{print $2}'

NIC_NAME=`get_nic_name $NIC_STRING`
ifconfig $NIC_NAME up
