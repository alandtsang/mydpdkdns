#!/bin/bash

rm -rf /dev/hugepages/*

#basepath=$(cd `dirname $0`; pwd)
basepath=$(dirname $(pwd))
echo $basepath

buildpath=$basepath/build
logpath=$basepath/log

if [ ! -d $buildpath ]; then
    mkdir $buildpath
fi

if [ ! -d $logpath ]; then
    mkdir $logpath
fi

cd $buildpath
cmake ..
make
# 1111
./bin/dserver -c 0xf -n 1 -- -p1 --config '(0,0,1,2,3)' &

