#!/bin/bash

PID=`ps axu|grep dserver | awk 'NR==1{print}' | awk -F" " '{print $2}'`
kill -2 $PID
