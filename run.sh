#!/bin/bash

RESET=$1
shift

if [[ ! -z $RESET ]] ; then
    echo "+ reset usb port"
    sudo python3 reset_usb.py search "Bluetooth"

    echo "+ restart bluetooth service"
    sudo service bluetooth restart

    echo "+ dmesg logs"
    sudo dmesg -T | tail -50 | egrep -i "usb|blue" 
fi

echo "+ running..."
/usr/bin/python3 -u ./es3.py 2>&1 | tee -a ./bt3.log
